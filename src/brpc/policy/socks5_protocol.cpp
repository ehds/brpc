// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.


#include "brpc/policy/socks5_protocol.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <algorithm>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <utility>
#include <vector>

#include "bthread/bthread.h"
#include "bthread/condition_variable.h"
#include "bthread/id.h"
#include "bthread/mutex.h"
#include "brpc/input_messenger.h"
#include "brpc/closure_guard.h"
#include "brpc/server.h"
#include "brpc/socket.h"
#include "brpc/socks5.h"
#include "butil/endpoint.h"
#include "butil/time.h"

namespace brpc {
namespace policy {

struct Socks5Action {
    enum Kind { METHOD, CONNECT, TO_UPSTREAM, TO_CLIENT, ERROR } kind;
    Socks5Request request;
    unsigned char code = 0;
    DestroyingPtr<InputMessageBase> message;
};

struct Socks5Session {
    enum ParseStage { GREETING, REQUEST, BYTES, REJECTED } parse_stage = GREETING;
    bthread::Mutex mutex;
    bool closed = false;
    bool connected = false;
    bool draining = false;
    bool method_replied = false;
    bool connect_replied = false;
    std::vector<unsigned char> offered_methods;
    std::shared_ptr<void> user_data;
    size_t pending_bytes = 0;
    SocketId client;
    SocketId upstream = INVALID_SOCKET_ID;
    int64_t handshake_deadline_us;
    std::deque<std::shared_ptr<Socks5Action>> actions;
    std::shared_ptr<Socks5Runtime> runtime;
    std::weak_ptr<Socks5Service> service;
};

struct Socks5Context : Destroyable {
    explicit Socks5Context(std::shared_ptr<Socks5Session> s) : session(std::move(s)) {}
    void Destroy() override { delete this; }
    std::shared_ptr<Socks5Session> session;
};

// Dispatch messages merely schedule a serial drain. Actions are appended in
// parse order, so concurrent process_request calls cannot reorder tunnel bytes.
struct Socks5Message : InputMessageBase {
    Socks5Message(std::shared_ptr<Socks5Session> s, std::shared_ptr<Socks5Action> a)
        : session(std::move(s)), action(std::move(a)) {}
    void DestroyImpl() override { delete this; }
    std::shared_ptr<Socks5Session> session;
    std::shared_ptr<Socks5Action> action;
};

struct Socks5Runtime {
    explicit Socks5Runtime(const Socks5Options& o)
        : options(o) {}
    Socks5Options options;
    bthread::Mutex mutex;
    bthread::ConditionVariable condition;
    bool shutting_down = false;
    size_t jobs = 0;
    std::map<SocketId, std::shared_ptr<Socks5Session>> sessions;
    InputMessenger upstream_input;
};

// Hold an accepted Socket reference before scheduling each task. Acceptor::Join
// already waits for these references to be released; no Server lifecycle hook
// or permanent Socket->Session->Socket reference cycle is needed.
struct Socks5Task {
    explicit Socks5Task(std::shared_ptr<Socks5Session> s)
        : session(std::move(s)), service(session->service.lock()) {}
    SocketUniquePtr client;
    std::shared_ptr<Socks5Session> session;
    // Keep derived handlers alive until JobDone, without a permanent cycle.
    std::shared_ptr<Socks5Service> service;
};

static void Close(const std::shared_ptr<Socks5Session>& s) {
    SocketId upstream;
    std::deque<std::shared_ptr<Socks5Action>> discarded;
    {
        std::lock_guard<bthread::Mutex> lock(s->mutex);
        if (s->closed) return;
        s->closed = true;
        discarded.swap(s->actions);
        upstream = s->upstream;
    }
    Socket::SetFailed(s->client);
    if (upstream != INVALID_SOCKET_ID) Socket::SetFailed(upstream);
    {
        std::lock_guard<bthread::Mutex> runtime_lock(s->runtime->mutex);
        s->runtime->sessions.erase(s->client);
        s->runtime->condition.notify_all();
    }
}

static int Failed(bthread_id_t id, void* arg, int) {
    std::unique_ptr<std::shared_ptr<Socks5Session>> s(
        static_cast<std::shared_ptr<Socks5Session>*>(arg));
    // Destroy the notification before failing the peer, to avoid recursive
    // callbacks attempting to lock this id again.
    bthread_id_unlock_and_destroy(id);
    Close(*s);
    return 0;
}

static void WatchFailure(SocketId socket_id, const std::shared_ptr<Socks5Session>& s) {
    auto* arg = new std::shared_ptr<Socks5Session>(s);
    bthread_id_t id;
    if (bthread_id_create(&id, arg, Failed) != 0) {
        delete arg;
        Close(s);
        return;
    }
    SocketUniquePtr socket;
    if (Socket::Address(socket_id, &socket) != 0) {
        bthread_id_error(id, ECONNRESET);
    } else {
        socket->NotifyOnFailed(id);
    }
}

static int Written(bthread_id_t id, void* arg, int error) {
    *static_cast<int*>(arg) = error;
    return bthread_id_unlock_and_destroy(id);
}

static bool Write(SocketId id, butil::IOBuf* data) {
    SocketUniquePtr socket;
    if (Socket::Address(id, &socket) != 0) return false;
    bthread_id_t wait;
    int error = 0;
    if (bthread_id_create(&wait, &error, Written) != 0) return false;
    Socket::WriteOptions options;
    options.id_wait = wait;
    options.notify_on_success = true;
    if (socket->Write(data, &options) != 0) bthread_id_error(wait, errno);
    bthread_id_join(wait);
    return error == 0;
}

static bool Result(const std::shared_ptr<Socks5Session>& s,
                   unsigned char code, const butil::EndPoint* bound = nullptr) {
    unsigned char reply[22] = {5, code, 0, 1};
    size_t size = 10;
    if (bound) {
        sockaddr_storage address = {};
        socklen_t length = 0;
        if (butil::endpoint2sockaddr(*bound, &address, &length) != 0) {
            return false;
        }
        if (address.ss_family == AF_INET) {
            auto* a = reinterpret_cast<sockaddr_in*>(&address);
            memcpy(reply + 4, &a->sin_addr, 4);
            memcpy(reply + 8, &a->sin_port, 2);
        } else if (address.ss_family == AF_INET6) {
            auto* a = reinterpret_cast<sockaddr_in6*>(&address);
            reply[3] = 4;
            memcpy(reply + 4, &a->sin6_addr, 16);
            memcpy(reply + 20, &a->sin6_port, 2);
            size = 22;
        }
    }
    butil::IOBuf data;
    data.append(reply, size);
    return Write(s->client, &data);
}

// Establish the upstream TCP connection requested by SOCKS5 CONNECT and attach
// it to the session for subsequent DATA forwarding. Return a SOCKS5 REP code:
// 0 means the upstream was created and its local address was stored in bound;
// a nonzero code indicates failure. The caller sends the CONNECT reply for
// either result. This function does not send a reply or complete an application
// request.
static unsigned char Connect(const std::shared_ptr<Socks5Session>& s,
                             const Socks5Request& request,
                             butil::EndPoint* bound) {
    addrinfo hints = {};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* addresses = nullptr;
    // Simplified mapping: any name-resolution failure is REP=4 (host unreachable).
    if (getaddrinfo(request.host.c_str(), std::to_string(request.port).c_str(),
                    &hints, &addresses) != 0) return 4;
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(addresses, freeaddrinfo);
    const timespec deadline = butil::milliseconds_from_now(
        s->runtime->options.connect_timeout_ms);
    for (auto* a = addresses; a; a = a->ai_next) {
        {
            std::lock_guard<bthread::Mutex> lock(s->mutex);
            if (s->closed) return 1;  // REP=1: general SOCKS server failure.
        }
        SocketOptions options;
        sockaddr_storage address = {};
        if (a->ai_addrlen > sizeof(address)) continue;
        memcpy(&address, a->ai_addr, a->ai_addrlen);
        if (butil::sockaddr2endpoint(&address, a->ai_addrlen, &options.remote_side) != 0) {
            continue;
        }
        // Create performs the upstream connect using brpc's Socket machinery.
        options.connect_on_create = true;
        options.defer_eof = true;
        options.connect_abstime = &deadline;
        options.initial_parsing_context = new Socks5Context(s);
        SocketId id;
        if (s->runtime->upstream_input.Create(options, &id) != 0) continue;
        bool closed;
        {
            std::lock_guard<bthread::Mutex> lock(s->mutex);
            closed = s->closed;
            if (!closed) s->upstream = id;
        }
        // The client may have disconnected while the upstream was connecting.
        if (closed) { Socket::SetFailed(id); return 1; }
        WatchFailure(id, s);
        SocketUniquePtr upstream;
        if (Socket::Address(id, &upstream) != 0) return 1;
        *bound = upstream->local_side();
        return 0;
    }
    // Simplified mapping: all exhausted connection attempts return REP=5
    // (connection refused), including timeouts and other connection failures.
    return 5;
}

static void JobDone(const std::shared_ptr<Socks5Runtime>& runtime) {
    std::lock_guard<bthread::Mutex> runtime_lock(runtime->mutex);
    --runtime->jobs;
    runtime->condition.notify_all();
}

class Socks5Done : public google::protobuf::Closure {
public:
    explicit Socks5Done(bthread_id_t id) : _id(id) {}
    void Run() override {
        const bthread_id_t id = _id;
        delete this;
        // Destruction of the id wakes the serial worker. No request or
        // connection pointer may be accessed after signaling completion.
        bthread_id_error(id, 0);
    }
private:
    bthread_id_t _id;
};

struct Socks5Dispatcher {
    static bool Process(const std::shared_ptr<Socks5Session>& s,
                        Socks5Service* service, Socks5Request* request) {
        if (!service) return false;
        bthread_id_t completion;
        int error = 0;
        if (bthread_id_create(&completion, &error, Written) != 0) return false;
        const Socks5Request::Type type = request->type;
        Socks5Connection connection(s);
        service->Process(&connection, request, new Socks5Done(completion));
        bthread_id_join(completion);
        std::lock_guard<bthread::Mutex> lock(s->mutex);
        if (s->closed) return false;
        // A handler must finish the handshake before declaring completion.
        return type == Socks5Request::METHOD ? s->method_replied : s->connected;
    }
};

static void* Drain(void* arg) {
    std::unique_ptr<Socks5Task> task(static_cast<Socks5Task*>(arg));
    auto s = task->session;
    while (true) {
        std::shared_ptr<Socks5Action> action;
        size_t size;
        {
            std::lock_guard<bthread::Mutex> lock(s->mutex);
            if (s->closed || s->actions.empty() || !s->actions.front()->message) {
                s->draining = false;
                break;
            }
            action = s->actions.front();
            s->actions.pop_front();
            size = action->request.data.size();
        }
        bool ok = true;
        if (action->kind == Socks5Action::ERROR) {
            Result(s, action->code);
            ok = false;
        } else if (action->kind == Socks5Action::TO_CLIENT) {
            ok = Write(s->client, &action->request.data);
        } else {
            ok = Socks5Dispatcher::Process(s, task->service.get(), &action->request);
        }
        {
            std::lock_guard<bthread::Mutex> lock(s->mutex);
            s->pending_bytes -= size;
        }
        if (!ok) Close(s);
    }
    JobDone(s->runtime);
    return nullptr;
}

void ProcessSocks5Request(InputMessageBase* base) {
    DestroyingPtr<Socks5Message> message(static_cast<Socks5Message*>(base));
    auto s = message->session;
    std::unique_ptr<Socks5Task> task(new Socks5Task(s));
    if (Socket::Address(s->client, &task->client) != 0) {
        Close(s);
        return;
    }
    auto action = message->action;
    {
        std::lock_guard<bthread::Mutex> lock(s->mutex);
        if (s->closed) return;
        // Keep the input message (and its EOF postponement) alive until its
        // bytes have actually been forwarded. Release the back-reference to
        // the action before transferring message ownership, avoiding a cycle.
        message->action.reset();
        action->message.reset(message.release());
        if (s->draining) return;
        s->draining = true;
        // Count the worker before Close() can release the queued message and
        // allow Server::Join() to finish waiting for accepted Socket refs.
        std::lock_guard<bthread::Mutex> runtime_lock(s->runtime->mutex);
        ++s->runtime->jobs;
    }
    bthread_t tid;
    if (bthread_start_background(&tid, nullptr, Drain, task.get()) != 0) {
        Close(s);
        JobDone(s->runtime);
    } else {
        task.release();
    }
}

static ParseResult Enqueue(butil::IOBuf* source, size_t size,
                           const std::shared_ptr<Socks5Session>& s, Socks5Action action) {
    auto queued = std::make_shared<Socks5Action>(std::move(action));
    bool overflow = false;
    {
        std::lock_guard<bthread::Mutex> lock(s->mutex);
        if (s->closed) return MakeParseError(PARSE_ERROR_ABSOLUTELY_WRONG);
        const size_t limit = s->runtime->options.max_pending_bytes;
        const bool payload = queued->kind == Socks5Action::TO_UPSTREAM ||
                             queued->kind == Socks5Action::TO_CLIENT;
        overflow = payload && size > limit - s->pending_bytes;
        if (!overflow) {
            if (payload) {
                source->cutn(&queued->request.data, size);
                s->pending_bytes += size;
            } else {
                source->pop_front(size);
            }
            s->actions.push_back(queued);
        }
    }
    if (overflow) { Close(s); return MakeParseError(PARSE_ERROR_TOO_BIG_DATA); }
    return MakeMessage(new Socks5Message(s, queued));
}

static ParseResult ParseUpstream(butil::IOBuf* source, Socket* socket, bool, const void*) {
    if (source->empty()) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
    auto* ctx = static_cast<Socks5Context*>(socket->parsing_context());
    Socks5Action action;
    action.kind = Socks5Action::TO_CLIENT;
    return Enqueue(source, source->size(), ctx->session, std::move(action));
}

static void* WatchHandshake(void* arg) {
    std::unique_ptr<Socks5Task> task(static_cast<Socks5Task*>(arg));
    auto s = task->session;
    while (true) {
        {
            std::lock_guard<bthread::Mutex> lock(s->mutex);
            if (s->closed || s->connected) break;
        }
        if (butil::gettimeofday_us() >= s->handshake_deadline_us) { Close(s); break; }
        bthread_usleep(10000);
    }
    JobDone(s->runtime);
    return nullptr;
}

ParseResult ParseSocks5Message(butil::IOBuf* source, Socket* socket, bool, const void* arg) {
    const auto* server = static_cast<const Server*>(arg);
    if (!server || !server->options().socks5_service) return MakeParseError(PARSE_ERROR_TRY_OTHERS);
    if (source->empty()) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
    auto* ctx = static_cast<Socks5Context*>(socket->parsing_context());
    if (!ctx) {
        unsigned char first;
        source->copy_to(&first, 1);
        if (first != 5) return MakeParseError(PARSE_ERROR_TRY_OTHERS);
        // Like RTMP, this is a streaming connection. Use Acceptor's existing
        // failure path on Server::Stop instead of a protocol-specific hook.
        socket->fail_me_at_server_stop();
        socket->EnableDeferredEOF();
        auto s = server->options().socks5_service->NewSession(socket->id());
        if (!s) return MakeParseError(PARSE_ERROR_NO_RESOURCE);
        ctx = new Socks5Context(s);
        socket->reset_parsing_context(ctx);
        WatchFailure(socket->id(), s);
    }
    auto s = ctx->session;
    // Only the Socket's serialized parser accesses parse_stage.
    Socks5Action action;
    unsigned char bytes[262];
    size_t available = std::min(source->size(), sizeof(bytes));
    source->copy_to(bytes, available);
    if (s->parse_stage == Socks5Session::GREETING) {
        if (available < 2) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
        size_t size = 2 + bytes[1];
        if (available < size) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
        action.kind = Socks5Action::METHOD;
        action.request.type = Socks5Request::METHOD;
        action.request.methods.assign(bytes + 2, bytes + size);
        {
            std::lock_guard<bthread::Mutex> lock(s->mutex);
            s->offered_methods = action.request.methods;
        }
        action.code = 255;
        for (size_t i = 2; i < size; ++i) if (bytes[i] == 0) action.code = 0;
        s->parse_stage = action.code == 0 ? Socks5Session::REQUEST : Socks5Session::REJECTED;
        return Enqueue(source, size, s, std::move(action));
    }
    if (s->parse_stage == Socks5Session::REQUEST) {
        if (available < 4) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
        action.kind = Socks5Action::ERROR;
        action.request.type = Socks5Request::CONNECT;
        if (bytes[0] != 5 || bytes[2] != 0) action.code = 1;
        else if (bytes[1] != 1) action.code = 7;
        else if (bytes[3] != 1 && bytes[3] != 3 && bytes[3] != 4) action.code = 8;
        size_t size = 4;
        if (!action.code) {
            action.request.address_type = bytes[3];
            size_t length = bytes[3] == 1 ? 4 : 16;
            size_t offset = 4;
            if (bytes[3] == 3) {
                if (available < 5) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
                length = bytes[4];
                offset = 5;
            }
            size = offset + length + 2;
            if (available < size) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
            if (bytes[3] == 3) {
                action.request.host.assign(reinterpret_cast<char*>(bytes + offset), length);
                if (!length || action.request.host.find(char(0)) != std::string::npos) action.code = 8;
            } else {
                char host[INET6_ADDRSTRLEN];
                inet_ntop(bytes[3] == 1 ? AF_INET : AF_INET6, bytes + offset, host, sizeof(host));
                action.request.host = host;
            }
            action.request.port = (uint16_t(bytes[size - 2]) << 8) | bytes[size - 1];
        }
        if (!action.code) action.kind = Socks5Action::CONNECT;
        s->parse_stage = action.code ? Socks5Session::REJECTED : Socks5Session::BYTES;
        return Enqueue(source, size, s, std::move(action));
    }
    if (s->parse_stage == Socks5Session::REJECTED) {
        // A rejection reply is queued; do not fail the socket before it is sent.
        source->clear();
        return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
    }
    action.kind = Socks5Action::TO_UPSTREAM;
    action.request.type = Socks5Request::DATA;
    return Enqueue(source, source->size(), s, std::move(action));
}
}  // namespace policy

Socks5Service::Socks5Service(const Socks5Options& options)
    : _runtime(std::make_shared<policy::Socks5Runtime>(options)) {
    InputMessageHandler handler = {policy::ParseUpstream, policy::ProcessSocks5Request,
                                  nullptr, nullptr, "socks5_upstream"};
    CHECK_EQ(0, _runtime->upstream_input.AddNonProtocolHandler(handler));
}

uint64_t Socks5Connection::socket_id() const { return _session->client; }

bool Socks5Connection::is_closed() const {
    std::lock_guard<bthread::Mutex> lock(_session->mutex);
    return _session->closed;
}

bool Socks5Connection::ReplyMethod(unsigned char method) const {
    {
        std::lock_guard<bthread::Mutex> lock(_session->mutex);
        if (_session->closed || _session->method_replied) return false;
        if (method != 255 && (method != 0 ||
            std::find(_session->offered_methods.begin(), _session->offered_methods.end(),
                      method) == _session->offered_methods.end())) return false;
        _session->method_replied = true;
    }
    const unsigned char reply[] = {5, method};
    butil::IOBuf data;
    data.append(reply, sizeof(reply));
    const bool ok = policy::Write(_session->client, &data);
    if (!ok || method == 255) Close();
    return ok;
}

bool Socks5Connection::ReplyConnect(unsigned char code, const butil::EndPoint& bound) const {
    {
        std::lock_guard<bthread::Mutex> lock(_session->mutex);
        if (_session->closed || !_session->method_replied ||
            _session->connect_replied || code > 8) return false;
        _session->connect_replied = true;
    }
    const bool ok = policy::Result(_session, code, &bound);
    if (!ok || code != 0) {
        Close();
    } else {
        std::lock_guard<bthread::Mutex> lock(_session->mutex);
        if (_session->closed) return false;
        _session->connected = true;
    }
    return ok;
}

bool Socks5Connection::Write(butil::IOBuf* data) const {
    {
        std::lock_guard<bthread::Mutex> lock(_session->mutex);
        if (_session->closed || !_session->connected) return false;
    }
    const bool ok = policy::Write(_session->client, data);
    if (!ok) Close();
    return ok;
}

void Socks5Connection::Close() const { policy::Close(_session); }

void Socks5Connection::set_user_data(std::shared_ptr<void> data) const {
    std::shared_ptr<void> previous;
    {
        std::lock_guard<bthread::Mutex> lock(_session->mutex);
        previous.swap(_session->user_data);
        _session->user_data = std::move(data);
    }
}

std::shared_ptr<void> Socks5Connection::user_data() const {
    std::lock_guard<bthread::Mutex> lock(_session->mutex);
    return _session->user_data;
}

void Socks5Service::Process(Socks5Connection* connection, Socks5Request* request,
                            google::protobuf::Closure* done) {
    ClosureGuard guard(done);
    if (connection->is_closed()) return;
    if (request->type == Socks5Request::METHOD) {
        const auto& methods = request->methods;
        if (!connection->ReplyMethod(std::find(methods.begin(), methods.end(), 0) !=
                                     methods.end() ? 0 : 255)) connection->Close();
    } else if (request->type == Socks5Request::CONNECT) {
        const auto s = connection->_session;
        butil::EndPoint bound;
        const unsigned char code = policy::Connect(s, *request, &bound);
        // Send exactly one reply for either success or failure. The bool result
        // reports reply-operation success; do not retry with another REP code.
        if (!connection->ReplyConnect(code, bound)) connection->Close();
    } else {
        SocketId upstream;
        {
            std::lock_guard<bthread::Mutex> lock(connection->_session->mutex);
            upstream = connection->_session->upstream;
        }
        if (!policy::Write(upstream, &request->data)) connection->Close();
    }
}
Socks5Service::~Socks5Service() {
    std::vector<std::shared_ptr<policy::Socks5Session>> sessions;
    {
        std::lock_guard<bthread::Mutex> runtime_lock(_runtime->mutex);
        _runtime->shutting_down = true;
        for (const auto& entry : _runtime->sessions) sessions.push_back(entry.second);
    }
    for (const auto& s : sessions) policy::Close(s);
    std::unique_lock<bthread::Mutex> lock(_runtime->mutex);
    _runtime->condition.wait(lock, [this] {
        return _runtime->jobs == 0 && _runtime->sessions.empty();
    });
}

std::shared_ptr<policy::Socks5Session> Socks5Service::NewSession(uint64_t socket_id) {
    if (!_runtime->options.IsValid()) return nullptr;
    auto s = std::make_shared<policy::Socks5Session>();
    s->client = socket_id;
    s->runtime = _runtime;
    s->service = shared_from_this();
    s->handshake_deadline_us = butil::gettimeofday_us() +
        _runtime->options.handshake_timeout_ms * int64_t(1000);
    std::unique_ptr<policy::Socks5Task> task(new policy::Socks5Task(s));
    if (Socket::Address(socket_id, &task->client) != 0) return nullptr;
    {
        std::lock_guard<bthread::Mutex> runtime_lock(_runtime->mutex);
        if (_runtime->shutting_down) return nullptr;
        _runtime->sessions.emplace(socket_id, s);
        ++_runtime->jobs;
    }
    bthread_t tid;
    if (bthread_start_background(&tid, nullptr, policy::WatchHandshake, task.get()) != 0) {
        policy::Close(s);
        policy::JobDone(_runtime);
        return nullptr;
    }
    task.release();
    return s;
}

size_t Socks5Service::session_count() const {
    std::lock_guard<bthread::Mutex> runtime_lock(_runtime->mutex);
    return _runtime->sessions.size();
}
}  // namespace brpc
