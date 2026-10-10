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
#include <algorithm>
#include <cstring>
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
#include "brpc/details/proxy_upstream.h"
#include "brpc/details/tcp_tunnel.h"
#include "brpc/server.h"
#include "brpc/socket.h"
#include "brpc/socks5.h"
#include "butil/endpoint.h"
#include "butil/time.h"

namespace brpc {
namespace policy {

struct Socks5Session : details::TcpTunnel {
    // Parse order: method negotiation -> CONNECT request -> raw tunnel bytes.
    // REJECTED discards input while the queued failure reply closes the socket.
    enum ParseStage { GREETING, REQUEST, BYTES, REJECTED } parse_stage = GREETING;
    bool connected = false;
    bool method_replied = false;
    bool connect_replied = false;
    std::vector<unsigned char> offered_methods;
    std::shared_ptr<void> user_data;
    int64_t handshake_deadline_us;
    std::shared_ptr<Socks5Runtime> runtime;
    std::weak_ptr<Socks5Service> service;
    void OnClosed() override;
};

struct Socks5Context : Destroyable {
    explicit Socks5Context(std::shared_ptr<Socks5Session> s) : session(std::move(s)) {}
    void Destroy() override { delete this; }
    std::shared_ptr<Socks5Session> session;
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
};

// Hold Socket and service during the timeout watcher. Queue tasks retain their
// own references; Acceptor::Join waits for both without a Server-specific hook.
struct Socks5Task {
    explicit Socks5Task(std::shared_ptr<Socks5Session> s)
        : session(std::move(s)), service(session->service.lock()) {}
    SocketUniquePtr client;
    std::shared_ptr<Socks5Session> session;
    // Keep derived handlers alive until JobDone, without a permanent cycle.
    std::shared_ptr<Socks5Service> service;
};

void Socks5Session::OnClosed() {
    std::lock_guard<bthread::Mutex> runtime_lock(runtime->mutex);
    runtime->sessions.erase(client);
    runtime->condition.notify_all();
}

static void Close(const std::shared_ptr<Socks5Session>& s) { s->Close(); }

static void WatchFailure(SocketId id, const std::shared_ptr<Socks5Session>& s) {
    Socks5Session::WatchFailure(id, s);
}

static int Written(bthread_id_t id, void* arg, int error) {
    *static_cast<int*>(arg) = error;
    return bthread_id_unlock_and_destroy(id);
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
    return s->WriteClient(&data);
}

// The client destination is logical input to the adapter. Connect may establish
// another endpoint or transport. Only a ready adapter returns success; this
// function does not send a protocol reply.
static unsigned char Connect(const std::shared_ptr<Socks5Session>& s,
                             const Socks5Request& request,
                             butil::EndPoint* bound) {
    auto peer = Socks5Session::CreateUpstream(s, s->runtime->options.upstream_factory);
    if (!peer) return 1;
    ProxyConnectRequest connect;
    connect.target.host = request.host;
    connect.target.port = request.port;
    connect.route = connect.target;
    connect.timeout_ms = s->runtime->options.connect_timeout_ms;
    const auto result = details::AwaitProxyConnect(peer.get(), connect);
    // Preserve the existing REP mapping for default DNS/connect failures.
    if (result.error) {
        return result.resolve_failed ? 4 : (result.error == ECANCELED ? 1 : 5);
    }
    *bound = result.bound;
    return 0;
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
        // Destruction of the id wakes the serial consumer. No request or
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

// Server registration requires a process callback. Parsing submits all work
// directly and returns no message, so this callback is not used by SOCKS5.
void ProcessSocks5Request(InputMessageBase* message) { message->Destroy(); }

static ParseResult Enqueue(Socket* socket, butil::IOBuf* source, size_t size,
                           const std::shared_ptr<Socks5Session>& session,
                           const std::shared_ptr<Socks5Request>& request,
                           unsigned char error_code = 0) {
    auto service = session->service.lock();
    const bool payload = request->type == Socks5Request::DATA;
    const auto status = session->Submit(socket, source, size,
        payload ? &request->data : nullptr,
        [session, service, request, error_code] {
            if (error_code) {
                Result(session, error_code);
                return false;
            }
            return Socks5Dispatcher::Process(session, service.get(), request.get());
        });
    return status.ok() ? MakeMessage(nullptr) : details::MakeTunnelEnqueueError(status);
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

// SOCKS5 wire format: https://www.rfc-editor.org/rfc/rfc1928.html#section-3
// GREETING: VER(1) | NMETHODS(1) | METHODS(NMETHODS)
// REQUEST:  VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR | DST.PORT(2)
// This implementation accepts method 0x00 (no authentication) and CMD 0x01
// (CONNECT). Incomplete handshake frames remain in source for the next read.
ParseResult ParseSocks5Message(butil::IOBuf* source, Socket* socket, bool, const void* arg) {
    const auto* server = static_cast<const Server*>(arg);
    if (!server || !server->options().socks5_service) return MakeParseError(PARSE_ERROR_TRY_OTHERS);
    if (source->empty()) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
    auto* ctx = static_cast<Socks5Context*>(socket->parsing_context());
    if (!ctx) {
        // Probe VER=0x05 only before claiming the connection for SOCKS5.
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
    auto request = std::make_shared<Socks5Request>();
    unsigned char error_code = 0;
    // Largest handshake: domain CONNECT, 4 + 1 + 255 + 2 = 262 bytes.
    unsigned char bytes[262];
    size_t available = std::min(source->size(), sizeof(bytes));
    source->copy_to(bytes, available);
    if (s->parse_stage == Socks5Session::GREETING) {
        // Read NMETHODS first, then wait for all method identifiers.
        if (available < 2) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
        size_t size = 2 + bytes[1];
        if (available < size) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
        request->type = Socks5Request::METHOD;
        request->methods.assign(bytes + 2, bytes + size);
        {
            std::lock_guard<bthread::Mutex> lock(s->mutex);
            s->offered_methods = request->methods;
        }
        const bool no_auth = std::find(request->methods.begin(), request->methods.end(), 0)
                             != request->methods.end();
        s->parse_stage = no_auth ? Socks5Session::REQUEST : Socks5Session::REJECTED;
        return Enqueue(socket, source, size, s, request);
    }
    if (s->parse_stage == Socks5Session::REQUEST) {
        if (available < 4) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
        request->type = Socks5Request::CONNECT;
        // Validate VER=05, RSV=00, CMD=01 and ATYP. Failure REP values:
        // 01 = general failure, 07 = unsupported command, 08 = unsupported address.
        if (bytes[0] != 5 || bytes[2] != 0) error_code = 1;
        else if (bytes[1] != 1) error_code = 7;
        else if (bytes[3] != 1 && bytes[3] != 3 && bytes[3] != 4) error_code = 8;
        size_t size = 4;
        if (!error_code) {
            request->address_type = bytes[3];
            // ATYP: 01 = IPv4 (4 bytes), 04 = IPv6 (16 bytes), 03 = domain.
            size_t length = bytes[3] == 1 ? 4 : 16;
            size_t offset = 4;
            if (bytes[3] == 3) {
                // The length byte precedes domain bytes; no trailing NUL on wire.
                if (available < 5) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
                length = bytes[4];
                offset = 5;
            }
            size = offset + length + 2;
            if (available < size) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
            if (bytes[3] == 3) {
                request->host.assign(reinterpret_cast<char*>(bytes + offset), length);
                if (!length || request->host.find(char(0)) != std::string::npos) error_code = 8;
            } else {
                char host[INET6_ADDRSTRLEN];
                inet_ntop(bytes[3] == 1 ? AF_INET : AF_INET6, bytes + offset, host, sizeof(host));
                request->host = host;
            }
            // DST.PORT is the final two bytes, in network byte order (big endian).
            request->port = (uint16_t(bytes[size - 2]) << 8) | bytes[size - 1];
        }
        // BYTES means CONNECT was parsed, not that the upstream is ready.
        // The serial queue keeps subsequent data behind the CONNECT task.
        s->parse_stage = error_code ? Socks5Session::REJECTED : Socks5Session::BYTES;
        return Enqueue(socket, source, size, s, request, error_code);
    }
    if (s->parse_stage == Socks5Session::REJECTED) {
        // A rejection reply is queued; do not fail the socket before it is sent.
        source->clear();
        return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
    }
    // After the handshake there are no SOCKS5 data headers; forward the entire
    // chunk, including payload coalesced with CONNECT in the same TCP read.
    request->type = Socks5Request::DATA;
    return Enqueue(socket, source, source->size(), s, request);
}
}  // namespace policy

Socks5Service::Socks5Service(const Socks5Options& options)
    : _runtime(std::make_shared<policy::Socks5Runtime>(options)) {}

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
    const bool ok = _session->WriteClient(&data);
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
    const bool ok = _session->WriteClient(data);
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
        if (!connection->_session->WriteUpstream(&request->data)) connection->Close();
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
    s->max_pending_bytes = _runtime->options.max_pending_bytes;
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
