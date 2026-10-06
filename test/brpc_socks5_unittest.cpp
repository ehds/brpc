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


#include <gtest/gtest.h>
#include <sys/socket.h>
#include <atomic>
#include <mutex>
#include "butil/fd_guard.h"
#include "bthread/bthread.h"
#include "bthread/countdown_event.h"
#include "brpc/closure_guard.h"
#include "brpc/server.h"
#include "brpc/socket.h"
#include "brpc/socks5.h"
#include "brpc/protocol.h"
#include "brpc/input_message_base.h"
#include "brpc/policy/socks5_protocol.h"
#include "brpc/policy/rdma_handshake_protocol.h"

namespace {
class Socks5Test : public testing::Test {
protected:
    void SetUp() override {
        brpc::Socks5Options settings;
        settings.max_pending_bytes = 64;
        settings.handshake_timeout_ms = 100;
        service = std::make_shared<brpc::Socks5Service>(settings);
        brpc::ServerOptions options;
        options.socks5_service = service;
        options.enabled_protocols = "socks5";
        options.has_builtin_services = false;
        ASSERT_EQ(0, server.Start("127.0.0.1:0", &options));
        brpc::SocketOptions socket_options;
        ASSERT_EQ(0, brpc::Socket::Create(socket_options, &id));
        ASSERT_EQ(0, brpc::Socket::Address(id, &socket));
    }
    void TearDown() override {
        brpc::Socket::SetFailed(id);
        socket.reset();
        server.Stop(0);
        server.Join();
        EXPECT_EQ(0u, service->session_count());
    }
    brpc::ParseResult Parse() {
        return brpc::policy::ParseSocks5Message(&input, socket.get(), false, &server);
    }
    void ConsumeMessage(brpc::ParseResult result) {
        ASSERT_TRUE(result.is_ok());
        brpc::DestroyingPtr<brpc::InputMessageBase> message(result.message());
    }
    brpc::Server server;
    std::shared_ptr<brpc::Socks5Service> service;
    brpc::SocketId id = brpc::INVALID_SOCKET_ID;
    brpc::SocketUniquePtr socket;
    butil::IOBuf input;
};

TEST_F(Socks5Test, RegisteredServerOnlyProtocol) {
    const auto* protocol = brpc::FindProtocol(brpc::PROTOCOL_SOCKS5);
    ASSERT_NE(nullptr, protocol);
    EXPECT_STREQ("socks5", protocol->name);
    EXPECT_TRUE(protocol->support_server());
    EXPECT_FALSE(protocol->support_client());
}

TEST_F(Socks5Test, RdmaRejectsMismatchingMagicPrefixes) {
    const std::string prefixes[] = {
        "X", "RX", "RDX", "RDMX", std::string("\x05\x01\x00", 3)
    };
    for (const auto& prefix : prefixes) {
        SCOPED_TRACE(prefix);
        butil::IOBuf source;
        source.append(prefix);
        EXPECT_EQ(brpc::PARSE_ERROR_TRY_OTHERS,
                  brpc::policy::ParseRdmaHandshake(
                      &source, socket.get(), false, &server).error());
        EXPECT_EQ(prefix, source.to_string());
        EXPECT_EQ(nullptr, socket->parsing_context());
    }
}

TEST_F(Socks5Test, RdmaWaitsForMatchingMagicPrefixes) {
    const std::string prefixes[] = {"", "R", "RD", "RDM", "RDMA", "RDM3"};
    for (const auto& prefix : prefixes) {
        SCOPED_TRACE(prefix);
        butil::IOBuf source;
        source.append(prefix);
        EXPECT_EQ(brpc::PARSE_ERROR_NOT_ENOUGH_DATA,
                  brpc::policy::ParseRdmaHandshake(
                      &source, socket.get(), false, &server).error());
        EXPECT_EQ(prefix, source.to_string());
        EXPECT_EQ(nullptr, socket->parsing_context());
    }
}

TEST_F(Socks5Test, ProbeDoesNotConsumeOtherProtocols) {
    input.append("GET /", 5);
    EXPECT_EQ(brpc::PARSE_ERROR_TRY_OTHERS, Parse().error());
    EXPECT_EQ(5u, input.size());
    EXPECT_EQ(nullptr, socket->parsing_context());
}

TEST_F(Socks5Test, FragmentedAndCoalescedFrames) {
    input.append("\x05", 1);
    EXPECT_EQ(brpc::PARSE_ERROR_NOT_ENOUGH_DATA, Parse().error());
    EXPECT_EQ(1u, input.size());
    auto* context = socket->parsing_context();
    ASSERT_NE(nullptr, context);
    EXPECT_TRUE(socket->shall_fail_me_at_server_stop());
    input.append("\x01\x00\x05\x01\x00\x01\x7f", 7);
    ConsumeMessage(Parse());
    EXPECT_EQ(context, socket->parsing_context());
    EXPECT_EQ(5u, input.size());
    EXPECT_EQ(brpc::PARSE_ERROR_NOT_ENOUGH_DATA, Parse().error());
    input.append("\x00\x00\x01\x00\x50hello", 10);
    ConsumeMessage(Parse());
    EXPECT_EQ(5u, input.size());
    ConsumeMessage(Parse());
    EXPECT_TRUE(input.empty());
}

TEST_F(Socks5Test, MaximumLengthDomain) {
    input.append("\x05\x01\x00", 3);
    ConsumeMessage(Parse());
    input.append("\x05\x01\x00\x03\xff", 5);
    input.append(std::string(255, 'a'));
    input.append("\x00\x50", 2);
    ConsumeMessage(Parse());
    EXPECT_TRUE(input.empty());
}

TEST_F(Socks5Test, PendingPayloadLimit) {
    input.append("\x05\x01\x00", 3);
    ConsumeMessage(Parse());
    input.append("\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50", 10);
    ConsumeMessage(Parse());
    input.append(std::string(64, 'x'));
    ConsumeMessage(Parse());
    input.append("y", 1);
    EXPECT_EQ(brpc::PARSE_ERROR_TOO_BIG_DATA, Parse().error());
    EXPECT_EQ(0u, service->session_count());
}

TEST_F(Socks5Test, HandshakeTimeoutAndRestart) {
    input.append("\x05", 1);
    EXPECT_EQ(brpc::PARSE_ERROR_NOT_ENOUGH_DATA, Parse().error());
    for (int i = 0; i < 100 && service->session_count(); ++i) bthread_usleep(10000);
    EXPECT_EQ(0u, service->session_count());
    ASSERT_EQ(0, server.Stop(0));
    ASSERT_EQ(0, server.Join());
    brpc::ServerOptions options;
    options.socks5_service = service;
    options.enabled_protocols = "socks5";
    options.has_builtin_services = false;
    ASSERT_EQ(0, server.Start("127.0.0.1:0", &options));
}

TEST(Socks5SocketTest, DeferredEOFForCustomMessenger) {
    brpc::Server server;
    ASSERT_EQ(0, server.Start("127.0.0.1:0", nullptr));
    brpc::SocketOptions options;
    options.defer_eof = true;
    brpc::SocketId id;
    ASSERT_EQ(0, brpc::Socket::Create(options, &id));
    brpc::SocketUniquePtr socket;
    ASSERT_EQ(0, brpc::Socket::Address(id, &socket));
    EXPECT_FALSE(socket->CreatedByConnect());
    socket->PostponeEOF();
    socket->SetEOF();
    brpc::SocketUniquePtr probe;
    EXPECT_EQ(0, brpc::Socket::Address(id, &probe));
    socket->CheckEOF();
    EXPECT_NE(0, brpc::Socket::Address(id, &probe));
    server.Stop(0);
    server.Join();
}

TEST(Socks5OptionsTest, InvalidSettings) {
    brpc::Socks5Options settings;
    settings.max_pending_bytes = 0;
    EXPECT_FALSE(settings.IsValid());
    brpc::ServerOptions options;
    options.socks5_service = std::make_shared<brpc::Socks5Service>(settings);
    brpc::Server server;
    ASSERT_EQ(0, server.Start("127.0.0.1:0", &options));
    brpc::SocketId id;
    ASSERT_EQ(0, brpc::Socket::Create(brpc::SocketOptions(), &id));
    EXPECT_EQ(nullptr, options.socks5_service->NewSession(id));
    brpc::Socket::SetFailed(id);
    server.Stop(0);
    server.Join();
}

TEST(Socks5OptionsTest, ProtocolSelectionDoesNotEnableService) {
    brpc::Server server;
    brpc::ServerOptions options;
    options.enabled_protocols = "socks5";
    ASSERT_EQ(0, server.Start("127.0.0.1:0", &options));
    EXPECT_EQ(nullptr, server.options().socks5_service);
    server.Stop(0);
    server.Join();
}

// Real accepted sockets exercise Acceptor::Stop/Join, unlike parser-only
// tests whose synthetic sockets are not tracked by the listener.
TEST(Socks5OptionsTest, SharedServiceStopsOnlyOwningServerSessions) {
    auto service = std::make_shared<brpc::Socks5Service>();
    brpc::ServerOptions options;
    options.socks5_service = service;
    options.enabled_protocols = "baidu_std socks5";
    brpc::Server first;
    brpc::Server second;
    ASSERT_EQ(0, first.Start("127.0.0.1:0", &options));
    ASSERT_EQ(0, second.Start("127.0.0.1:0", &options));
    butil::fd_guard clients[2];
    brpc::Server* servers[] = {&first, &second};
    for (int i = 0; i < 2; ++i) {
        clients[i].reset(butil::tcp_connect(servers[i]->listen_address(), nullptr, 1000));
        ASSERT_GE(clients[i], 0);
        timeval timeout = {1, 0};
        ASSERT_EQ(0, setsockopt(clients[i], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
        ASSERT_EQ(3, send(clients[i], "\x05\x01\x00", 3, 0));
        char method[2];
        ASSERT_EQ(2, recv(clients[i], method, 2, MSG_WAITALL));
        EXPECT_EQ(0, method[1]);
    }
    EXPECT_EQ(2u, service->session_count());
    first.Stop(0);
    first.Join();
    EXPECT_EQ(1u, service->session_count());
    char byte;
    EXPECT_EQ(0, recv(clients[0], &byte, 1, 0));
    second.Stop(0);
    second.Join();
    EXPECT_EQ(0u, service->session_count());
    // Reuse the same configuration without resetting a service runtime.
    ASSERT_EQ(0, first.Start("127.0.0.1:0", &options));
    first.Stop(0);
    first.Join();
}

TEST(Socks5OptionsTest, DisabledByDefault) {
    brpc::Server server;
    ASSERT_EQ(0, server.Start("127.0.0.1:0", nullptr));
    brpc::SocketOptions options;
    brpc::SocketId id;
    ASSERT_EQ(0, brpc::Socket::Create(options, &id));
    brpc::SocketUniquePtr socket;
    ASSERT_EQ(0, brpc::Socket::Address(id, &socket));
    butil::IOBuf input;
    input.append("\x05\x01\x00", 3);
    EXPECT_EQ(brpc::PARSE_ERROR_TRY_OTHERS,
              brpc::policy::ParseSocks5Message(&input, socket.get(), false, &server).error());
    EXPECT_EQ(nullptr, socket->parsing_context());
    brpc::Socket::SetFailed(id);
    server.Stop(0);
    server.Join();
}

class EchoService : public brpc::Socks5Service {
public:
    bool reject_method = false;
    bool reject_connect = false;

    void Process(brpc::Socks5Connection* connection, brpc::Socks5Request* request,
                 google::protobuf::Closure* done) override {
        Record(request->type);
        if (request->type == brpc::Socks5Request::METHOD && !reject_method) {
            brpc::Socks5Service::Process(connection, request, done);
            return;
        }
        brpc::ClosureGuard guard(done);
        if (request->type == brpc::Socks5Request::METHOD) {
            connection->ReplyMethod(255);
        } else if (request->type == brpc::Socks5Request::CONNECT) {
            connection->set_user_data(std::make_shared<std::string>(
                request->host + ":" + std::to_string(request->port) + ":"));
            connection->ReplyConnect(reject_connect ? 2 : 0);
        } else {
            butil::IOBuf reply;
            reply.append(*std::static_pointer_cast<std::string>(connection->user_data()));
            reply.append(request->data);
            connection->Write(&reply);
        }
    }
    std::vector<brpc::Socks5Request::Type> calls() {
        std::lock_guard<std::mutex> lock(mutex);
        return requests;
    }
protected:
    void Record(brpc::Socks5Request::Type type) {
        std::lock_guard<std::mutex> lock(mutex);
        requests.push_back(type);
    }
    std::mutex mutex;
    std::vector<brpc::Socks5Request::Type> requests;
};

class AsyncEchoService : public EchoService {
public:
    std::atomic<int> data_calls{0};
    std::atomic<bool> released{false};
    bthread::CountdownEvent gate;
    std::shared_ptr<brpc::Socks5Connection> retained;

    void Release() {
        if (!released.exchange(true)) gate.signal();
    }
    void Process(brpc::Socks5Connection* connection, brpc::Socks5Request* request,
                 google::protobuf::Closure* done) override {
        if (request->type != brpc::Socks5Request::DATA) {
            EchoService::Process(connection, request, done);
            return;
        }
        Record(request->type);
        retained = std::make_shared<brpc::Socks5Connection>(*connection);
        const bool first = data_calls.fetch_add(1) == 0;
        struct Work {
            AsyncEchoService* service;
            brpc::Socks5Connection* connection;
            brpc::Socks5Request* request;
            google::protobuf::Closure* done;
            bool first;
        };
        auto* work = new Work{this, connection, request, done, first};
        bthread_t tid;
        if (bthread_start_background(&tid, nullptr, [](void* arg) -> void* {
                std::unique_ptr<Work> work(static_cast<Work*>(arg));
                brpc::ClosureGuard guard(work->done);
                if (work->first) work->service->gate.wait();
                work->connection->Write(&work->request->data);
                return nullptr;
            }, work) != 0) {
            delete work;
            connection->Close();
            done->Run();
        }
    }
};

class CustomSocks5Test : public testing::Test {
protected:
    void TearDown() override {
        if (async) async->Release();
        client.reset(-1);
        server.Stop(0);
        server.Join();
        if (service) EXPECT_EQ(0u, service->session_count());
    }
    void Start(std::shared_ptr<brpc::Socks5Service> custom) {
        service = std::move(custom);
        brpc::ServerOptions options;
        options.socks5_service = service;
        options.enabled_protocols = "baidu_std socks5";
        ASSERT_EQ(0, server.Start("127.0.0.1:0", &options));
        client.reset(butil::tcp_connect(server.listen_address(), nullptr, 1000));
        ASSERT_GE(client, 0);
        timeval timeout = {3, 0};
        ASSERT_EQ(0, setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    }
    void Greeting() {
        ASSERT_EQ(3, send(client, "\x05\x01\x00", 3, 0));
        char reply[2];
        ASSERT_EQ(2, recv(client, reply, sizeof(reply), MSG_WAITALL));
        EXPECT_EQ(std::string("\x05\x00", 2), std::string(reply, 2));
    }
    std::string ConnectRequest() {
        return std::string("\x05\x01\x00\x03\x0c", 5) +
               "example.test" + std::string("\x04\xd2", 2);  // port 1234
    }
    void Connect(unsigned char code = 0, const std::string& payload = "") {
        const std::string request = ConnectRequest() + payload;
        ASSERT_EQ(static_cast<ssize_t>(request.size()),
                  send(client, request.data(), request.size(), 0));
        unsigned char reply[10];
        ASSERT_EQ(10, recv(client, reply, sizeof(reply), MSG_WAITALL));
        EXPECT_EQ(5, reply[0]);
        EXPECT_EQ(code, reply[1]);
    }
    void WaitForData() {
        for (int i = 0; i < 3000 && async->data_calls.load() == 0; ++i) {
            bthread_usleep(1000);
        }
        ASSERT_EQ(1, async->data_calls.load());
    }
    brpc::Server server;
    butil::fd_guard client;
    std::shared_ptr<brpc::Socks5Service> service;
    std::shared_ptr<AsyncEchoService> async;
};

TEST_F(CustomSocks5Test, CustomConnectDataAndPerConnectionState) {
    auto echo = std::make_shared<EchoService>();
    Start(echo);
    Greeting();
    // No DNS or upstream socket: custom CONNECT accepts a logical destination.
    Connect(0, "hello");
    const std::string expected = "example.test:1234:hello";
    std::string reply(expected.size(), '\0');
    ASSERT_EQ(static_cast<ssize_t>(reply.size()),
              recv(client, &reply[0], reply.size(), MSG_WAITALL));
    EXPECT_EQ(expected, reply);
    const std::vector<brpc::Socks5Request::Type> expected_calls = {
        brpc::Socks5Request::METHOD, brpc::Socks5Request::CONNECT, brpc::Socks5Request::DATA
    };
    EXPECT_EQ(expected_calls, echo->calls());
}

TEST_F(CustomSocks5Test, CustomMethodRejection) {
    auto echo = std::make_shared<EchoService>();
    echo->reject_method = true;
    Start(echo);
    ASSERT_EQ(3, send(client, "\x05\x01\x00", 3, 0));
    char reply[2];
    ASSERT_EQ(2, recv(client, reply, 2, MSG_WAITALL));
    EXPECT_EQ(std::string("\x05\xff", 2), std::string(reply, 2));
    EXPECT_EQ(0, recv(client, reply, 1, 0));
}

TEST_F(CustomSocks5Test, CustomConnectRejectionDiscardsQueuedData) {
    auto echo = std::make_shared<EchoService>();
    echo->reject_connect = true;
    Start(echo);
    Greeting();
    Connect(2, "discard");
    char byte;
    EXPECT_EQ(0, recv(client, &byte, 1, 0));
    EXPECT_EQ(2u, echo->calls().size());
}

TEST_F(CustomSocks5Test, AsyncCompletionSerializesData) {
    async = std::make_shared<AsyncEchoService>();
    Start(async);
    Greeting();
    Connect(0, "a");
    WaitForData();
    ASSERT_EQ(1, send(client, "b", 1, 0));
    bthread_usleep(50000);
    EXPECT_EQ(1, async->data_calls.load());
    async->Release();
    char reply[2];
    ASSERT_EQ(2, recv(client, reply, 2, MSG_WAITALL));
    EXPECT_EQ("ab", std::string(reply, 2));
    EXPECT_EQ(2, async->data_calls.load());
}

TEST_F(CustomSocks5Test, AsyncMessageSurvivesClientEOF) {
    async = std::make_shared<AsyncEchoService>();
    Start(async);
    Greeting();
    Connect(0, "tail");
    WaitForData();
    ASSERT_EQ(0, shutdown(client, SHUT_WR));
    bthread_usleep(50000);
    EXPECT_FALSE(async->retained->is_closed());
    async->Release();
    char reply[4];
    ASSERT_EQ(4, recv(client, reply, 4, MSG_WAITALL));
    EXPECT_EQ("tail", std::string(reply, 4));
    EXPECT_EQ(0, recv(client, reply, 1, 0));
}

TEST_F(CustomSocks5Test, ServerJoinWaitsForAsyncCompletionAfterStop) {
    async = std::make_shared<AsyncEchoService>();
    Start(async);
    Greeting();
    Connect(0, "pending");
    WaitForData();
    server.Stop(0);
    struct JoinState {
        brpc::Server* server;
        std::atomic<bool> finished{false};
    } state{&server};
    bthread_t tid;
    ASSERT_EQ(0, bthread_start_background(&tid, nullptr, [](void* arg) -> void* {
        auto* state = static_cast<JoinState*>(arg);
        state->server->Join();
        state->finished.store(true);
        return nullptr;
    }, &state));
    bthread_usleep(50000);
    EXPECT_TRUE(async->retained->is_closed());
    EXPECT_FALSE(state.finished.load());
    async->Release();
    bthread_join(tid, nullptr);
    EXPECT_TRUE(state.finished.load());
}

TEST_F(CustomSocks5Test, CustomRoutingDelegatesToDefaultProxy) {
    brpc::Server upstream;
    ASSERT_EQ(0, upstream.Start("127.0.0.1:0", nullptr));
    class RedirectService : public brpc::Socks5Service {
    public:
        int port = 0;
        void Process(brpc::Socks5Connection* connection, brpc::Socks5Request* request,
                     google::protobuf::Closure* done) override {
            if (request->type == brpc::Socks5Request::CONNECT) {
                request->host = "127.0.0.1";
                request->port = port;
            }
            brpc::Socks5Service::Process(connection, request, done);
        }
    };
    auto redirect = std::make_shared<RedirectService>();
    redirect->port = upstream.listen_address().port;
    Start(redirect);
    Greeting();
    Connect(0, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
    char reply[12];
    ASSERT_EQ(12, recv(client, reply, sizeof(reply), MSG_WAITALL));
    EXPECT_EQ("HTTP/1.1 200", std::string(reply, 12));
    client.reset(-1);
    server.Stop(0);
    server.Join();
    upstream.Stop(0);
    upstream.Join();
}
}  // namespace
