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

#include <atomic>
#include <cerrno>
#include <mutex>
#include <sys/socket.h>
#include <gtest/gtest.h>
#include "bthread/bthread.h"
#include "bthread/mutex.h"
#include "brpc/http_proxy.h"
#include "brpc/server.h"
#include "brpc/socks5.h"
#include "butil/fd_guard.h"

namespace {
struct State {
    std::atomic<int> connects{0};
    std::atomic<int> client_chunks{0};
    std::atomic<int> sends{0};
    std::atomic<int> upstream_chunks{0};
    std::atomic<int> closes{0};
    brpc::ProxyConnectRequest request;
};

class EchoUpstream : public brpc::ProxyUpstream {
public:
    EchoUpstream(const brpc::ProxyTunnel& context, std::shared_ptr<State> s)
        : ProxyUpstream(context), state(std::move(s)) {}
    void Connect(const brpc::ProxyConnectRequest& request, ConnectDone done) override {
        state->request = request;
        ++state->connects;
        // No resolution/socket: the logical target is interpreted by this adapter.
        butil::IOBuf banner;
        banner.append("banner");
        EXPECT_TRUE(tunnel().Receive(&banner));
        done(brpc::ProxyConnectResult());
    }
    void OnClientData(butil::IOBuf* data, Done done) override {
        ++state->client_chunks;
        butil::IOBuf transformed;
        transformed.append("client:");
        transformed.append(*data);
        data->swap(transformed);
        ProxyUpstream::OnClientData(data, std::move(done));
    }
    void WriteUpstream(butil::IOBuf* data, Done done) override {
        ++state->sends;
        done(tunnel().Receive(data) ? 0 : ECANCELED);
    }
    void OnUpstreamData(butil::IOBuf* data, Done done) override {
        ++state->upstream_chunks;
        butil::IOBuf transformed;
        transformed.append("upstream:");
        transformed.append(*data);
        data->swap(transformed);
        // The custom processor writes through the public output interface,
        // without relying on the base data-processing implementation.
        tunnel().WriteClient(data, std::move(done));
    }
    void Close() override {
        if (!closed.exchange(true)) ++state->closes;
        ProxyUpstream::Close();
    }
    std::shared_ptr<State> state;
    std::atomic<bool> closed{false};
};

class RedirectUpstream : public brpc::ProxyUpstream {
public:
    RedirectUpstream(const brpc::ProxyTunnel& context, brpc::ProxyTarget endpoint,
                     std::shared_ptr<State> s)
        : ProxyUpstream(context), actual(std::move(endpoint)), state(std::move(s)) {}
    void Connect(const brpc::ProxyConnectRequest& request, ConnectDone done) override {
        state->request = request;
        ++state->connects;
        ConnectTcp(actual, request.timeout_ms, std::move(done));
    }
    brpc::ProxyTarget actual;
    std::shared_ptr<State> state;
};

class PendingDataUpstream : public EchoUpstream {
public:
    using EchoUpstream::EchoUpstream;
    void OnUpstreamData(butil::IOBuf*, Done done) override {
        bool cancelled;
        {
            std::lock_guard<bthread::Mutex> lock(mutex);
            cancelled = data_closed;
            if (!cancelled) pending = std::move(done);
            ++state->upstream_chunks;
        }
        if (cancelled) done(ECANCELED);
    }
    void Close() override {
        Done done;
        {
            std::lock_guard<bthread::Mutex> lock(mutex);
            data_closed = true;
            done.swap(pending);
        }
        EchoUpstream::Close();
        if (done) done(ECANCELED);  // Last use of this before worker completion.
    }
    bthread::Mutex mutex;
    bool data_closed = false;
    Done pending;
};

class PendingUpstream : public brpc::ProxyUpstream {
public:
    PendingUpstream(const brpc::ProxyTunnel& context, std::shared_ptr<State> s)
        : ProxyUpstream(context), state(std::move(s)) {}
    void Connect(const brpc::ProxyConnectRequest&, ConnectDone done) override {
        bool cancelled;
        {
            std::lock_guard<bthread::Mutex> lock(mutex);
            cancelled = closed;
            if (!cancelled) pending = std::move(done);
            ++state->connects;
        }
        if (cancelled) Fail(std::move(done));
    }
    void Close() override {
        ConnectDone done;
        {
            std::lock_guard<bthread::Mutex> lock(mutex);
            if (closed) return;
            closed = true;
            ++state->closes;
            done.swap(pending);
        }
        if (done) Fail(std::move(done));
        ProxyUpstream::Close();
    }
    static void Fail(ConnectDone done) {
        brpc::ProxyConnectResult result;
        result.error = ECANCELED;
        done(result);
    }
    std::shared_ptr<State> state;
    bthread::Mutex mutex;
    bool closed = false;
    ConnectDone pending;
};

// Use an upstream HTTP health exchange as a stand-in for gateway negotiation.
// Its response must be consumed by the native parser before CONNECT completes,
// rather than queued behind CONNECT or leaked to the client.
class NegotiatingUpstream : public RedirectUpstream {
public:
    using RedirectUpstream::RedirectUpstream;
    void Connect(const brpc::ProxyConnectRequest& request, ConnectDone done) override {
        state->request = request;
        ++state->connects;
        ConnectTcp(actual, request.timeout_ms, [this, done](brpc::ProxyConnectResult result) {
            if (result.error) { done(result); return; }
            bool cancelled;
            {
                std::lock_guard<bthread::Mutex> lock(mutex);
                cancelled = closed;
                if (!cancelled) { pending = done; connected = result; }
            }
            if (cancelled) { PendingUpstream::Fail(done); return; }
            butil::IOBuf hello;
            hello.append("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
            WriteUpstream(&hello, [this](int error) {
                if (error) tunnel().Close();
            });
        });
    }
    brpc::ParseResult ParseUpstreamData(butil::IOBuf* source, brpc::Socket* socket,
                                      bool eof) override {
        ConnectDone done;
        brpc::ProxyConnectResult result;
        bool control;
        {
            std::lock_guard<bthread::Mutex> lock(mutex);
            control = negotiating;
            if (control) {
                const auto bytes = source->to_string();
                const size_t end = bytes.find("\r\n\r\n");
                if (end == std::string::npos || bytes.size() < end + 6) {
                    return brpc::MakeParseError(brpc::PARSE_ERROR_NOT_ENOUGH_DATA);
                }
                EXPECT_EQ(0u, bytes.find("HTTP/1.1 200"));
                EXPECT_EQ("OK", bytes.substr(end + 4, 2));
                source->pop_front(end + 6);
                negotiating = false;
                done.swap(pending);
                result = connected;
            }
        }
        if (!control) return ProxyUpstream::ParseUpstreamData(source, socket, eof);
        if (done) done(result);
        return brpc::MakeMessage(nullptr);
    }
    void Close() override {
        ConnectDone done;
        {
            std::lock_guard<bthread::Mutex> lock(mutex);
            if (closed) return;
            closed = true;
            done.swap(pending);
        }
        if (done) PendingUpstream::Fail(done);
        ProxyUpstream::Close();
    }
    bthread::Mutex mutex;
    bool negotiating = true;
    bool closed = false;
    ConnectDone pending;
    brpc::ProxyConnectResult connected;
};

class ProxyUpstreamTest : public testing::TestWithParam<bool> {
protected:
    void TearDown() override {
        client.reset(-1);
        server.Stop(0);
        server.Join();
    }
    void Start(brpc::ProxyUpstreamFactory factory) {
        brpc::ServerOptions options;
        options.has_builtin_services = false;
        options.strict_enabled_protocols = true;
        if (GetParam()) {
            brpc::Socks5Options settings;
            settings.upstream_factory = std::move(factory);
            options.socks5_service = std::make_shared<brpc::Socks5Service>(settings);
            options.enabled_protocols = "socks5";
        } else {
            brpc::HttpProxyOptions settings;
            settings.upstream_factory = std::move(factory);
            options.http_master_service = brpc::NewHttpProxyMasterService(
                std::make_shared<brpc::HttpProxyService>(settings));
            options.enabled_protocols = "http_proxy";
        }
        ASSERT_EQ(0, server.Start("127.0.0.1:0", &options));
        client.reset(butil::tcp_connect(server.listen_address(), nullptr, 1000));
        ASSERT_GE(client, 0);
        timeval timeout = {3, 0};
        ASSERT_EQ(0, setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
        if (GetParam()) {
            ASSERT_EQ(3, send(client, "\x05\x01\x00", 3, 0));
            EXPECT_EQ(std::string("\x05\x00", 2), Read(2));
        }
    }
    void Request(const std::string& data = "") {
        const std::string request = GetParam() ?
            std::string("\x05\x01\x00\x03\x0c", 5) + "example.test" +
                std::string("\x04\xd2", 2) + data :
            "CONNECT example.test:1234 HTTP/1.1\r\nHost: example.test:1234\r\n\r\n" + data;
        ASSERT_EQ(static_cast<ssize_t>(request.size()),
                  send(client, request.data(), request.size(), 0));
    }
    void Reply() {
        if (GetParam()) {
            const auto reply = Read(10);
            ASSERT_EQ(10u, reply.size());
            EXPECT_EQ(5, reply[0]);
            EXPECT_EQ(0, reply[1]);
        } else {
            EXPECT_EQ("HTTP/1.1 200 Connection Established\r\n\r\n", Header());
        }
    }
    std::string Header() {
        std::string header;
        while (header.size() < 65536 &&
               (header.size() < 4 || header.compare(header.size()-4, 4, "\r\n\r\n"))) {
            auto byte = Read(1);
            if (byte.empty()) break;
            header += byte;
        }
        return header;
    }
    std::string Read(size_t n) {
        std::string result(n, '\0');
        const auto count = recv(client, &result[0], n, MSG_WAITALL);
        EXPECT_EQ(static_cast<ssize_t>(n), count);
        result.resize(count > 0 ? count : 0);
        return result;
    }
    brpc::Server server;
    butil::fd_guard client;
};

TEST_P(ProxyUpstreamTest, CustomTransportAndBothDataHooks) {
    auto state = std::make_shared<State>();
    Start([state](const brpc::ProxyTunnel& context) {
        return std::unique_ptr<brpc::ProxyUpstream>(new EchoUpstream(context, state));
    });
    Request("payload");
    Reply();
    // The banner emitted during Connect must follow the handshake reply.
    EXPECT_EQ("upstream:banner", Read(15));
    EXPECT_EQ("upstream:client:payload", Read(std::string("upstream:client:payload").size()));
    EXPECT_EQ("example.test", state->request.target.host);
    EXPECT_EQ(1234, state->request.target.port);
    EXPECT_EQ(1, state->connects.load());
    EXPECT_EQ(1, state->client_chunks.load());
    EXPECT_EQ(1, state->sends.load());
    EXPECT_EQ(2, state->upstream_chunks.load());
    server.Stop(0);
    server.Join();
    EXPECT_EQ(1, state->closes.load());
}

TEST_P(ProxyUpstreamTest, ActualEndpointDiffersFromLogicalTarget) {
    brpc::Server origin;
    ASSERT_EQ(0, origin.Start("127.0.0.1:0", nullptr));
    brpc::ProxyTarget actual;
    actual.host = "127.0.0.1";
    actual.port = origin.listen_address().port;
    auto state = std::make_shared<State>();
    Start([state, actual](const brpc::ProxyTunnel& context) {
        return std::unique_ptr<brpc::ProxyUpstream>(new RedirectUpstream(context, actual, state));
    });
    Request("GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    Reply();
    EXPECT_EQ(0u, Header().find("HTTP/1.1 200"));
    EXPECT_EQ("OK", Read(2));
    EXPECT_EQ("example.test", state->request.target.host);
    EXPECT_EQ(1234, state->request.target.port);
    origin.Stop(0);
    origin.Join();
}

TEST_P(ProxyUpstreamTest, StopCancelsPendingAsynchronousConnect) {
    auto state = std::make_shared<State>();
    Start([state](const brpc::ProxyTunnel& context) {
        return std::unique_ptr<brpc::ProxyUpstream>(new PendingUpstream(context, state));
    });
    Request();
    for (int i = 0; i < 1000 && !state->connects.load(); ++i) bthread_usleep(1000);
    EXPECT_EQ(1, state->connects.load());
    server.Stop(0);
    server.Join();
    EXPECT_EQ(1, state->closes.load());
    char byte;
    EXPECT_EQ(0, recv(client, &byte, 1, 0));
}

TEST_P(ProxyUpstreamTest, StopWaitsForCommonUpstreamDataCompletion) {
    auto state = std::make_shared<State>();
    Start([state](const brpc::ProxyTunnel& context) {
        return std::unique_ptr<brpc::ProxyUpstream>(new PendingDataUpstream(context, state));
    });
    Request();
    Reply();
    for (int i = 0; i < 1000 && !state->upstream_chunks.load(); ++i) bthread_usleep(1000);
    EXPECT_EQ(1, state->upstream_chunks.load());
    // The banner is pending in a common data task, not a protocol handler.
    // Stop must cancel it and Join must wait for its completion/worker release.
    server.Stop(0);
    server.Join();
    EXPECT_EQ(1, state->closes.load());
    char byte;
    EXPECT_EQ(0, recv(client, &byte, 1, 0));
}

TEST_P(ProxyUpstreamTest, NegotiationCompletesBeforeClientHandshakeReply) {
    brpc::Server origin;
    ASSERT_EQ(0, origin.Start("127.0.0.1:0", nullptr));
    brpc::ProxyTarget actual;
    actual.host = "127.0.0.1";
    actual.port = origin.listen_address().port;
    auto state = std::make_shared<State>();
    Start([state, actual](const brpc::ProxyTunnel& context) {
        return std::unique_ptr<brpc::ProxyUpstream>(
            new NegotiatingUpstream(context, actual, state));
    });
    Request("GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    Reply();
    EXPECT_EQ(0u, Header().find("HTTP/1.1 200"));
    EXPECT_EQ("OK", Read(2));
    origin.Stop(0);
    origin.Join();
}

INSTANTIATE_TEST_SUITE_P(Protocols, ProxyUpstreamTest, testing::Values(false, true));
}  // namespace
