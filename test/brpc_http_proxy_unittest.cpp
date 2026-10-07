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


#include <sys/socket.h>
#include <arpa/inet.h>
#include "brpc/channel.h"
#include "brpc/protocol.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <utility>
#include <gtest/gtest.h>
#include "brpc/controller.h"
#include "brpc/authenticator.h"
#include "brpc/http_proxy.h"
#include "brpc/server.h"
#include "butil/fd_guard.h"
#include "butil/endpoint.h"

namespace {
class Done : public google::protobuf::Closure {
public:
    void Run() override { ++calls; }
    int calls = 0;
};

TEST(HttpProxyOptionsTest, InvalidOptionsCompleteForwardWithError) {
    brpc::HttpProxyOptions options;
    options.max_pending_bytes = 0;
    EXPECT_FALSE(options.IsValid());
    brpc::HttpProxyService service(options);
    brpc::Controller controller;
    controller.http_request().uri() = "http://127.0.0.1/";
    Done done;
    service.Forward(&controller, &done);
    EXPECT_EQ(1, done.calls);
    EXPECT_EQ(500, controller.http_response().status_code());
}

TEST(HttpProxyOptionsTest, OriginFormIsRejectedAndCompleted) {
    brpc::HttpProxyService service;
    brpc::Controller controller;
    controller.http_request().uri() = "/health";
    Done done;
    service.Forward(&controller, &done);
    EXPECT_EQ(1, done.calls);
    EXPECT_EQ(400, controller.http_response().status_code());
}

class HttpProxyTest : public testing::Test {
protected:
    void SetUp() override {
        ASSERT_EQ(0, upstream.Start("127.0.0.1:0", nullptr));
    }
    void TearDown() override {
        client.reset(-1);
        proxy.Stop(0);
        proxy.Join();
        upstream.Stop(0);
        upstream.Join();
    }
    void Start(std::shared_ptr<brpc::HttpProxyService> service,
               const char* protocol = "http_proxy", int internal_port = -1,
               const brpc::Authenticator* auth = nullptr) {
        brpc::ServerOptions options;
        options.http_master_service = brpc::NewHttpProxyMasterService(std::move(service));
        options.enabled_protocols = protocol;
        options.internal_port = internal_port;
        options.auth = auth;
        options.strict_enabled_protocols = true;
        ASSERT_EQ(0, proxy.Start("127.0.0.1:0", &options));
        client.reset(butil::tcp_connect(proxy.listen_address(), nullptr, 1000));
        ASSERT_GE(client, 0);
        timeval timeout = {3, 0};
        ASSERT_EQ(0, setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    }
    std::string Exchange(const std::string& request) {
        EXPECT_EQ(static_cast<ssize_t>(request.size()),
                  send(client, request.data(), request.size(), 0));
        std::string response;
        bool tunnel = request.find("CONNECT ") == 0;
        do {
            std::string header;
            while (header.size() < 65536 &&
                   (header.size() < 4 || header.compare(header.size() - 4, 4, "\r\n\r\n") != 0)) {
                char byte;
                if (recv(client, &byte, 1, 0) != 1) {
                    ADD_FAILURE() << "incomplete response headers";
                    return response + header;
                }
                header.push_back(byte);
            }
            response += header;
            if (tunnel && header.find("HTTP/1.1 200") == 0) {
                tunnel = false;
                continue;  // Read the tunneled upstream HTTP response as well.
            }
            std::string lower = header;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            const size_t pos = lower.find("\r\ncontent-length:");
            if (pos != std::string::npos) {
                const size_t length = std::stoul(lower.substr(pos + 17));
                std::string body(length, '\0');
                if (length) {
                    EXPECT_EQ(static_cast<ssize_t>(length),
                              recv(client, &body[0], length, MSG_WAITALL));
                    response += body;
                }
            }
            break;
        } while (true);
        return response;
    }
    std::string Target() {
        return "127.0.0.1:" + std::to_string(upstream.listen_address().port);
    }
    brpc::Server proxy;
    brpc::Server upstream;
    butil::fd_guard client;
};

TEST_F(HttpProxyTest, ForwardAbsoluteURL) {
    Start(std::make_shared<brpc::HttpProxyService>());
    const auto response = Exchange("GET http://" + Target() +
        "/health HTTP/1.1\r\nHost: ignored.example\r\nConnection: close\r\n\r\n");
    EXPECT_EQ(0u, response.find("HTTP/1.1 200"));
    EXPECT_NE(std::string::npos, response.find("OK"));
}

TEST_F(HttpProxyTest, ConnectReplyPrecedesCoalescedPayloadResponse) {
    Start(std::make_shared<brpc::HttpProxyService>());
    const auto response = Exchange("CONNECT " + Target() +
        " HTTP/1.1\r\nHost: " + Target() + "\r\n\r\n"
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    const std::string success = "HTTP/1.1 200 Connection Established\r\n\r\n";
    ASSERT_EQ(0u, response.find(success));
    EXPECT_EQ(success.size(), response.find("HTTP/1.1 200 OK", success.size()));
    EXPECT_EQ(std::string::npos, response.find("Connection Established", success.size()));
}

class TokenAuthenticator : public brpc::Authenticator {
public:
    int GenerateCredential(std::string* credential) const override {
        *credential = "valid-token";
        return 0;
    }
    int VerifyCredential(const std::string& credential, const butil::EndPoint&,
                         brpc::AuthContext*) const override {
        return credential == "valid-token" ? 0 : EACCES;
    }
};

class HttpProxyAuthTest : public HttpProxyTest {
protected:
    TokenAuthenticator auth;
};

TEST_F(HttpProxyAuthTest, MissingConnectCredentialIsRejected) {
    Start(std::make_shared<brpc::HttpProxyService>(), "http_proxy", -1, &auth);
    EXPECT_EQ(0u, Exchange("CONNECT " + Target() +
        " HTTP/1.1\r\nHost: localhost\r\n\r\n").find("HTTP/1.1 403"));
}

TEST_F(HttpProxyAuthTest, InvalidConnectCredentialIsRejected) {
    Start(std::make_shared<brpc::HttpProxyService>(), "http_proxy", -1, &auth);
    EXPECT_EQ(0u, Exchange("CONNECT " + Target() +
        " HTTP/1.1\r\nAuthorization: wrong-token\r\n\r\n").find("HTTP/1.1 403"));
}

TEST_F(HttpProxyAuthTest, AuthenticatedConnectForwardsCoalescedData) {
    Start(std::make_shared<brpc::HttpProxyService>(), "http_proxy", -1, &auth);
    const auto response = Exchange("CONNECT " + Target() +
        " HTTP/1.1\r\nAuthorization: valid-token\r\n\r\n"
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    EXPECT_EQ(0u, response.find("HTTP/1.1 200 Connection Established"));
    EXPECT_NE(std::string::npos, response.find("HTTP/1.1 200 OK"));
}

TEST_F(HttpProxyTest, RejectedConnectRepliesOnceAndDiscardsEarlyData) {
    class Reject : public brpc::HttpProxyService {
    public:
        bool RouteConnect(std::string*, int*) override { return false; }
    };
    Start(std::make_shared<Reject>());
    const auto response = Exchange("CONNECT " + Target() +
        " HTTP/1.1\r\nHost: localhost\r\n\r\nearly tunnel bytes");
    EXPECT_EQ(0u, response.find("HTTP/1.1 403"));
    EXPECT_EQ(std::string::npos, response.find("HTTP/1.1", 1));
    char byte;
    EXPECT_EQ(0, recv(client, &byte, 1, 0));
}

TEST_F(HttpProxyTest, ConnectRouteCanRewriteTarget) {
    class Redirect : public brpc::HttpProxyService {
    public:
        int target_port = 0;
        bool RouteConnect(std::string* host, int* port) override {
            *host = "127.0.0.1";
            *port = target_port;
            return true;
        }
    };
    auto redirect = std::make_shared<Redirect>();
    redirect->target_port = upstream.listen_address().port;
    Start(redirect);
    const auto response = Exchange("CONNECT example.invalid:443 HTTP/1.1\r\n"
        "Host: example.invalid:443\r\n\r\n"
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    EXPECT_EQ(0u, response.find("HTTP/1.1 200 Connection Established"));
    EXPECT_NE(std::string::npos, response.find("HTTP/1.1 200 OK"));
}

class InvalidConnectTargetTest : public HttpProxyTest,
                                 public testing::WithParamInterface<const char*> {};

TEST_P(InvalidConnectTargetTest, RejectsBeforeRouting) {
    class Route : public brpc::HttpProxyService {
    public:
        bool RouteConnect(std::string*, int*) override {
            ++calls;
            return false;
        }
        std::atomic<int> calls{0};
    };
    auto route = std::make_shared<Route>();
    Start(route);
    const auto response = Exchange(std::string("CONNECT ") + GetParam() +
        " HTTP/1.1\r\nHost: ignored\r\n\r\n");
    EXPECT_EQ(0u, response.find("HTTP/1.1 400"));
    EXPECT_EQ(0, route->calls.load());
}

INSTANTIATE_TEST_SUITE_P(Targets, InvalidConnectTargetTest, testing::Values(
    "example.invalid", "example.invalid:0", "example.invalid:65536",
    "user@example.invalid:443", "example.invalid:443/path",
    "example.invalid:443?query", "http://example.invalid:443"));

using RoutedAddress = std::pair<std::string, int>;
class InvalidConnectRouteTest : public HttpProxyTest,
                                public testing::WithParamInterface<RoutedAddress> {};

TEST_P(InvalidConnectRouteTest, RejectsRewrittenAddressBeforeCreatingUpstream) {
    class Route : public brpc::HttpProxyService {
    public:
        explicit Route(const brpc::HttpProxyOptions& options)
            : HttpProxyService(options) {}
        bool RouteConnect(std::string* host, int* port) override {
            *host = address.first;
            *port = address.second;
            return true;
        }
        RoutedAddress address;
    };
    brpc::HttpProxyOptions options;
    options.upstream_factory = [](const brpc::ProxyTunnel&) {
        ADD_FAILURE() << "Invalid route must not create an upstream adapter";
        return std::unique_ptr<brpc::ProxyUpstream>();
    };
    auto route = std::make_shared<Route>(options);
    route->address = GetParam();
    Start(route);
    EXPECT_EQ(0u, Exchange("CONNECT example.invalid:443 HTTP/1.1\r\n"
        "Host: ignored\r\n\r\n").find("HTTP/1.1 400"));
}

INSTANTIATE_TEST_SUITE_P(Routes, InvalidConnectRouteTest,
    testing::Values(RoutedAddress{"example.invalid", -1},
                    RoutedAddress{"example.invalid", 0},
                    RoutedAddress{"example.invalid", 65536},
                    RoutedAddress{"", 443}));

TEST_F(HttpProxyTest, ForwardHookCanReturnCustomResponse) {
    class Custom : public brpc::HttpProxyService {
    public:
        void Forward(brpc::Controller* controller, google::protobuf::Closure* done) override {
            controller->http_response().set_status_code(201);
            controller->response_attachment().append("custom-http-response");
            done->Run();
        }
    };
    Start(std::make_shared<Custom>());
    const auto response = Exchange("GET http://example.invalid/ HTTP/1.1\r\n"
                                  "Host: example.invalid\r\nConnection: close\r\n\r\n");
    EXPECT_EQ(0u, response.find("HTTP/1.1 201"));
    EXPECT_NE(std::string::npos, response.find("custom-http-response"));
}
TEST_F(HttpProxyTest, OrdinaryHttpUsesTheSameMasterAdapter) {
    class Custom : public brpc::HttpProxyService {
    public:
        void Forward(brpc::Controller* c, google::protobuf::Closure* done) override {
            c->response_attachment().append("master-adapter");
            done->Run();
        }
    };
    // The existing HTTP handler, with no http_proxy handler registered, calls
    // the same adapter through its original http_master_service dispatch.
    Start(std::make_shared<Custom>(), "http");
    const auto response = Exchange("GET http://example.invalid/ HTTP/1.1\r\n"
                                  "Host: example.invalid\r\n\r\n");
    EXPECT_EQ(0u, response.find("HTTP/1.1 200"));
    EXPECT_NE(std::string::npos, response.find("master-adapter"));
}

TEST_F(HttpProxyTest, ConnectDoesNotInvokeTheHttpForwardHook) {
    class Custom : public brpc::HttpProxyService {
    public:
        bool RouteConnect(std::string*, int*) override { return false; }
        void Forward(brpc::Controller* c, google::protobuf::Closure* done) override {
            ADD_FAILURE() << "CONNECT must use the tunnel handshake";
            c->http_response().set_status_code(500);
            done->Run();
        }
    };
    Start(std::make_shared<Custom>());
    EXPECT_EQ(0u, Exchange("CONNECT " + Target() +
        " HTTP/1.1\r\nHost: localhost\r\n\r\n").find("HTTP/1.1 403"));
}

TEST_F(HttpProxyTest, InternalPortKeepsBuiltinHttpRouting) {
    butil::fd_guard probe(::socket(AF_INET, SOCK_STREAM, 0));
    ASSERT_GE(probe, 0);
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(0, bind(probe, reinterpret_cast<sockaddr*>(&address), sizeof(address)));
    socklen_t size = sizeof(address);
    ASSERT_EQ(0, getsockname(probe, reinterpret_cast<sockaddr*>(&address), &size));
    const int port = ntohs(address.sin_port);
    probe.reset(-1);
    Start(std::make_shared<brpc::HttpProxyService>(), "http_proxy", port);
    // An origin-form request on the public proxy port is not a builtin request.
    EXPECT_EQ(0u, Exchange("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .find("HTTP/1.1 400"));
    brpc::Channel channel;
    brpc::ChannelOptions options;
    options.protocol = brpc::PROTOCOL_HTTP;
    options.timeout_ms = 1000;
    options.max_retry = 0;
    ASSERT_EQ(0, channel.Init(("127.0.0.1:" + std::to_string(port)).c_str(), &options));
    brpc::Controller c;
    c.http_request().uri() = "/health";
    channel.CallMethod(nullptr, &c, nullptr, nullptr, nullptr);
    ASSERT_FALSE(c.Failed()) << c.ErrorText();
    EXPECT_EQ("OK", c.response_attachment().to_string());
}

TEST(HttpProxyProtocolTest, StrictWhitelistRemovesImplicitHttp) {
    brpc::Server server;
    brpc::ServerOptions options;
    options.enabled_protocols = "baidu_std";
    options.strict_enabled_protocols = true;
    ASSERT_EQ(0, server.Start("127.0.0.1:0", &options));
    brpc::Channel channel;
    brpc::ChannelOptions client_options;
    client_options.protocol = brpc::PROTOCOL_HTTP;
    client_options.timeout_ms = 1000;
    client_options.max_retry = 0;
    ASSERT_EQ(0, channel.Init(server.listen_address(), &client_options));
    brpc::Controller c;
    c.http_request().uri() = "/health";
    channel.CallMethod(nullptr, &c, nullptr, nullptr, nullptr);
    EXPECT_TRUE(c.Failed());
    EXPECT_TRUE(c.response_attachment().empty());
    server.Stop(0);
    server.Join();
}

}  // namespace
