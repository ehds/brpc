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


#include <signal.h>
#include <gflags/gflags.h>
#include <iostream>
#include <memory>
#include "bthread/bthread.h"
#include "brpc/http_proxy.h"
#include "brpc/server.h"
#include "brpc/socks5.h"

DEFINE_string(admin_address, "127.0.0.1:8080",
              "Independent brpc builtin-tools HTTP server listen address");
DEFINE_string(upstream_host, "",
              "Optional actual TCP upstream host for both tunnel protocols");
DEFINE_int32(upstream_port, 0,
             "Actual TCP upstream port; use with upstream_host");
DEFINE_int32(connect_timeout_ms, 15000,
             "Upstream TCP connect timeout for SOCKS5 and HTTP proxy, "
             "in milliseconds");
DEFINE_int32(handshake_timeout_ms, 30000,
             "Entire SOCKS5 handshake timeout, including upstream connect, "
             "in milliseconds");
DEFINE_int32(request_timeout_ms, 30000,
             "Entire ordinary HTTP forwarding timeout, including connect, "
             "in milliseconds");
DEFINE_int32(idle_timeout_sec, 60,
             "Close idle client connections after these seconds; <=0 disables it");

namespace {
volatile sig_atomic_t stopping = 0;
void Stop(int) { stopping = 1; }

// The client target remains available for routing/negotiation, while this demo
// connects a separately configured endpoint. A gateway needing SOCKS/HTTP/RPC
// negotiation must finish that negotiation before calling Connect's done.
class FixedUpstream : public brpc::ProxyUpstream {
public:
    FixedUpstream(const brpc::ProxyTunnel& tunnel, brpc::ProxyTarget endpoint)
        : ProxyUpstream(tunnel), _endpoint(std::move(endpoint)) {}
    void Connect(const brpc::ProxyConnectRequest& request, ConnectDone done) override {
        LOG(INFO) << "Client target=" << request.target.host << ':' << request.target.port
                  << ", actual upstream=" << _endpoint.host << ':' << _endpoint.port;
        ConnectTcp(_endpoint, request.timeout_ms, std::move(done));
    }
private:
    brpc::ProxyTarget _endpoint;
};
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, Stop);
    signal(SIGTERM, Stop);
    GFLAGS_NAMESPACE::ParseCommandLineFlags(&argc, &argv, true);
    if (argc > 2) {
        std::cerr << "Usage: " << argv[0]
                  << " [listen_address] [--admin_address=host:port]"
                  << " [--timeout_flags...]"
                  << std::endl;
        return 1;
    }
    brpc::Socks5Options socks5_options;
    socks5_options.connect_timeout_ms = FLAGS_connect_timeout_ms;
    socks5_options.handshake_timeout_ms = FLAGS_handshake_timeout_ms;
    brpc::HttpProxyOptions http_options;
    http_options.connect_timeout_ms = FLAGS_connect_timeout_ms;
    http_options.request_timeout_ms = FLAGS_request_timeout_ms;
    if (!socks5_options.IsValid() || !http_options.IsValid()) {
        std::cerr << "Connect, handshake and request timeouts must be positive"
                  << std::endl;
        return 1;
    }
    if (!FLAGS_upstream_host.empty() || FLAGS_upstream_port != 0) {
        if (FLAGS_upstream_host.empty() || FLAGS_upstream_port <= 0 ||
            FLAGS_upstream_port > 65535) {
            std::cerr << "Specify upstream_host and a valid upstream_port together"
                      << std::endl;
            return 1;
        }
        brpc::ProxyTarget endpoint;
        endpoint.host = FLAGS_upstream_host;
        endpoint.port = FLAGS_upstream_port;
        brpc::ProxyUpstreamFactory factory = [endpoint](const brpc::ProxyTunnel& tunnel) {
            return std::unique_ptr<brpc::ProxyUpstream>(new FixedUpstream(tunnel, endpoint));
        };
        socks5_options.upstream_factory = factory;
        http_options.upstream_factory = factory;
    }
    const char* address = argc > 1 ? argv[1] : "127.0.0.1:1080";
    brpc::Server server;
    brpc::Server admin_server;
    brpc::ServerOptions options;
    options.socks5_service = std::make_shared<brpc::Socks5Service>(socks5_options);
    options.http_master_service = brpc::NewHttpProxyMasterService(
        std::make_shared<brpc::HttpProxyService>(http_options));
    // Both handshakes use this listener. The SOCKS5 version byte is distinct
    // from HTTP methods. After CONNECT, each connection stays in raw TCP mode.
    // Strict selection excludes ordinary http/h2 and late-header protocols.
    options.enabled_protocols = "socks5 http_proxy";
    options.strict_enabled_protocols = true;
    options.idle_timeout_sec = FLAGS_idle_timeout_sec;
    options.max_connections = 128;
    options.server_info_name = "proxy";
    if (server.Start(address, &options) != 0) return 1;

    // A separate Server retains brpc's builtin URL routing and HTTP protocols.
    // It has no proxy services and shares process-wide bvars with the proxy.
    brpc::ServerOptions admin_options;
    admin_options.enabled_protocols = "http h2";
    admin_options.strict_enabled_protocols = true;
    admin_options.server_info_name = "proxy_admin";
    admin_options.idle_timeout_sec = 30;
    admin_options.max_connections = 64;
    if (admin_server.Start(FLAGS_admin_address.c_str(), &admin_options) != 0) {
        std::cerr << "Fail to start brpc tools on " << FLAGS_admin_address
                  << std::endl;
        // Avoid leaving the proxy listener running after partial startup.
        server.Stop(0);
        server.Join();
        return 1;
    }
    std::cout << "SOCKS5 and HTTP forward/CONNECT proxy listening on "
              << address << "; connect=" << FLAGS_connect_timeout_ms
              << "ms, SOCKS5 handshake=" << FLAGS_handshake_timeout_ms
              << "ms, HTTP request=" << FLAGS_request_timeout_ms
              << "ms, idle=" << FLAGS_idle_timeout_sec << "s" << std::endl;
    std::cout << "brpc builtin tools: http://"
              << admin_server.listen_address() << std::endl;
    while (!stopping) bthread_usleep(50000);
    // Stop both acceptors before waiting for either Server's active work.
    server.Stop(0);
    admin_server.Stop(0);
    server.Join();
    admin_server.Join();
    return options.socks5_service->session_count() == 0 ? 0 : 1;
}
