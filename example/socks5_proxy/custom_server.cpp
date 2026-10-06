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
#include <iostream>
#include "bthread/bthread.h"
#include "brpc/closure_guard.h"
#include "brpc/server.h"
#include "brpc/socks5.h"
#include "butil/iobuf.h"

namespace {
volatile sig_atomic_t stopping = 0;
void Stop(int) { stopping = 1; }

// Accept a logical destination and echo DATA locally, without an upstream.
// Authentication negotiation still delegates to the default implementation.
class EchoService : public brpc::Socks5Service {
public:
    void Process(brpc::Socks5Connection* connection, brpc::Socks5Request* request,
                 google::protobuf::Closure* done) override {
        if (request->type == brpc::Socks5Request::METHOD) {
            brpc::Socks5Service::Process(connection, request, done);
            return;
        }
        brpc::ClosureGuard guard(done);
        if (request->type == brpc::Socks5Request::CONNECT) {
            connection->set_user_data(std::make_shared<uint64_t>(0));
            connection->ReplyConnect(0);
        } else {
            auto count = std::static_pointer_cast<uint64_t>(connection->user_data());
            *count += request->data.size();
            // butil::IOBuf buf;
            // buf.append("hello")
            // Echo bytes immediately; this is not an HTTP response. A curl
            // client allowing HTTP/0.9 waits for EOF to finish reading it.
            connection->Write(&request->data);
        }
    }
};
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, Stop);
    signal(SIGTERM, Stop);
    const char* address = argc > 1 ? argv[1] : "127.0.0.1:1081";
    brpc::Server server;
    brpc::ServerOptions options;
    options.socks5_service = std::make_shared<EchoService>();
    options.enabled_protocols = "socks5";
    options.idle_timeout_sec = 30;
    options.max_connections = 128;
    if (server.Start(address, &options) != 0) return 1;
    std::cout << "Custom SOCKS5 echo service listening on " << address
              << " (raw byte echo; no upstream connection or HTTP response)"
              << std::endl;
    while (!stopping) bthread_usleep(50000);
    server.Stop(0);
    server.Join();
    return options.socks5_service->session_count() == 0 ? 0 : 1;
}
