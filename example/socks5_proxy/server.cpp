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
#include <memory>
#include "bthread/bthread.h"
#include "brpc/server.h"
#include "brpc/socks5.h"

namespace {
volatile sig_atomic_t stopping = 0;
void Stop(int) { stopping = 1; }
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, Stop);
    signal(SIGTERM, Stop);
    const char* address = argc > 1 ? argv[1] : "127.0.0.1:1080";
    brpc::Server server;
    brpc::ServerOptions options;
    options.socks5_service = std::make_shared<brpc::Socks5Service>();
    // Select the listener's protocols explicitly: late-header protocols such
    // as nshead cannot exclude a three-byte SOCKS5 greeting by its prefix.
    options.enabled_protocols = "socks5";
    options.idle_timeout_sec = 30;
    options.max_connections = 128;
    if (server.Start(address, &options) != 0) return 1;
    std::cout << "SOCKS5 protocol listening on " << address << std::endl;
    while (!stopping) bthread_usleep(50000);
    server.Stop(0);
    server.Join();
    return options.socks5_service->session_count() == 0 ? 0 : 1;
}
