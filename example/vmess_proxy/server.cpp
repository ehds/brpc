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

#include <iostream>
#include <gflags/gflags.h>
#include "../socks5_proxy/mixed_server.h"
#include "vmess_upstream.h"

DEFINE_string(vmess_host, "", "Actual VMess gateway host, not the client target");
DEFINE_int32(vmess_port, 0, "VMess gateway TCP port");
DEFINE_string(vmess_uuid, "", "VMess AEAD user UUID");
DEFINE_string(vmess_ws_path, "", "WebSocket path; empty selects raw TCP");
DEFINE_string(vmess_ws_host, "", "Optional WebSocket Host header");
DEFINE_int64(vmess_timestamp_offset_sec, 0, "VMess authentication clock offset");

int main(int argc, char** argv) {
    GFLAGS_NAMESPACE::ParseCommandLineFlags(&argc, &argv, true);
    try {
        vmess_example::Options options;
        options.server.host = FLAGS_vmess_host;
        options.server.port = FLAGS_vmess_port;
        options.uuid = FLAGS_vmess_uuid;
        options.ws_path = FLAGS_vmess_ws_path;
        options.ws_host = FLAGS_vmess_ws_host;
        options.timestamp_offset_sec = FLAGS_vmess_timestamp_offset_sec;
        return RunProxyServer(argc, argv,
                              vmess_example::MakeUpstreamFactory(options), true);
    } catch (const std::exception& e) {
        std::cerr << "VMess configuration: " << e.what() << std::endl;
        return 1;
    }
}
