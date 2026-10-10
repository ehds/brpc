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

#ifndef BRPC_EXAMPLE_VMESS_UPSTREAM_H
#define BRPC_EXAMPLE_VMESS_UPSTREAM_H
#include <cstdint>
#include "brpc/proxy_upstream.h"

namespace vmess_example {
struct Options {
    brpc::ProxyTarget server;
    std::string uuid;
    std::string ws_path;  // Empty selects raw TCP. Otherwise, plain WebSocket.
    std::string ws_host;
    int64_t timestamp_offset_sec = 0;
};
// Validates configuration once. Throws std::exception on invalid configuration.
// Each factory invocation creates independent VMess keys and stream state.
brpc::ProxyUpstreamFactory MakeUpstreamFactory(const Options& options);
}  // namespace vmess_example
#endif
