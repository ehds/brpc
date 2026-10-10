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

// Shared example runner: protocol services, listener, tools server and shutdown.
#ifndef BRPC_EXAMPLE_MIXED_SERVER_H
#define BRPC_EXAMPLE_MIXED_SERVER_H
#include "brpc/proxy_upstream.h"
// argv contains only positional arguments; caller parses gflags first.
int RunProxyServer(int argc, char** argv,
                   const brpc::ProxyUpstreamFactory& upstream_factory,
                   bool connect_only);
#endif
