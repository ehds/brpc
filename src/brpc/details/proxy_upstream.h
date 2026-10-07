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


#ifndef BRPC_DETAILS_PROXY_UPSTREAM_H
#define BRPC_DETAILS_PROXY_UPSTREAM_H

#include "brpc/proxy_upstream.h"
#include "brpc/parse_result.h"
#include "butil/status.h"

namespace brpc {
namespace details {
// Parser adapters convert a failed enqueue Status into a brpc ParseResult.
// ENOBUFS maps to TOO_BIG_DATA; closure maps to ABSOLUTELY_WRONG. Do not pass
// Status error text into ParseResult: its description would outlive the Status.
ParseResult MakeTunnelEnqueueError(const butil::Status& status);
brpc::ProxyConnectResult AwaitProxyConnect(ProxyUpstream* upstream,
                                     const ProxyConnectRequest& request);
int AwaitProxyData(ProxyUpstream* upstream, butil::IOBuf* data, bool from_client);
}  // namespace details
}  // namespace brpc
#endif
