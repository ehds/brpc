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


#ifndef BRPC_DETAILS_PROXY_SOCKET_H
#define BRPC_DETAILS_PROXY_SOCKET_H

#include <functional>
#include <string>
#include "brpc/destroyable.h"
#include "brpc/socket_id.h"
#include "butil/iobuf.h"

namespace brpc {
class InputMessenger;
namespace details {

// Consume data and wait for brpc's write completion, including on accepted sockets.
bool WriteProxyData(SocketId id, butil::IOBuf* data);

// One-shot notification. The callback runs after the notification id is destroyed,
// so it may safely fail a peer socket. Registration failure also invokes callback.
void WatchProxySocketFailure(SocketId id, std::function<void()> callback);

struct ProxySocketConnectResult {
    SocketId socket_id = INVALID_SOCKET_ID;
    int error = 0;
    bool resolve_failed = false;
};

// Resolve and try addresses with one shared connect deadline. Each socket owns
// the context returned by make_context. DNS uses the system resolver and is not
// bounded by timeout_ms. No protocol reply is sent here.
ProxySocketConnectResult ConnectProxySocket(
    InputMessenger* input, const std::string& host, int port, int timeout_ms,
    const std::function<Destroyable*()>& make_context,
    const std::function<bool()>& cancelled);

}  // namespace details
}  // namespace brpc
#endif
