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


#ifndef BRPC_HTTP_PROXY_H
#define BRPC_HTTP_PROXY_H

#include <memory>
#include <cstddef>
#include <string>
#include <google/protobuf/service.h>
#include "brpc/proxy_upstream.h"

namespace brpc {
class Controller;

struct HttpProxyOptions {
    // Applies to CONNECT tunnels. Ordinary HTTP uses the Forward hook.
    ProxyUpstreamFactory upstream_factory;
    int connect_timeout_ms = 3000;
    int request_timeout_ms = 10000;
    size_t max_pending_bytes = 1024 * 1024;
    bool IsValid() const {
        return connect_timeout_ms > 0 && request_timeout_ms > 0 &&
               max_pending_bytes != 0;
    }
};

// Install through NewHttpProxyMasterService and select the http_proxy protocol.
// The default implementation forwards HTTP requests and establishes HTTP/1.1
// CONNECT tunnels using brpc.
// There are no separate Start/Stop/Join calls. Use a trusted listener or provide
// application policy through the hooks below before exposing a forward proxy.
class HttpProxyService {
public:
    explicit HttpProxyService(const HttpProxyOptions& options = HttpProxyOptions());
    virtual ~HttpProxyService();

    // HTTP forwarding hook. Must call done->Run exactly once, including on errors.
    // The controller remains valid until done. Delegating to the base transfers
    // completion responsibility to it; do not also run done yourself.
    virtual void Forward(Controller* controller, google::protobuf::Closure* done);

    // CONNECT policy/routing hook, called on a bthread. May rewrite host/port.
    // Return true to connect, false to reply 403 and close. Do not retain pointers.
    virtual bool RouteConnect(std::string* host, int* port);

    const HttpProxyOptions& options() const { return _options; }

private:
    HttpProxyOptions _options;
};

// Create an adapter for ServerOptions.http_master_service. Server owns and
// deletes the returned adapter; it retains service through HTTP/tunnel work.
// Select enabled_protocols="http_proxy" and strict_enabled_protocols=true.
google::protobuf::Service* NewHttpProxyMasterService(
    std::shared_ptr<HttpProxyService> service);
}  // namespace brpc
#endif
