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


#ifndef BRPC_PROXY_UPSTREAM_H
#define BRPC_PROXY_UPSTREAM_H

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include "butil/endpoint.h"
#include "butil/iobuf.h"
#include "brpc/parse_result.h"

namespace brpc {
namespace details { struct TcpTunnel; }
class Socket;

struct ProxyTarget {
    std::string host;
    int port = 0;
};

struct ProxyConnectRequest {
    // Original client destination, even when connecting to another gateway.
    ProxyTarget target;
    // Routing hint used by the default TCP implementation, not a requirement.
    ProxyTarget route;
    int timeout_ms = 3000;
};

struct ProxyConnectResult {
    int error = 0;  // 0 means the upstream is ready for client data.
    bool resolve_failed = false;
    butil::EndPoint bound;  // Address reported in a SOCKS5 CONNECT reply.
};

// Client-side operations for an upstream adapter. This copyable handle refers
// weakly to the connection's TcpTunnel session; it owns neither the session nor
// the upstream adapter. Close/is_closed may run concurrently with processing.
class ProxyTunnel {
public:
    using Done = std::function<void(int)>;
    // Submit raw upstream data to the ordered queue, behind the handshake.
    // Accepted data is consumed and delivered to OnUpstreamData. Call in stream
    // order; true means acceptance, not completion of the client write.
    bool Receive(butil::IOBuf* data) const;
    // Write processed data directly to the client, without invoking
    // OnUpstreamData or enqueuing another action. Call from OnUpstreamData
    // before completing its done callback to preserve handshake/data ordering.
    // Raw data from a transport callback must enter through Receive instead.
    // This may wait for socket output and calls done exactly once (possibly
    // inline): 0 means written to the socket, EIO means rejected/failed,
    // including a closed or expired session. Completion does not imply receipt
    // by the client application. data must remain alive until done; it may be
    // consumed even on failure. Do not access data after signaling hook completion.
    void WriteClient(butil::IOBuf* data, Done done) const;
    void Close() const;
    bool is_closed() const;
private:
    friend struct details::TcpTunnel;
    friend class ProxyUpstream;
    struct Impl;
    explicit ProxyTunnel(const std::shared_ptr<details::TcpTunnel>& session);
    std::shared_ptr<Impl> _impl;
};

// One adapter per connection, owned by its internal TcpTunnel session.
// The default methods use brpc TCP sockets. Override
// any method, including Connect, to use a different destination or transport.
// Data is an arbitrary TCP chunk; application framing belongs to the adapter.
class ProxyUpstream {
public:
    using Done = ProxyTunnel::Done;
    using ConnectDone = std::function<void(ProxyConnectResult)>;
    explicit ProxyUpstream(const ProxyTunnel& tunnel);
    virtual ~ProxyUpstream();
    virtual void Connect(const ProxyConnectRequest& request, ConnectDone done);
    virtual void OnClientData(butil::IOBuf* data, Done done);
    virtual void WriteUpstream(butil::IOBuf* data, Done done);
    // Process queued upstream data. The default calls tunnel().WriteClient;
    // overrides can use the same explicit output interface after processing.
    virtual void OnUpstreamData(butil::IOBuf* data, Done done);
    // Native brpc reader hook, serialized per socket, including during Connect.
    // Consume upstream control/negotiation frames and return MakeMessage(nullptr),
    // or NOT_ENOUGH_DATA for an incomplete frame. Delegate payload to the base,
    // which submits it directly to the serial queue and retains socket's EOF
    // barrier. Return no message: there is no second message-processing stage.
    // Do not wait for queued tasks here. Custom transports use Receive instead.
    virtual ParseResult ParseUpstreamData(butil::IOBuf* data, Socket* socket,
                                         bool read_eof);
    virtual void Close();

    // Connect/OnClientData/OnUpstreamData execute serially per tunnel.
    // ParseUpstreamData and Close can run concurrently with these hooks.
    // Call done exactly once, including after Close. Request/data and this
    // remain alive until done; do not access them after signaling completion.
    // done means this operation finished, not that the destination replied.
    // Async implementations must cancel/complete pending work on Close;
    // Server::Join waits for completion. Close must be idempotent and must
    // not wait for the serial dispatcher to run another queued action.
protected:
    const ProxyTunnel& tunnel() const { return _tunnel; }
    // Actual endpoint may differ from both request.target and request.route.
    // Transport/proxy negotiation belongs in Connect before calling done.
    void ConnectTcp(const ProxyTarget& endpoint, int timeout_ms, ConnectDone done);
private:
    struct NativeState;
    // Client operations, with a weak back-reference to the owning session.
    ProxyTunnel _tunnel;
    std::shared_ptr<NativeState> _state;
};

// Construct an adapter with the supplied client handle. The framework installs
// it in the session before calling Connect; the factory only constructs it.
using ProxyUpstreamFactory =
    std::function<std::unique_ptr<ProxyUpstream>(const ProxyTunnel&)>;
}  // namespace brpc
#endif
