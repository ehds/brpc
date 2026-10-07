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


#ifndef BRPC_SOCKS5_H
#define BRPC_SOCKS5_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <google/protobuf/service.h>
#include "butil/endpoint.h"
#include "butil/iobuf.h"
#include "brpc/proxy_upstream.h"

namespace brpc {
namespace policy {
struct Socks5Runtime;
struct Socks5Session;
struct Socks5Dispatcher;
}

// DATA is an arbitrary TCP chunk, not a complete application message.
struct Socks5Request {
    enum Type { METHOD, CONNECT, DATA } type = METHOD;
    std::vector<unsigned char> methods;
    unsigned char address_type = 0;
    std::string host;
    uint16_t port = 0;
    butil::IOBuf data;
};

// Copyable handle. Copies may outlive a callback; operations fail after close.
// Writes wait for brpc's write completion and consume the supplied IOBuf.
class Socks5Connection {
public:
    uint64_t socket_id() const;
    bool is_closed() const;
    // This implementation supports method 0 (no authentication) or 255
    // (reject). Selecting method 0 requires it to have been offered.
    bool ReplyMethod(unsigned char method) const;
    // Reply exactly once to CONNECT. A nonzero result closes the connection
    // after sending; success enables DATA handling and stops the handshake timer.
    bool ReplyConnect(unsigned char code,
                      const butil::EndPoint& bound = butil::EndPoint()) const;
    bool Write(butil::IOBuf* data) const;
    void Close() const;
    void set_user_data(std::shared_ptr<void> data) const;
    std::shared_ptr<void> user_data() const;

private:
    friend class Socks5Service;
    friend struct policy::Socks5Dispatcher;
    explicit Socks5Connection(std::shared_ptr<policy::Socks5Session> session)
        : _session(std::move(session)) {}
    std::shared_ptr<policy::Socks5Session> _session;
};

struct Socks5Options {
    // One adapter per connection; empty selects the default brpc TCP adapter.
    ProxyUpstreamFactory upstream_factory;
    size_t max_pending_bytes = 1024 * 1024;
    int handshake_timeout_ms = 10000;
    int connect_timeout_ms = 3000;

    bool IsValid() const {
        return max_pending_bytes != 0 && handshake_timeout_ms > 0 &&
               connect_timeout_ms > 0;
    }
};

// Server-side, no-authentication SOCKS5 TCP CONNECT service. Explicitly opt in
// with ServerOptions::socks5_service. Like other protocol services, it needs no
// explicit Start/Stop/Join. A service may be shared by multiple Servers.
class Socks5Service : public std::enable_shared_from_this<Socks5Service> {
public:
    explicit Socks5Service(const Socks5Options& options = Socks5Options());
    virtual ~Socks5Service();
    size_t session_count() const;

    // Override to handle METHOD, CONNECT and DATA, or delegate selected requests
    // to Socks5Service::Process for the default TCP proxy behavior. Owned by
    // ServerOptions via shared_ptr. Call done->Run() exactly once, including
    // after a connection closes, and do not delete done. connection/request
    // stay valid until Run(); Run() must be the last use of these pointers.
    // Calls on one connection are serialized through done, while different
    // connections may run concurrently. Asynchronous handlers must arrange
    // completion themselves; Server::Join waits for their completion.
    virtual void Process(Socks5Connection* connection, Socks5Request* request,
                         google::protobuf::Closure* done);

    // Internal protocol entry point. Returns null for invalid configuration
    // or when the accepted Socket has already failed.
    std::shared_ptr<policy::Socks5Session> NewSession(uint64_t socket_id);

private:
    std::shared_ptr<policy::Socks5Runtime> _runtime;
    Socks5Service(const Socks5Service&) = delete;
    Socks5Service& operator=(const Socks5Service&) = delete;
};
}  // namespace brpc
#endif  // BRPC_SOCKS5_H
