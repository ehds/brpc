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


#include "brpc/details/proxy_socket.h"

#include <netdb.h>
#include <cstring>
#include <memory>
#include "bthread/id.h"
#include "brpc/input_messenger.h"
#include "brpc/socket.h"
#include "butil/endpoint.h"
#include "butil/time.h"

namespace brpc {
namespace details {
namespace {
int Written(bthread_id_t id, void* arg, int error) {
    *static_cast<int*>(arg) = error;
    return bthread_id_unlock_and_destroy(id);
}
int Failed(bthread_id_t id, void* arg, int) {
    std::unique_ptr<std::function<void()>> callback(
        static_cast<std::function<void()>*>(arg));
    bthread_id_unlock_and_destroy(id);
    (*callback)();
    return 0;
}
}  // namespace

bool WriteProxyData(SocketId id, butil::IOBuf* data) {
    SocketUniquePtr socket;
    if (Socket::Address(id, &socket) != 0) return false;
    bthread_id_t wait;
    int error = 0;
    if (bthread_id_create(&wait, &error, Written) != 0) return false;
    Socket::WriteOptions options;
    options.id_wait = wait;
    options.notify_on_success = true;
    if (socket->Write(data, &options) != 0) bthread_id_error(wait, errno);
    bthread_id_join(wait);
    return error == 0;
}

void WatchProxySocketFailure(SocketId socket_id, std::function<void()> callback) {
    auto* arg = new std::function<void()>(std::move(callback));
    bthread_id_t id;
    if (bthread_id_create(&id, arg, Failed) != 0) {
        std::unique_ptr<std::function<void()>> guard(arg);
        (*arg)();
        return;
    }
    SocketUniquePtr socket;
    if (Socket::Address(socket_id, &socket) != 0) {
        bthread_id_error(id, ECONNRESET);
    } else {
        socket->NotifyOnFailed(id);
    }
}

ProxySocketConnectResult ConnectProxySocket(
    InputMessenger* input, const std::string& host, int port, int timeout_ms,
    const std::function<Destroyable*()>& make_context,
    const std::function<bool()>& cancelled) {
    ProxySocketConnectResult result;
    addrinfo hints = {};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* addresses = nullptr;
    // HTTP authority syntax brackets IPv6 literals; the system resolver does not.
    const std::string name = host.size() > 2 && host.front() == '[' && host.back() == ']'
        ? host.substr(1, host.size() - 2) : host;
    if (getaddrinfo(name.c_str(), std::to_string(port).c_str(), &hints, &addresses) != 0) {
        result.error = EHOSTUNREACH;
        result.resolve_failed = true;
        return result;
    }
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(addresses, freeaddrinfo);
    const timespec deadline = butil::milliseconds_from_now(timeout_ms);
    result.error = ECONNREFUSED;
    for (auto* a = addresses; a; a = a->ai_next) {
        if (cancelled()) { result.error = ECANCELED; break; }
        sockaddr_storage address = {};
        if (a->ai_addrlen > sizeof(address)) continue;
        memcpy(&address, a->ai_addr, a->ai_addrlen);
        SocketOptions options;
        if (butil::sockaddr2endpoint(&address, a->ai_addrlen, &options.remote_side) != 0) {
            continue;
        }
        options.connect_on_create = true;
        options.defer_eof = true;
        options.connect_abstime = &deadline;
        options.initial_parsing_context = make_context();
        if (input->Create(options, &result.socket_id) == 0) {
            result.error = 0;
            return result;
        }
        result.socket_id = INVALID_SOCKET_ID;
        result.error = errno ? errno : ECONNREFUSED;
    }
    return result;
}
}  // namespace details
}  // namespace brpc
