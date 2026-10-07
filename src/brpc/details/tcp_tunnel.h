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


#ifndef BRPC_DETAILS_TCP_TUNNEL_H
#define BRPC_DETAILS_TCP_TUNNEL_H

#include <functional>
#include <memory>
#include "bthread/execution_queue.h"
#include "bthread/mutex.h"
#include "brpc/proxy_upstream.h"
#include "brpc/socket.h"
#include "butil/status.h"

namespace brpc {
namespace details {

// Per-connection state. Owns the upstream adapter and serializes handshake and
// data processing with bthread::ExecutionQueue. ProxyTunnel refers here weakly.
struct TcpTunnel : std::enable_shared_from_this<TcpTunnel> {
    virtual ~TcpTunnel();
    bthread::Mutex mutex;
    bool closed = false;
    size_t pending_bytes = 0;
    // Set before exposing the session to readers.
    size_t max_pending_bytes = 1024 * 1024;
    SocketId client = INVALID_SOCKET_ID;

    // Submit a complete processing function in parse order. Consume size bytes
    // into payload (or discard handshake bytes when payload is null). Retain
    // input's EOF barrier and the client Socket until processing completes.
    // Closure/limit failures leave source untouched; ENOBUFS closes the session.
    // source/input may be null for a handshake already parsed by HTTP.
    butil::Status Submit(Socket* input, butil::IOBuf* source, size_t size,
                         butil::IOBuf* payload, std::function<bool()> process);
    // Submit raw data directly to the appropriate upstream hook.
    butil::Status ReceiveClient(Socket* input, butil::IOBuf* source);
    butil::Status ReceiveUpstream(Socket* input, butil::IOBuf* source);
    // Stop accepting tasks, cancel the upstream, and discard queued work.
    // Never wait here: Close may run from the consumer itself.
    void Close();
    virtual void OnClosed() {}
    static void WatchFailure(SocketId id, const std::shared_ptr<TcpTunnel>& session);
    // Empty after closure; a snapshot retains the adapter during a callback.
    std::shared_ptr<ProxyUpstream> GetUpstream();
    bool WriteClient(butil::IOBuf* data);
    bool WriteUpstream(butil::IOBuf* data);
    bool ProcessUpstreamData(butil::IOBuf* data);
    // Install the one adapter before calling Connect. User factory runs unlocked.
    static std::shared_ptr<ProxyUpstream> CreateUpstream(
        const std::shared_ptr<TcpTunnel>& session, const ProxyUpstreamFactory& factory);
private:
    struct Task;
    static int Consume(void*, bthread::TaskIterator<std::shared_ptr<Task>>& tasks);
    butil::Status SubmitData(Socket* input, butil::IOBuf* source, bool from_upstream);
    std::shared_ptr<ProxyUpstream> _upstream;
    bthread::ExecutionQueueId<std::shared_ptr<Task>> _queue = {};
    bool _queue_started = false;
};

}  // namespace details
}  // namespace brpc
#endif
