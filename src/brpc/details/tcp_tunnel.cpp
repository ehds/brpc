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


#include "brpc/details/tcp_tunnel.h"

#include <cerrno>
#include <mutex>
#include "brpc/details/proxy_socket.h"
#include "brpc/details/proxy_upstream.h"

namespace brpc {
namespace details {

// A ready callable plus its lifetime/EOF guards. No protocol message or action
// is needed: the queue owns this task until execution or cancellation.
struct TcpTunnel::Task {
    ~Task() {
        if (accounted) {
            std::lock_guard<bthread::Mutex> lock(session->mutex);
            session->pending_bytes -= size;
        }
        if (input) input->CheckEOF();
    }
    std::shared_ptr<TcpTunnel> session;
    SocketUniquePtr client;
    SocketUniquePtr input;
    size_t size = 0;
    bool accounted = false;
    std::function<bool()> process;
};

TcpTunnel::~TcpTunnel() {
    if (_queue_started) bthread::execution_queue_stop(_queue);
}

void TcpTunnel::Close() {
    std::shared_ptr<ProxyUpstream> peer;
    bool stop;
    {
        std::lock_guard<bthread::Mutex> lock(mutex);
        if (closed) return;
        closed = true;
        peer = _upstream;
        stop = _queue_started;
    }
    if (stop) bthread::execution_queue_stop(_queue);
    Socket::SetFailed(client);
    if (peer) peer->Close();
    OnClosed();
}

butil::Status TcpTunnel::Submit(Socket* input, butil::IOBuf* source, size_t size,
                                butil::IOBuf* payload, std::function<bool()> process) {
    auto task = std::make_shared<Task>();
    task->session = shared_from_this();
    task->process = std::move(process);
    if (Socket::Address(client, &task->client) != 0)
        return butil::Status(ECANCELED, "Client socket is closed");
    SocketUniquePtr reader;
    if (input && Socket::Address(input->id(), &reader) != 0)
        return butil::Status(ECANCELED, "Input socket is closed");
    int error = 0;
    {
        std::lock_guard<bthread::Mutex> lock(mutex);
        if (closed) return butil::Status(ECANCELED, "Tunnel session is closed");
        if (payload && size > max_pending_bytes - pending_bytes) {
            error = ENOBUFS;
        } else {
            if (!_queue_started) {
                error = bthread::execution_queue_start(&_queue, nullptr, Consume, nullptr);
                _queue_started = error == 0;
            }
            // Keep our reference while finalizing the task below. The queue
            // implementation may move from its argument even in the const& API.
            if (!error) error = bthread::execution_queue_execute(
                _queue, std::shared_ptr<Task>(task));
            if (!error) {
                // Consume takes this same mutex before executing, so the data
                // and EOF guard are complete before the callable can run.
                if (payload) {
                    source->cutn(payload, size);
                    task->size = size;
                    pending_bytes += size;
                    task->accounted = true;
                } else if (source) {
                    source->pop_front(size);
                }
                if (reader) {
                    reader->PostponeEOF();
                    task->input = std::move(reader);
                }
            }
        }
    }
    if (!error) return butil::Status::OK();
    Close();
    return butil::Status(error, "Failed to submit tunnel task");
}

int TcpTunnel::Consume(void*, bthread::TaskIterator<std::shared_ptr<Task>>& tasks) {
    if (tasks.is_queue_stopped()) return 0;
    for (; tasks; ++tasks) {
        auto task = std::move(*tasks);
        bool run;
        {
            std::lock_guard<bthread::Mutex> lock(task->session->mutex);
            run = !task->session->closed;
        }
        if (run && !task->process()) task->session->Close();
        // Release this task's EOF/client guards before advancing the iterator.
    }
    return 0;
}

butil::Status TcpTunnel::SubmitData(Socket* input, butil::IOBuf* source,
                                    bool from_upstream) {
    auto data = std::make_shared<butil::IOBuf>();
    auto session = shared_from_this();
    return Submit(input, source, source->size(), data.get(),
        [session, data, from_upstream] {
            return from_upstream ? session->ProcessUpstreamData(data.get())
                                 : session->WriteUpstream(data.get());
        });
}

butil::Status TcpTunnel::ReceiveClient(Socket* input, butil::IOBuf* source) {
    return SubmitData(input, source, false);
}
butil::Status TcpTunnel::ReceiveUpstream(Socket* input, butil::IOBuf* source) {
    return SubmitData(input, source, true);
}

void TcpTunnel::WatchFailure(SocketId id, const std::shared_ptr<TcpTunnel>& session) {
    WatchProxySocketFailure(id, [session] { session->Close(); });
}

std::shared_ptr<ProxyUpstream> TcpTunnel::GetUpstream() {
    std::lock_guard<bthread::Mutex> lock(mutex);
    return closed ? nullptr : _upstream;
}

bool TcpTunnel::WriteClient(butil::IOBuf* data) {
    SocketId peer;
    {
        std::lock_guard<bthread::Mutex> lock(mutex);
        if (closed) return false;
        peer = client;
    }
    return WriteProxyData(peer, data);
}

bool TcpTunnel::WriteUpstream(butil::IOBuf* data) {
    auto peer = GetUpstream();
    return peer && AwaitProxyData(peer.get(), data, true) == 0;
}

bool TcpTunnel::ProcessUpstreamData(butil::IOBuf* data) {
    auto peer = GetUpstream();
    return peer && AwaitProxyData(peer.get(), data, false) == 0;
}

std::shared_ptr<ProxyUpstream> TcpTunnel::CreateUpstream(
    const std::shared_ptr<TcpTunnel>& session, const ProxyUpstreamFactory& factory) {
    {
        std::lock_guard<bthread::Mutex> lock(session->mutex);
        if (session->closed || session->_upstream) return nullptr;
    }
    // Construction may invoke user code; never hold the session mutex here.
    ProxyTunnel tunnel(session);
    std::shared_ptr<ProxyUpstream> peer = factory ? factory(tunnel) :
        std::unique_ptr<ProxyUpstream>(new ProxyUpstream(tunnel));
    if (!peer) return nullptr;
    {
        std::lock_guard<bthread::Mutex> lock(session->mutex);
        if (!session->closed && !session->_upstream) {
            session->_upstream = peer;
            return peer;
        }
    }
    // Stop may close the session during factory execution. Cancel the adapter
    // that could not be installed, without calling user Close under mutex.
    peer->Close();
    return nullptr;
}

}  // namespace details
}  // namespace brpc
