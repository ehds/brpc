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

#include "brpc/proxy_upstream.h"

#include "brpc/details/proxy_socket.h"
#include "brpc/details/proxy_upstream.h"
#include "brpc/details/tcp_tunnel.h"
#include "brpc/input_messenger.h"
#include "brpc/socket.h"
#include "bthread/countdown_event.h"
#include "bthread/mutex.h"
#include <cerrno>
#include <mutex>

namespace brpc {
struct ProxyTunnel::Impl {
    // The public handle may outlive the connection. Reference the common
    // session weakly, without retaining it or any protocol parse/process hook.
    std::weak_ptr<details::TcpTunnel> session;
};

ProxyTunnel::ProxyTunnel(const std::shared_ptr<details::TcpTunnel>& session)
    : _impl(std::make_shared<Impl>()) {
    _impl->session = session;
}

bool ProxyTunnel::Receive(butil::IOBuf* data) const {
    auto session = _impl->session.lock();
    if (!session) return false;
    {
        std::lock_guard<bthread::Mutex> lock(session->mutex);
        if (session->closed) return false;
    }
    if (data->empty()) return true;
    return session->ReceiveUpstream(nullptr, data).ok();
}
void ProxyTunnel::WriteClient(butil::IOBuf* data, Done done) const {
    auto session = _impl->session.lock();
    const int error = session && session->WriteClient(data) ? 0 : EIO;
    done(error);
}
void ProxyTunnel::Close() const {
    if (auto session = _impl->session.lock()) session->Close();
}
bool ProxyTunnel::is_closed() const {
    auto session = _impl->session.lock();
    if (!session) return true;
    std::lock_guard<bthread::Mutex> lock(session->mutex);
    return session->closed;
}

struct ProxyUpstream::NativeState {
  explicit NativeState(const ProxyTunnel &t) : tunnel(t) {
    InputMessageHandler handler = {Parse, DiscardMessage, nullptr, this,
                                   "proxy_upstream"};
    CHECK_EQ(0, input.AddNonProtocolHandler(handler));
  }
  struct Context : Destroyable {
    explicit Context(std::shared_ptr<NativeState> s) : state(std::move(s)) {}
    void Destroy() override { delete this; }
    std::shared_ptr<NativeState> state;
  };
  // Registration requires a process callback; Parse returns no messages.
  static void DiscardMessage(InputMessageBase* message) { message->Destroy(); }
  static ParseResult Parse(butil::IOBuf *source, Socket *socket, bool eof,
                           const void *) {
    auto state = static_cast<Context *>(socket->parsing_context())->state;
    // The session installs its one adapter before Connect can create a Socket.
    // Resolve that adapter through the session rather than a second owner bind.
    auto session = state->tunnel._impl->session.lock();
    auto upstream = session ? session->GetUpstream() : nullptr;
    return upstream ? upstream->ParseUpstreamData(source, socket, eof)
                    : MakeParseError(PARSE_ERROR_ABSOLUTELY_WRONG);
  }
  // Socket callbacks retain NativeState, with only a weak session handle.
  ProxyTunnel tunnel;
  InputMessenger input;
  bthread::Mutex mutex;
  SocketId socket = INVALID_SOCKET_ID;
  bool closed = false;
};

ProxyUpstream::ProxyUpstream(const ProxyTunnel &tunnel)
    : _tunnel(tunnel), _state(std::make_shared<NativeState>(tunnel)) {}
ProxyUpstream::~ProxyUpstream() { ProxyUpstream::Close(); }

void ProxyUpstream::Connect(const ProxyConnectRequest &request,
                            ConnectDone done) {
  ConnectTcp(request.route, request.timeout_ms, std::move(done));
}

void ProxyUpstream::ConnectTcp(const ProxyTarget &endpoint, int timeout_ms,
                               ConnectDone done) {
  auto state = _state;
  ProxyConnectResult result;
  if (endpoint.host.empty() || endpoint.port <= 0 || endpoint.port > 65535 ||
      timeout_ms <= 0) {
    result.error = EINVAL;
    done(result);
    return;
  }
  auto native = details::ConnectProxySocket(
      &state->input, endpoint.host, endpoint.port, timeout_ms,
      [state]() -> Destroyable * { return new NativeState::Context(state); },
      [state] {
        std::lock_guard<bthread::Mutex> lock(state->mutex);
        return state->closed || state->tunnel.is_closed();
      });
  result.error = native.error;
  result.resolve_failed = native.resolve_failed;
  if (!result.error) {
    {
      std::lock_guard<bthread::Mutex> lock(state->mutex);
      if (state->closed)
        result.error = ECANCELED;
      else
        state->socket = native.socket_id;
    }
    SocketUniquePtr socket;
    if (!result.error && Socket::Address(native.socket_id, &socket) == 0) {
      result.bound = socket->local_side();
      std::weak_ptr<NativeState> weak = state;
      details::WatchProxySocketFailure(native.socket_id, [weak] {
        if (auto live = weak.lock())
          live->tunnel.Close();
      });
      if (state->tunnel.is_closed())
        result.error = ECANCELED;
    } else if (!result.error) {
      result.error = ECONNRESET;
    }
    if (result.error)
      Socket::SetFailed(native.socket_id);
  }
  done(result);
}

void ProxyUpstream::OnClientData(butil::IOBuf *data, Done done) {
  WriteUpstream(data, std::move(done));
}
void ProxyUpstream::WriteUpstream(butil::IOBuf *data, Done done) {
  SocketId socket;
  {
    std::lock_guard<bthread::Mutex> lock(_state->mutex);
    socket = _state->closed ? INVALID_SOCKET_ID : _state->socket;
  }
  const int error = socket == INVALID_SOCKET_ID
                        ? ENOTCONN
                        : (details::WriteProxyData(socket, data) ? 0 : EIO);
  done(error);
}
void ProxyUpstream::OnUpstreamData(butil::IOBuf *data, Done done) {
    _tunnel.WriteClient(data, std::move(done));
}
ParseResult ProxyUpstream::ParseUpstreamData(butil::IOBuf *data, Socket* socket, bool) {
    auto session = _tunnel._impl->session.lock();
    if (!session) return MakeParseError(PARSE_ERROR_ABSOLUTELY_WRONG);
    if (data->empty()) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
    const auto status = session->ReceiveUpstream(socket, data);
    return status.ok() ? MakeMessage(nullptr) : details::MakeTunnelEnqueueError(status);
}
void ProxyUpstream::Close() {
  SocketId socket;
  {
    std::lock_guard<bthread::Mutex> lock(_state->mutex);
    if (_state->closed)
      return;
    _state->closed = true;
    socket = _state->socket;
  }
  if (socket != INVALID_SOCKET_ID)
    Socket::SetFailed(socket);
}

namespace details {
ParseResult MakeTunnelEnqueueError(const butil::Status& status) {
    return MakeParseError(status.error_code() == ENOBUFS
                              ? PARSE_ERROR_TOO_BIG_DATA
                              : PARSE_ERROR_ABSOLUTELY_WRONG);
}

brpc::ProxyConnectResult AwaitProxyConnect(ProxyUpstream *upstream,
                                           const ProxyConnectRequest &request) {
  brpc::ProxyConnectResult result;
  bthread::CountdownEvent finished;
  upstream->Connect(request, [&](brpc::ProxyConnectResult value) {
    result = value;
    finished.signal();
  });
  finished.wait();
  return result;
}
int AwaitProxyData(ProxyUpstream *upstream, butil::IOBuf *data,
                   bool from_client) {
  int result = 0;
  bthread::CountdownEvent finished;
  auto done = [&](int error) {
    result = error;
    finished.signal();
  };
  if (from_client)
    upstream->OnClientData(data, done);
  else
    upstream->OnUpstreamData(data, done);
  finished.wait();
  return result;
}
} // namespace details
} // namespace brpc
