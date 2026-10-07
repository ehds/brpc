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

#include "brpc/policy/http_proxy_protocol.h"

#include "brpc/controller.h"
#include "brpc/details/proxy_socket.h"
#include "brpc/details/proxy_upstream.h"
#include "brpc/details/server_private_accessor.h"
#include "brpc/details/tcp_tunnel.h"
#include "brpc/http_status_code.h"
#include "brpc/input_messenger.h"
#include "brpc/policy/http_rpc_protocol.h"
#include "brpc/server.h"
#include "brpc/socket.h"
#include "bthread/mutex.h"
#include <mutex>

namespace brpc {
namespace policy {

struct HttpProxySession : details::TcpTunnel {
  // The service does not own sessions, so retaining it creates no cycle.
  std::shared_ptr<HttpProxyService> service;
};

// Proxy-only connection state never enters the ordinary HTTP RPC context.
struct HttpProxyContext : HttpContext {
  HttpProxyContext() : HttpContext(false) {}
  // CONNECT session in the Socket's parsing context.
  // Non-null selects raw data parsing, even while connecting upstream.
  std::shared_ptr<HttpProxySession> session;
  bool invalid_target = false;
  void CheckProgressiveRead(const void *arg, Socket *socket) override {
    // Proxy Forward uses a complete attachment. Progressive flags belonging
    // to unrelated URL services must not affect the master service route.
    const auto *server = static_cast<const Server *>(arg);
    if (server && IsInternalPort(*server, socket->local_side())) {
      HttpContext::CheckProgressiveRead(arg, socket);
    }
  }
};

namespace {
bool ValidTarget(const std::string &target, bool connect) {
  http_parser_url parsed = {};
  if (target.empty() || http_parser_parse_url(target.data(), target.size(),
                                            connect, &parsed) != 0)
    return false;
  // CONNECT parsing requires host:port; port zero is not a destination.
  return !connect || parsed.port != 0;
}
HttpContext *NewProxyContext(Socket *) { return new HttpProxyContext; }

butil::IOBuf MakeConnectResponse(int code) {
  butil::IOBuf response;
  if (code == HTTP_STATUS_OK) {
    // A successful CONNECT has no HTTP body or length/transfer-encoding header.
    response.append("HTTP/1.1 200 Connection Established\r\n\r\n");
  } else {
    HttpHeader header;
    header.set_status_code(code);
    header.SetHeader("Connection", "close");
    MakeRawHttpResponse(&response, &header, nullptr);
  }
  return response;
}

int Connect(const std::shared_ptr<HttpProxySession> &s,
            const HttpProxyContext &message) {
  if (!ValidTarget(message.request_target(), true))
    return HTTP_STATUS_BAD_REQUEST;
  if (!s->service->options().IsValid()) {
    return HTTP_STATUS_INTERNAL_SERVER_ERROR;
  }
  const URI &uri = message.header().uri();
  std::string host = uri.host();
  int port = uri.port();
  if (!s->service->RouteConnect(&host, &port))
    return HTTP_STATUS_FORBIDDEN;
  // The routing hook may rewrite the validated client destination.
  if (host.empty() || port <= 0 || port > 65535)
    return HTTP_STATUS_BAD_REQUEST;
  auto peer =
      HttpProxySession::CreateUpstream(s, s->service->options().upstream_factory);
  if (!peer)
    return HTTP_STATUS_INTERNAL_SERVER_ERROR;
  ProxyConnectRequest request;
  request.target.host = uri.host();
  request.target.port = uri.port();
  request.route.host = host;
  request.route.port = port;
  request.timeout_ms = s->service->options().connect_timeout_ms;
  const auto result = details::AwaitProxyConnect(peer.get(), request);
  if (result.error)
    return result.error == ETIMEDOUT ? HTTP_STATUS_GATEWAY_TIMEOUT
                                     : HTTP_STATUS_BAD_GATEWAY;
  return HTTP_STATUS_OK;
}

butil::Status PrepareHttpProxyConnect(HttpProxyContext *message, Socket *socket,
                                      const std::shared_ptr<HttpProxyService> &service,
                                      const Server* server) {
  auto request = std::shared_ptr<HttpProxyContext>(message,
      [](HttpProxyContext* m) { m->Destroy(); });
  auto session = std::make_shared<HttpProxySession>();
  session->client = socket->id();
  session->service = service;
  session->max_pending_bytes = service->options().max_pending_bytes;
  // Switch to raw-data parsing immediately; queued data follows this handshake.
  auto *context = new HttpProxyContext;
  context->session = session;
  socket->reset_parsing_context(context);
  socket->EnableDeferredEOF();
  socket->fail_me_at_server_stop();
  HttpProxySession::WatchFailure(socket->id(), session);
  return session->Submit(socket, nullptr, 0, nullptr, [session, request, server] {
    SocketUniquePtr client;
    if (Socket::Address(session->client, &client) != 0) return false;
    int auth_error = 0;
    if (client->FightAuthentication(&auth_error) == 0) {
      const bool valid = VerifyHttpRequest(request.get(), server, client.get());
      client->SetAuthentication(valid ? 0 : ERPCAUTH);
      if (!valid) return false;
    } else if (auth_error != 0) {
      return false;
    }
    const int code = Connect(session, *request);
    auto response = MakeConnectResponse(code);
    return session->WriteClient(&response) && code == HTTP_STATUS_OK;
  });
}
} // namespace

ParseResult ParseHttpProxyMessage(butil::IOBuf *source, Socket *socket,
                                  bool read_eof, const void *arg) {
  const auto *server = static_cast<const Server *>(arg);
  if (!server)
    return MakeParseError(PARSE_ERROR_TRY_OTHERS);
  auto service = GetHttpProxyService(server->options().http_master_service);
  if (!service)
    return MakeParseError(PARSE_ERROR_TRY_OTHERS);
  auto *context = static_cast<HttpProxyContext *>(socket->parsing_context());
  if (context && context->session) {
    // CONNECT changes the input to raw tunnel data. The serial queue keeps
    // these bytes behind the handshake, including while Connect is pending.
    auto session = context->session;
    if (source->empty()) return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
    const auto status = session->ReceiveClient(socket, source);
    return status.ok() ? MakeMessage(nullptr) : details::MakeTunnelEnqueueError(status);
  }
  // Shared framing, including fragmented/chunked messages and size limits.
  const ParseResult result = ParseHttpMessageWithContext(
      source, socket, read_eof, arg, NewProxyContext);
  if (!result.is_ok() || !result.message())
    return result;
  auto *message = static_cast<HttpProxyContext *>(result.message());
  if (IsInternalPort(*server, socket->local_side()))
    return result;
  if (message->header().method() == HTTP_METHOD_CONNECT) {
    // Commit the mode switch during serialized parsing, before dispatch or
    // reading more bytes. No HTTP parsing takes place in this state.
    const auto status = PrepareHttpProxyConnect(message, socket, service, server);
    return status.ok() ? MakeMessage(nullptr) : details::MakeTunnelEnqueueError(status);
  } else {
    // URI normalizes an invalid port to -1. Validate the original target so
    // it cannot accidentally become a request to the default HTTP port.
    message->invalid_target = !ValidTarget(message->request_target(), false);
  }
  return result;
}

void ProcessHttpProxyRequest(InputMessageBase *input) {
  auto *message = static_cast<HttpProxyContext *>(input);
  if (message->invalid_target) {
    DestroyingPtr<HttpProxyContext> guard(message);
    auto response = MakeConnectResponse(HTTP_STATUS_BAD_REQUEST);
    details::WriteProxyData(message->socket()->id(), &response);
    message->socket()->SetFailed();
    return;
  }
  // Normal HTTP dispatch selects http_master_service, whose adapter invokes
  // Forward. Controller setup, response framing and completion stay shared.
  ProcessHttpRequest(input);
}
} // namespace policy
} // namespace brpc
