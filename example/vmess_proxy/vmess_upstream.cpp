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

#include "vmess_upstream.h"

#include "brpc/details/http_message.h"
#include "bthread/condition_variable.h"
#include "bthread/countdown_event.h"
#include "bthread/mutex.h"
#include "butil/time.h"
#include "vmess/chunk.hpp"
#include "vmess/crypto.hpp"
#include "vmess/header.hpp"
#include "vmess/kdf.hpp"
#include "vmess/uuid.hpp"
#include "vmess/ws_frame.hpp"
#include "ws_codec.h"
#include <algorithm>
#include <array>
#include <butil/logging.h>
#include <cerrno>
#include <chrono>
#include <mutex>
#include <span>

namespace vmess_example {
namespace {
using vmess::Bytes;

class VmessUpstream : public brpc::ProxyUpstream {
public:
  VmessUpstream(const brpc::ProxyTunnel &tunnel, Options options,
                vmess::Uuid uuid)
      : ProxyUpstream(tunnel), _options(std::move(options)), _uuid(uuid),
        _upgrade_pending(!_options.ws_path.empty()) {}

  void Connect(const brpc::ProxyConnectRequest &request,
               ConnectDone done) override {
    const auto deadline = butil::milliseconds_from_now(request.timeout_ms);
    Bytes header;
    try {
      vmess::RequestOptions target;
      LOG(INFO)<<request.target.host;
      // Route selects the gateway; VMess still carries the original target.
      target.address = request.target.host;
      target.port = request.target.port;
      const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
      header = vmess::build_request_header(_uuid, target, _keys,
                                           now + _options.timestamp_offset_sec);
      _tx = vmess::ChunkCodec(_keys.request_body_key.data(),
                              _keys.request_body_iv.data());
      _rx = vmess::ChunkCodec(_keys.response_body_key.data(),
                              _keys.response_body_iv.data());
      _response.bind(_keys, _keys.response_header);
      _chunks.bind(_rx);
      if (_upgrade_pending) {
        _ws_key = NewWebSocketKey();
        _ws_accept = WebSocketAccept(_ws_key);
      }
    } catch (const std::exception &e) {
      Fail("request header", e);
      brpc::ProxyConnectResult result;
      result.error = EPROTO;
      done(result);
      return;
    }
    ConnectTcp(_options.server, request.timeout_ms,
               [this, header, deadline, done](brpc::ProxyConnectResult result) {
                 if (!result.error && !_options.ws_path.empty()) {
                   std::string host = _options.ws_host;
                   if (host.empty()) {
                     host = _options.server.host;
                     if (host.find(':') != std::string::npos)
                       host = '[' + host + ']';
                     host += ':' + std::to_string(_options.server.port);
                   }
                   std::string upgrade =
                       "GET " + _options.ws_path +
                       " HTTP/1.1\r\nHost: " + host +
                       "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Key: " +
                       _ws_key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
                   result.error = WriteNative(vmess::as_bytes(upgrade));
                   if (!result.error) {
                     std::unique_lock<bthread::Mutex> lock(_mutex);
                     while (_upgrade_pending && !_closed && !_upgrade_error) {
                       if (_changed.wait_until(lock, deadline) == ETIMEDOUT) {
                         _upgrade_error = ETIMEDOUT;
                         break;
                       }
                     }
                     result.error = _closed ? ECANCELED : _upgrade_error;
                   }
                 }
                 if (!result.error) {
                   try {
                     result.error = WriteWire(header);
                   } catch (const std::exception &e) {
                     Fail("send header", e);
                     result.error = EPROTO;
                   }
                 }
                 // Do not await the VMess response here: Xray may flush it only
                 // after the target replies. The client must first send
                 // payload. The protocol sends its failure reply before closing
                 // the session. Closing here would abort that reply
                 // prematurely.
                 done(result);
               });
  }

  void OnClientData(butil::IOBuf *data, Done done) override {
    int error = 0;
    try {
      // Bound encryption buffers, independently of TCP read chunk size.
      std::array<uint8_t, 8174> bytes;
      while (!data->empty() && !error) {
        const size_t n = data->cutn(bytes.data(), bytes.size());
        error = WriteWire(_tx.seal({bytes.data(), n}));
      }
    } catch (const std::exception &e) {
      Fail("encrypt data", e);
      error = EPROTO;
    }
    done(error);
  }

  brpc::ParseResult ParseUpstreamData(butil::IOBuf *data, brpc::Socket *socket,
                                      bool eof) override {
    if (!_options.ws_path.empty()) {
      std::unique_lock<bthread::Mutex> lock(_mutex);
      if (_upgrade_pending) {
        if (data->empty()) {
          if (eof) {
            _upgrade_error = EPROTO;
            _changed.notify_all();
          }
          // A successful parse must consume input. Returning OK for
          // an empty buffer makes InputMessenger retry indefinitely.
          return brpc::MakeParseError(brpc::PARSE_ERROR_NOT_ENOUGH_DATA);
        }
        if (_upgrade_error) {
          data->clear();
          return brpc::MakeMessage(nullptr);
        }
        // Read only the HTTP header. brpc's HTTP parser may otherwise
        // interpret coalesced WebSocket bytes as another HTTP response.
        constexpr size_t kMaxHeaders = 16 * 1024;
        const size_t previous = _upgrade_head.size();
        std::string part;
        data->copy_to(&part, std::min(data->size(), kMaxHeaders - previous));
        _upgrade_head += part;
        const size_t end = _upgrade_head.find("\r\n\r\n");
        const bool complete = end != std::string::npos;
        const size_t consumed = complete ? end + 4 - previous : part.size();
        int error = 0;
        if (complete) {
          _upgrade_head.resize(end + 4);
          const ssize_t n = _upgrade.ParseFromArray(_upgrade_head.data(),
                                                    _upgrade_head.size());
          const auto &h = _upgrade.header();
          const auto *accept = h.GetHeader("Sec-WebSocket-Accept");
          const auto *upgrade = h.GetHeader("Upgrade");
          const auto *connection = h.GetHeader("Connection");
          if (n < 0 || !_upgrade.Completed() ||
              h.status_code() != brpc::HTTP_STATUS_SWITCHING_PROTOCOLS ||
              !accept || *accept != _ws_accept || !upgrade ||
              !HasHeaderToken(*upgrade, "websocket") || !connection ||
              !HasHeaderToken(*connection, "upgrade"))
            error = EPROTO;
        } else if (_upgrade_head.size() == kMaxHeaders || eof) {
          error = EPROTO;
        }
        // Queue the header bytes too, only to retain the native EOF
        // guard until CONNECT's success/failure reply has been written.
        // OnUpstreamData discards these bytes before decoding frames.
        butil::IOBuf prefix;
        data->cutn(&prefix, consumed);
        _upgrade_discard_bytes += consumed;
        lock.unlock();
        const auto queued =
            prefix.empty()
                ? brpc::MakeMessage(nullptr)
                : ProxyUpstream::ParseUpstreamData(&prefix, socket, false);
        lock.lock();
        if (error)
          _upgrade_error = error;
        else if (complete)
          _upgrade_pending = false;
        if (error || complete)
          _changed.notify_all();
        if (!queued.is_ok())
          return queued;
        if (error) {
          data->clear();
          return brpc::MakeMessage(nullptr);
        }
        if (data->empty())
          return brpc::MakeMessage(nullptr);
        if (!complete)
          return brpc::MakeParseError(brpc::PARSE_ERROR_NOT_ENOUGH_DATA);
      }
    }
    return ProxyUpstream::ParseUpstreamData(data, socket, eof);
  }

  void OnUpstreamData(butil::IOBuf *data, Done done) override {
    butil::IOBuf plaintext;
    {
      std::lock_guard<bthread::Mutex> lock(_mutex);
      const size_t discard = std::min(_upgrade_discard_bytes, data->size());
      data->pop_front(discard);
      _upgrade_discard_bytes -= discard;
    }
    try {
      // Connect and both data hooks share the existing serial queue;
      // codec counters and incremental readers need no extra locks.
      std::array<uint8_t, 16384> bytes;
      while (!data->empty() && !_peer_eof) {
        const size_t n = data->cutn(bytes.data(), bytes.size());
        const std::span<const uint8_t> input(bytes.data(), n);
        if (_options.ws_path.empty()) {
          Decode(input, &plaintext);
        } else {
          _frames.feed(input);
          Bytes payload;
          std::string error;
          for (;;) {
            const auto event = _frames.next(payload, error);
            if (event == vmess::WsFrameReader::Event::NeedMore)
              break;
            if (event == vmess::WsFrameReader::Event::Error)
              throw vmess::Error(error);
            if (event == vmess::WsFrameReader::Event::Close) {
              _peer_eof = true;
              break;
            }
            if (event == vmess::WsFrameReader::Event::Ping) {
              if (WriteWire(payload, 0xA))
                throw vmess::Error("pong write failed");
            } else if (event == vmess::WsFrameReader::Event::Data) {
              Decode(payload, &plaintext);
              if (_peer_eof)
                break;
            }
          }
        }
      }
    } catch (const std::exception &e) {
      Fail("decode response", e);
      done(EPROTO);
      return;
    }
    const bool ended = _peer_eof;
    if (plaintext.empty()) {
      done(ended ? ECONNRESET : 0);
      return;
    }
    // Write the final decrypted bytes before telling the queue to close.
    tunnel().WriteClient(&plaintext, [done, ended](int error) {
      done(error ? error : (ended ? ECONNRESET : 0));
    });
  }

  void Close() override {
    {
      std::lock_guard<bthread::Mutex> lock(_mutex);
      _closed = true;
      _changed.notify_all(); // Cancel a pending WebSocket upgrade wait.
    }
    ProxyUpstream::Close();
  }

private:
  int WriteNative(std::span<const uint8_t> bytes) {
    butil::IOBuf wire;
    wire.append(bytes.data(), bytes.size());
    int result = 0;
    bthread::CountdownEvent finished;
    // Explicitly call the native writer; plaintext must pass through
    // OnClientData.
    ProxyUpstream::WriteUpstream(&wire, [&](int error) {
      result = error;
      finished.signal();
    });
    finished.wait();
    return result;
  }
  int WriteWire(std::span<const uint8_t> bytes, uint8_t opcode = 0x2) {
    if (_options.ws_path.empty())
      return WriteNative(bytes);
    // Reuse the original demo's masked-frame encoding, with native output.
    const auto frame = EncodeClientFrame(opcode, bytes);
    return WriteNative(frame);
  }
  void Decode(std::span<const uint8_t> input, butil::IOBuf *plaintext) {
    if (!_response.done()) {
      _response.feed(input);
      vmess::ResponseHeader header;
      std::string error;
      const auto event = _response.next(header, error);
      if (event == vmess::ResponseHeaderReader::Event::Error)
        throw vmess::Error(error);
      if (event == vmess::ResponseHeaderReader::Event::NeedMore)
        return;
      if (header.command_id != 0)
        throw vmess::Error("unsupported VMess response command");
      _chunks.feed(_response.take_remaining());
    } else {
      _chunks.feed(input);
    }
    Bytes chunk;
    std::string error;
    for (;;) {
      const auto event = _chunks.next(chunk, error);
      if (event == vmess::ChunkReader::Event::NeedMore)
        return;
      if (event == vmess::ChunkReader::Event::Error)
        throw vmess::Error(error);
      if (event == vmess::ChunkReader::Event::Eof) {
        _peer_eof = true;
        return;
      }
      plaintext->append(chunk.data(), chunk.size());
    }
  }
  static void Fail(const char *stage, const std::exception &e) {
    LOG(WARNING) << "VMess " << stage << ": " << e.what();
  }
  const Options _options;
  const vmess::Uuid _uuid;
  vmess::SessionKeys _keys;
  vmess::ChunkCodec _tx, _rx;
  vmess::ResponseHeaderReader _response;
  vmess::ChunkReader _chunks;
  vmess::WsFrameReader _frames;
  bool _peer_eof = false;
  // Only the upgrade callback and Close run concurrently with Connect.
  bthread::Mutex _mutex;
  bthread::ConditionVariable _changed;
  bool _closed = false;
  bool _upgrade_pending;
  int _upgrade_error = 0;
  size_t _upgrade_discard_bytes = 0;
  std::string _upgrade_head;
  brpc::HttpMessage _upgrade;
  std::string _ws_key, _ws_accept;
};
} // namespace

brpc::ProxyUpstreamFactory MakeUpstreamFactory(const Options &options) {
  if (options.server.host.empty() || options.server.port <= 0 ||
      options.server.port > 65535)
    throw vmess::Error("provide vmess_host and a valid vmess_port");
  if ((!options.ws_path.empty() &&
       (options.ws_path.front() != '/' ||
        options.ws_path.find_first_of(" \t\r\n") != std::string::npos)) ||
      options.ws_host.find_first_of("\r\n") != std::string::npos)
    throw vmess::Error("invalid WebSocket path or Host header");
  // The old UUID parser accepts partial hexadecimal pairs; validate before use.
  size_t digits = 0;
  for (unsigned char c : options.uuid) {
    if (c == '-')
      continue;
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F')))
      throw vmess::Error("invalid VMess UUID");
    ++digits;
  }
  if (digits != 32)
    throw vmess::Error("invalid VMess UUID");
  const auto uuid = vmess::Uuid::parse(options.uuid);
  return [options, uuid](const brpc::ProxyTunnel &tunnel) {
    return std::unique_ptr<brpc::ProxyUpstream>(
        new VmessUpstream(tunnel, options, uuid));
  };
}
} // namespace vmess_example
