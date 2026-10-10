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

// Local test peer, not a production VMess server. Socket I/O here is test-only.
#include <algorithm>
#include <array>
#include <cerrno>
#include <iostream>
#include <span>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include "vmess/chunk.hpp"
#include "vmess/crypto.hpp"
#include "vmess/header.hpp"
#include "vmess/kdf.hpp"
#include "vmess/uuid.hpp"
#include "../ws_codec.h"

namespace {
using vmess::Bytes;
const char* kUuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
Bytes Read(int fd, size_t n) {
    Bytes bytes(n);
    size_t pos = 0;
    while (pos < n) {
        const ssize_t got = recv(fd, bytes.data() + pos, n - pos, 0);
        if (got <= 0) throw vmess::Error("read failed");
        pos += got;
    }
    return bytes;
}
void Write(int fd, std::span<const uint8_t> bytes, bool fragment = false) {
    size_t pos = 0;
    while (pos < bytes.size()) {
        const size_t count = fragment ? (pos < 64 ? 1 : 211) : bytes.size() - pos;
        const ssize_t n = send(fd, bytes.data() + pos,
                               std::min(count, bytes.size() - pos), 0);
        if (n <= 0) throw vmess::Error("write failed");
        pos += n;
        // Force an incomplete read, including InputMessenger's empty-buffer
        // retry, instead of relying on the OS to preserve send() boundaries.
        if (fragment && pos == 1) usleep(20000);
    }
}
Bytes ServerFrame(std::span<const uint8_t> bytes, uint8_t opcode = 2) {
    Bytes frame{uint8_t(0x80 | opcode)};
    if (bytes.size() < 126) frame.push_back(bytes.size());
    else if (bytes.size() < 65536) {
        frame.push_back(126);
        frame.push_back(bytes.size() >> 8);
        frame.push_back(bytes.size());
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; --i) frame.push_back(uint64_t(bytes.size()) >> (8 * i));
    }
    frame.insert(frame.end(), bytes.begin(), bytes.end());
    return frame;
}
struct Stream {
    int fd;
    bool ws;
    Bytes pending;
    size_t offset = 0;
    bool pong = false;
    Bytes ReadExact(size_t count) {
        if (!ws) return Read(fd, count);
        Bytes result;
        while (result.size() < count) {
            if (offset == pending.size()) {
                const Bytes head = Read(fd, 2);
                if (!(head[1] & 0x80)) throw vmess::Error("missing client mask");
                uint64_t length = head[1] & 127;
                if (length >= 126) {
                    const Bytes extended = Read(fd, length == 126 ? 2 : 8);
                    length = 0;
                    for (uint8_t c : extended) length = (length << 8) | c;
                }
                if (length > 1024 * 1024) throw vmess::Error("oversized client frame");
                const Bytes mask = Read(fd, 4);
                pending = Read(fd, length);
                for (size_t i = 0; i < pending.size(); ++i) pending[i] ^= mask[i % 4];
                offset = 0;
                if ((head[0] & 15) == 10) {
                    pong = pending == Bytes{'p','i','n','g'};
                    pending.clear();
                    continue;
                }
                if ((head[0] & 15) != 2) throw vmess::Error("unexpected client opcode");
            }
            const size_t n = std::min(count - result.size(), pending.size() - offset);
            result.insert(result.end(), pending.begin() + offset, pending.begin() + offset + n);
            offset += n;
        }
        return result;
    }
    void Send(std::span<const uint8_t> bytes) {
        if (ws) Write(fd, ServerFrame(bytes), true);
        else Write(fd, bytes, true);
    }
};
Bytes Response(const vmess::SessionKeys& keys, bool bad_echo) {
    Bytes length{0, 4};
    auto key = vmess::kdf16(keys.response_body_key, {vmess::as_bytes("AEAD Resp Header Len Key")});
    auto iv = vmess::kdf(keys.response_body_iv, {vmess::as_bytes("AEAD Resp Header Len IV")});
    iv.resize(12);
    auto result = vmess::aes128_gcm_seal(key, iv, length);
    key = vmess::kdf16(keys.response_body_key, {vmess::as_bytes("AEAD Resp Header Key")});
    iv = vmess::kdf(keys.response_body_iv, {vmess::as_bytes("AEAD Resp Header IV")});
    iv.resize(12);
    Bytes header{uint8_t(keys.response_header ^ (bad_echo ? 1 : 0)), 0, 0, 0};
    const auto sealed = vmess::aes128_gcm_seal(key, iv, header);
    result.insert(result.end(), sealed.begin(), sealed.end());
    return result;
}
void Serve(int fd, const std::string& transport, const std::string& mode, size_t expected) {
    Stream stream{fd, transport == "ws", {}, 0, false};
    if (stream.ws) {
        std::string request;
        while (!request.ends_with("\r\n\r\n")) {
            request.push_back(Read(fd, 1)[0]);
            if (request.size() > 16384) throw vmess::Error("oversized upgrade");
        }
        if (request.find("GET /images HTTP/1.1\r\nHost: vmess.test\r\n") != 0)
            throw vmess::Error("wrong WS path/Host");
        if (mode == "stall") { sleep(30); return; }
        if (mode == "reject") {
            const std::string reject = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
            Write(fd, vmess::as_bytes(reject));
            return;
        }
        const auto start = request.find("Sec-WebSocket-Key: ") + 19;
        const auto end = request.find("\r\n", start);
        std::string accept = vmess_example::WebSocketAccept(request.substr(start, end - start));
        if (mode == "bad_accept") accept = "invalid";
        const std::string upgrade = "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\n"
            "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
        Bytes response(upgrade.begin(), upgrade.end());
        // Coalesce control bytes with HTTP upgrade; they must not be discarded.
        const Bytes ping = ServerFrame(Bytes{'p','i','n','g'}, 9);
        response.insert(response.end(), ping.begin(), ping.end());
        Write(fd, response, true);
        if (mode == "bad_accept") return;
    }
    const auto uuid = vmess::Uuid::parse(kUuid);
    Bytes wire = stream.ReadExact(42);
    const std::span<const uint8_t> auth(wire.data(), 16), nonce(wire.data() + 34, 8);
    const auto cmd = uuid.cmd_key();
    auto key = vmess::kdf16(cmd, {vmess::as_bytes("VMess Header AEAD Key_Length"), auth, nonce});
    auto iv = vmess::kdf(cmd, {vmess::as_bytes("VMess Header AEAD Nonce_Length"), auth, nonce});
    iv.resize(12);
    const auto length = vmess::aes128_gcm_open(key, iv, {wire.data() + 16, 18}, auth);
    const size_t n = (length[0] << 8) | length[1];
    const auto tail = stream.ReadExact(n + 16);
    wire.insert(wire.end(), tail.begin(), tail.end());
    const auto header = vmess::open_request_header(cmd, wire);
    const size_t port = (header.at(38) << 8) | header.at(39);
    const size_t address_length = header.at(41);
    const std::string target(header.begin() + 42, header.begin() + 42 + address_length);
    if (header.at(40) != 2 || target != "target.invalid" || port != 443)
        throw vmess::Error("VMess lost the original destination");
    vmess::SessionKeys keys;
    std::copy_n(header.begin() + 1, 16, keys.request_body_iv.begin());
    std::copy_n(header.begin() + 17, 16, keys.request_body_key.begin());
    const auto rk = vmess::sha256(keys.request_body_key);
    const auto ri = vmess::sha256(keys.request_body_iv);
    std::copy_n(rk.begin(), 16, keys.response_body_key.begin());
    std::copy_n(ri.begin(), 16, keys.response_body_iv.begin());
    keys.response_header = header.at(33);
    vmess::ChunkCodec rx(keys.request_body_key.data(), keys.request_body_iv.data());
    Bytes plaintext;
    while (plaintext.size() < expected) {
        const auto size = stream.ReadExact(2);
        const auto payload = rx.open(stream.ReadExact((size[0] << 8) | size[1]));
        plaintext.insert(plaintext.end(), payload.begin(), payload.end());
    }
    if (stream.ws && !stream.pong) {
        // The Pong can follow the final client data frame in the serial queue.
        const auto head = Read(fd, 2);
        if (head != Bytes{0x8A, 0x84}) throw vmess::Error("missing masked Pong");
        const auto mask = Read(fd, 4);
        auto body = Read(fd, 4);
        for (size_t i = 0; i < 4; ++i) body[i] ^= mask[i];
        if (body != Bytes{'p','i','n','g'}) throw vmess::Error("wrong Pong payload");
    }
    vmess::ChunkCodec tx(keys.response_body_key.data(), keys.response_body_iv.data());
    Bytes response = Response(keys, mode == "bad_echo");
    Bytes body = vmess::seal_stream(tx, plaintext);
    if (mode == "bad_tag") body.back() ^= 1;
    response.insert(response.end(), body.begin(), body.end());
    if (mode != "native_eof" && mode != "ws_close") {
        const auto eof = tx.seal({});
        response.insert(response.end(), eof.begin(), eof.end());
    }
    stream.Send(response);
    if (mode == "ws_close") Write(fd, ServerFrame({}, 8));
    std::cout << "target=" << target << ':' << port << std::endl;
}
}  // namespace
int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc != 4) return 2;
    const int listener = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ||
        listen(listener, 1)) return 2;
    socklen_t size = sizeof(address);
    getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size);
    std::cout << ntohs(address.sin_port) << std::endl;
    const int fd = accept(listener, nullptr, nullptr);
    int status = 0;
    try { Serve(fd, argv[1], argv[2], std::stoul(argv[3])); }
    catch (const std::exception& e) { std::cerr << e.what() << std::endl; status = 1; }
    if (fd >= 0) close(fd);
    close(listener);
    return status;
}
