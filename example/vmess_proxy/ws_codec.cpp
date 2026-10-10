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

// Pure helpers extracted from vmess_client/src/websocket.cpp; no socket I/O.
#include "ws_codec.h"
#include <array>
#include <openssl/evp.h>
#include "vmess/crypto.hpp"

namespace vmess_example {
namespace {
std::string Base64(std::span<const uint8_t> bytes) {
    std::string output(4 * ((bytes.size() + 2) / 3) + 1, '\0');
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&output[0]),
                                  bytes.data(), bytes.size());
    if (n < 0) throw vmess::Error("Base64 encoding failed");
    output.resize(n);
    return output;
}
}  // namespace
std::string NewWebSocketKey() {
    std::array<uint8_t, 16> nonce;
    vmess::secure_random(nonce);
    return Base64(nonce);
}
std::string WebSocketAccept(const std::string& key) {
    const std::string material = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::array<uint8_t, EVP_MAX_MD_SIZE> digest;
    unsigned int size = 0;
    if (EVP_Digest(material.data(), material.size(), digest.data(), &size,
                   EVP_sha1(), nullptr) != 1) throw vmess::Error("SHA1 failed");
    return Base64({digest.data(), size});
}
bool HasHeaderToken(const std::string& value, const std::string& token) {
    size_t start = 0;
    while (start < value.size()) {
        const size_t end = value.find(',', start);
        std::string part = value.substr(start, end == std::string::npos
                                               ? std::string::npos : end - start);
        const auto first = part.find_first_not_of(" \t");
        const auto last = part.find_last_not_of(" \t");
        if (first != std::string::npos) part = part.substr(first, last - first + 1);
        for (char& c : part) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (part == token) return true;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return false;
}
vmess::Bytes EncodeClientFrame(uint8_t opcode, std::span<const uint8_t> payload) {
    // Same mask/length encoding as the original demo's send_frame().
    std::array<uint8_t, 14> header{};
    size_t length = 0;
    header[length++] = 0x80 | opcode;
    std::array<uint8_t, 4> mask;
    vmess::secure_random(mask);
    const size_t n = payload.size();
    if (n < 126) {
        header[length++] = 0x80 | n;
    } else if (n < 65536) {
        header[length++] = 0x80 | 126;
        header[length++] = n >> 8;
        header[length++] = n;
    } else {
        header[length++] = 0x80 | 127;
        for (int i = 7; i >= 0; --i) header[length++] = uint64_t(n) >> (8 * i);
    }
    for (uint8_t byte : mask) header[length++] = byte;
    vmess::Bytes frame;
    frame.reserve(length + n);
    frame.insert(frame.end(), header.begin(), header.begin() + length);
    frame.insert(frame.end(), payload.begin(), payload.end());
    for (size_t i = 0; i < n; ++i) frame[length + i] ^= mask[i % mask.size()];
    return frame;
}
}  // namespace vmess_example
