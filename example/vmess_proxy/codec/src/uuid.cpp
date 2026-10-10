#include "vmess/uuid.hpp"

#include <cstdio>
#include <format>

#include "vmess/crypto.hpp"
#include "vmess/kdf.hpp"

namespace vmess {

Uuid Uuid::parse(std::string_view s) {
    // After stripping hyphens there must be exactly 32 hex characters
    std::string compact;
    compact.reserve(32);
    for (char c : s) {
        if (c == '-') continue;
        compact.push_back(c);
    }
    if (compact.size() != 32) {
        throw Error("invalid UUID length: " + std::string(s));
    }

    Uuid id;
    for (std::size_t i = 0; i < 16; ++i) {
        unsigned byte = 0;
        if (std::sscanf(compact.data() + i * 2, "%2x", &byte) != 1) {
            throw Error(std::format("invalid UUID hex digit {} at {}", compact.data()[i], i));
        }
        id.bytes[i] = static_cast<std::uint8_t>(byte);
    }
    return id;
}

Bytes Uuid::cmd_key() const {
    constexpr std::string_view kCmdKeySalt = "c48619fe-8f02-49e0-b9e9-edf763e17e21";
    Bytes data(bytes.begin(), bytes.end());
    auto salt = as_bytes(kCmdKeySalt);
    data.insert(data.end(), salt.begin(), salt.end());
    return md5(data);
}

} // namespace vmess
