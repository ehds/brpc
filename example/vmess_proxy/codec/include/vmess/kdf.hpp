#pragma once
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string_view>

#include "common.hpp"

namespace vmess {

// Convenience conversion from string_view / literals to a byte span
inline std::span<const std::uint8_t> as_bytes(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

// VMess AEAD KDF (Xray's chained HMAC construction, not standard HKDF):
//   h0 = HMAC-SHA256(key="VMess AEAD KDF", data=key)
//   hᵢ = HMAC-SHA256(key=pathᵢ, data=hᵢ₋₁)
// Path elements are "raw bytes used as the string key" — the salt constants
// are ASCII while authID/nonce are binary.
Bytes kdf(std::span<const std::uint8_t> key,
          std::initializer_list<std::span<const std::uint8_t>> path);

// First 16 bytes of the KDF output
Bytes kdf16(std::span<const std::uint8_t> key,
            std::initializer_list<std::span<const std::uint8_t>> path);

} // namespace vmess
