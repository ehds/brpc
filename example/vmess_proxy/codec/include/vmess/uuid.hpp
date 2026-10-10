#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string_view>

#include "common.hpp"

namespace vmess {

// VMess user ID (16-byte UUID) and its derived keys
struct Uuid {
    std::array<std::uint8_t, 16> bytes{};

    // Accepts "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (case-insensitive,
    // hyphens optional)
    static Uuid parse(std::string_view s);

    // cmdKey = MD5(uuid_bytes ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21")
    // Root key of the VMess auth header (see Xray common/protocol/id.go NewID)
    Bytes cmd_key() const;

    std::span<const std::uint8_t> as_span() const {
        return {bytes.data(), bytes.size()};
    }
};

} // namespace vmess
