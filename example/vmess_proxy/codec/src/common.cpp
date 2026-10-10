#include "vmess/common.hpp"

#include <cstdio>

namespace vmess {

std::string to_hex(const std::uint8_t* data, std::size_t len) {
    static const char* kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 0x0F]);
    }
    return out;
}

Bytes from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) throw Error("from_hex: odd-length input");
    Bytes out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        unsigned byte = 0;
        if (std::sscanf(hex.data() + i * 2, "%2x", &byte) != 1) {
            throw Error("from_hex: invalid hex digit");
        }
        out[i] = static_cast<std::uint8_t>(byte);
    }
    return out;
}

} // namespace vmess
