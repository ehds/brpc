#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace vmess {

using Bytes = std::vector<std::uint8_t>;

// Library-wide error type. Uses exceptions for now in this demo; can be
// migrated smoothly to std::error_code later.
struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// IO timeout (SO_RCVTIMEO/SO_SNDTIMEO expired). Kept distinct from ordinary
// errors: for long-lived connections an idle timeout is a normal event, and
// callers usually just tear down the connection instead of treating it as a
// failure.
struct TimeoutError : Error {
    using Error::Error;
};

// The peer closed the connection cleanly while we were in the middle of
// "must read exactly N bytes". Distinguishes "the server rejected us" (EOF
// during the handshake) from "decryption/verification failed", so that
// accurate diagnostics can be reported.
struct EndOfStreamError : Error {
    using Error::Error;
};

// Hex encoding/decoding (for tests and debugging)
std::string to_hex(const std::uint8_t* data, std::size_t len);
inline std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }
Bytes from_hex(std::string_view hex);

} // namespace vmess
