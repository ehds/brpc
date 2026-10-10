#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string>

#include "common.hpp"
#include "uuid.hpp"

namespace vmess {

// Request parameters (client-side fields of Xray protocol.RequestHeader)
struct RequestOptions {
    std::uint8_t version = 0x01;
    std::uint8_t command = 0x01;  // 0x01 TCP / 0x02 UDP / 0x03 Mux
    std::uint8_t security = 0x03; // 0x03 AES-128-GCM (proto SecurityType_AES128_GCM)
    std::uint8_t option = 0x01;   // 0x01 chunk stream (PlainChunkSizeParser)
    std::string address;          // domain / IPv4 / IPv6 string
    std::uint16_t port = 0;
};

// Key material of one connection (determined when encoding the request
// header; shared by the chunk layer and the response header)
struct SessionKeys {
    std::array<std::uint8_t, 16> request_body_iv{};
    std::array<std::uint8_t, 16> request_body_key{};
    std::array<std::uint8_t, 16> response_body_iv{};  // SHA256(request_body_iv)[:16]
    std::array<std::uint8_t, 16> response_body_key{}; // SHA256(request_body_key)[:16]
    std::uint8_t response_header = 0;                 // byte the server must echo back
    std::uint8_t padding_len = 0;                     // 0~15, written into the high 4 bits of the security byte

    // Randomly generate the full set of material (response derived keys included)
    static SessionKeys generate();
};

// ---- Request header ----

// Plaintext payload (protocol §4: version/IV/Key/echo byte/option/command/
// port+address/padding/FNV)
Bytes encode_request_payload(const RequestOptions& opt, const SessionKeys& keys,
                             std::span<const std::uint8_t> padding);

// AuthID（16B）= AES-128-ECB(KDF16(cmdKey,"AES Auth ID Encryption")) of
//              ts(8B BE) ‖ rand(4B) ‖ crc32(first 12B)(4B BE)
Bytes make_auth_id(std::span<const std::uint8_t> cmd_key, std::int64_t unix_ts,
                   std::span<const std::uint8_t> rand4);

// Full AEAD encapsulation (§3):
//   authID ‖ GCM(len, aad=authID) ‖ nonce(8) ‖ GCM(payload, aad=authID)
Bytes seal_request_header(std::span<const std::uint8_t> cmd_key, std::span<const std::uint8_t> payload,
                          std::int64_t unix_ts, std::span<const std::uint8_t> rand4,
                          std::span<const std::uint8_t> nonce8);

// Convenience combo: randomly generate key material (written into keys) and
// return a request header ready to send
Bytes build_request_header(const Uuid& uuid, const RequestOptions& opt, SessionKeys& keys);

// Same as above, but with an explicit authID timestamp (for diagnosing
// server clock skew)
Bytes build_request_header(const Uuid& uuid, const RequestOptions& opt, SessionKeys& keys,
                           std::int64_t unix_ts);

// Reverse operation: unpack (for interop verification/debugging; wire = authID‖…)
Bytes open_request_header(std::span<const std::uint8_t> cmd_key,
                          std::span<const std::uint8_t> wire);

// ---- Response header ----

struct ResponseHeader {
    std::uint8_t option = 0;
    std::uint8_t command_id = 0; // 0 = no attached command
};

// Decrypt the 18B length section → plaintext header length (§6)
std::uint16_t decrypt_response_header_length(const SessionKeys& keys,
                                             std::span<const std::uint8_t> ct18);

// Decrypt the header payload and verify the echo byte (throws Error on mismatch)
ResponseHeader decrypt_response_header(const SessionKeys& keys,
                                       std::span<const std::uint8_t> ct_with_tag,
                                       std::uint8_t expected_echo);

// Incremental response header parser.
//
// The wire format is two-part: the payload length is unknown until the 18-byte
// length section has been consumed:
//   [GCM(2B length) + tag = 18B][GCM(payload) + tag = len+16 B]
//   payload = [echo byte][option][cmdID][cmdLen][cmdData…]
// A blocking read_exact naturally expresses this ordering, but under
// event-driven I/O it must be explicitly modeled as a state machine.
//
// After parsing completes, the buffer **may still hold bytes belonging to the
// chunk stream** (servers often send the response header together with the
// first batch of data). They must be taken out via take_remaining() and fed
// to ChunkReader, otherwise those bytes would be dropped.
class ResponseHeaderReader {
public:
    enum class Event {
        NeedMore, // insufficient buffered data
        Ready,    // parsing complete and echo verified; out holds the header
        Error,    // decryption failure / echo mismatch / implausible length; err carries the reason
    };

    ResponseHeaderReader() = default;
    void bind(const SessionKeys& keys, std::uint8_t expected_echo) {
        keys_ = &keys;
        expected_echo_ = expected_echo;
    }

    void feed(std::span<const std::uint8_t> data);
    Event next(ResponseHeader& out, std::string& err);

    bool done() const { return done_; }
    std::size_t buffered() const { return buf_.size() - off_; }

    // Take away unconsumed leftover bytes (belonging to the chunk stream) and
    // clear the buffer. Only meaningful after done().
    Bytes take_remaining();

private:
    std::size_t available() const { return buf_.size() - off_; }

    const SessionKeys* keys_ = nullptr;
    std::uint8_t expected_echo_ = 0;
    Bytes buf_;
    std::size_t off_ = 0;
    std::uint16_t payload_len_ = 0;
    bool have_len_ = false;
    bool done_ = false;
    bool failed_ = false;
    ResponseHeader parsed_;
};

} // namespace vmess
