#include "vmess/header.hpp"

#include <arpa/inet.h>

#include <chrono>

#include "vmess/crypto.hpp"
#include "vmess/kdf.hpp"

namespace vmess {
namespace {

// KDF salt constants from Xray proxy/vmess/aead/consts.go (verbatim)
constexpr std::string_view kSaltAuthIdEncKey = "AES Auth ID Encryption";
constexpr std::string_view kSaltHeaderLenKey = "VMess Header AEAD Key_Length";
constexpr std::string_view kSaltHeaderLenNonce = "VMess Header AEAD Nonce_Length";
constexpr std::string_view kSaltHeaderKey = "VMess Header AEAD Key";
constexpr std::string_view kSaltHeaderNonce = "VMess Header AEAD Nonce";
constexpr std::string_view kSaltRespLenKey = "AEAD Resp Header Len Key";
constexpr std::string_view kSaltRespLenNonce = "AEAD Resp Header Len IV";
constexpr std::string_view kSaltRespPayloadKey = "AEAD Resp Header Key";
constexpr std::string_view kSaltRespPayloadNonce = "AEAD Resp Header IV";

void append_u16(Bytes& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}

void append_u64(Bytes& b, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
}

void append_u32(Bytes& b, std::uint32_t v) {
    for (int i = 3; i >= 0; --i) {
        b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
}

std::uint16_t read_u16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

// Port (2B BE) + address type (1B) + address (domain carries a 1B length
// prefix) — note VMess puts the port first
void append_address(Bytes& out, const std::string& host, std::uint16_t port) {
    append_u16(out, port);

    std::array<std::uint8_t, 16> v6{};
    std::array<std::uint8_t, 4> v4{};
    if (inet_pton(AF_INET, host.c_str(), v4.data()) == 1) {
        out.push_back(0x01); // IPv4
        out.insert(out.end(), v4.begin(), v4.end());
    } else if (inet_pton(AF_INET6, host.c_str(), v6.data()) == 1) {
        out.push_back(0x03); // IPv6
        out.insert(out.end(), v6.begin(), v6.end());
    } else {
        if (host.empty() || host.size() > 255) throw Error("invalid domain length");
        out.push_back(0x02); // domain
        out.push_back(static_cast<std::uint8_t>(host.size()));
        out.insert(out.end(), host.begin(), host.end());
    }
}

} // namespace

SessionKeys SessionKeys::generate() {
    SessionKeys k;
    secure_random(k.request_body_key);
    secure_random(k.request_body_iv);
    std::array<std::uint8_t, 1> echo{};
    secure_random(echo);
    k.response_header = echo[0];
    k.padding_len = echo[0] & 0x0F; // reuse the random byte for 0~15 (dice.Roll(16))

    auto resp_key = sha256(k.request_body_key);
    auto resp_iv = sha256(k.request_body_iv);
    std::copy(resp_key.begin(), resp_key.begin() + 16, k.response_body_key.begin());
    std::copy(resp_iv.begin(), resp_iv.begin() + 16, k.response_body_iv.begin());
    return k;
}

Bytes encode_request_payload(const RequestOptions& opt, const SessionKeys& keys,
                             std::span<const std::uint8_t> padding) {
    if (padding.size() != keys.padding_len) throw Error("padding length mismatch");

    Bytes b;
    b.reserve(41 + opt.address.size() + padding.size());
    b.push_back(opt.version);
    b.insert(b.end(), keys.request_body_iv.begin(), keys.request_body_iv.end());
    b.insert(b.end(), keys.request_body_key.begin(), keys.request_body_key.end());
    b.push_back(keys.response_header);
    b.push_back(opt.option);
    b.push_back(static_cast<std::uint8_t>((keys.padding_len << 4) | (opt.security & 0x0F)));
    b.push_back(0x00); // reserved
    b.push_back(opt.command);
    if (opt.command != 0x03) { // Mux carries no address
        append_address(b, opt.address, opt.port);
    }
    b.insert(b.end(), padding.begin(), padding.end());
    append_u32(b, fnv1a32(b));
    return b;
}

Bytes make_auth_id(std::span<const std::uint8_t> cmd_key, std::int64_t unix_ts,
                   std::span<const std::uint8_t> rand4) {
    if (rand4.size() != 4) throw Error("auth id rand must be 4 bytes");

    Bytes pt;
    pt.reserve(16);
    append_u64(pt, static_cast<std::uint64_t>(unix_ts));
    pt.insert(pt.end(), rand4.begin(), rand4.end());
    append_u32(pt, crc32_ieee(pt));

    Bytes enc_key = kdf16(cmd_key, {as_bytes(kSaltAuthIdEncKey)});
    return aes128_ecb_encrypt_block(enc_key, pt);
}

Bytes seal_request_header(std::span<const std::uint8_t> cmd_key, std::span<const std::uint8_t> payload,
                          std::int64_t unix_ts, std::span<const std::uint8_t> rand4,
                          std::span<const std::uint8_t> nonce8) {
    if (nonce8.size() != 8) throw Error("connection nonce must be 8 bytes");

    Bytes auth_id = make_auth_id(cmd_key, unix_ts, rand4);
    auto auth_span = std::span<const std::uint8_t>(auth_id);
    auto nonce_span = std::span<const std::uint8_t>(nonce8);

    // Length section: BE16(len(payload)), aad = authID
    Bytes len_pt;
    append_u16(len_pt, static_cast<std::uint16_t>(payload.size()));
    Bytes len_key = kdf16(cmd_key, {as_bytes(kSaltHeaderLenKey), auth_span, nonce_span});
    Bytes len_nonce = kdf(cmd_key, {as_bytes(kSaltHeaderLenNonce), auth_span, nonce_span});
    len_nonce.resize(12);
    Bytes enc_len = aes128_gcm_seal(len_key, len_nonce, len_pt, auth_span);

    // Payload section, aad = authID
    Bytes pay_key = kdf16(cmd_key, {as_bytes(kSaltHeaderKey), auth_span, nonce_span});
    Bytes pay_nonce = kdf(cmd_key, {as_bytes(kSaltHeaderNonce), auth_span, nonce_span});
    pay_nonce.resize(12);
    Bytes enc_payload = aes128_gcm_seal(pay_key, pay_nonce, payload, auth_span);

    // wire: authID ‖ encLen ‖ nonce ‖ encPayload
    Bytes out;
    out.reserve(auth_id.size() + enc_len.size() + nonce8.size() + enc_payload.size());
    out.insert(out.end(), auth_id.begin(), auth_id.end());
    out.insert(out.end(), enc_len.begin(), enc_len.end());
    out.insert(out.end(), nonce8.begin(), nonce8.end());
    out.insert(out.end(), enc_payload.begin(), enc_payload.end());
    return out;
}

Bytes build_request_header(const Uuid& uuid, const RequestOptions& opt, SessionKeys& keys) {
    auto ts = std::chrono::duration_cast<std::chrono::seconds>(
                  std::chrono::system_clock::now().time_since_epoch())
                  .count();
    return build_request_header(uuid, opt, keys, ts);
}

Bytes build_request_header(const Uuid& uuid, const RequestOptions& opt, SessionKeys& keys,
                           std::int64_t unix_ts) {
    keys = SessionKeys::generate();
    Bytes padding(keys.padding_len);
    secure_random(padding);
    Bytes payload = encode_request_payload(opt, keys, padding);

    Bytes rand4(4);
    secure_random(rand4);
    Bytes nonce8(8);
    secure_random(nonce8);

    return seal_request_header(uuid.cmd_key(), payload, unix_ts, rand4, nonce8);
}

Bytes open_request_header(std::span<const std::uint8_t> cmd_key,
                          std::span<const std::uint8_t> wire) {
    // authID ‖ encLen(18) ‖ nonce(8) ‖ encPayload(len+16)
    if (wire.size() < 16 + 18 + 8 + 16) throw Error("header too short");
    auto auth_span = wire.first(16);
    auto enc_len = wire.subspan(16, 18);
    auto nonce_span = wire.subspan(16 + 18, 8);
    auto rest = wire.subspan(16 + 18 + 8);

    Bytes len_key = kdf16(cmd_key, {as_bytes(kSaltHeaderLenKey), auth_span, nonce_span});
    Bytes len_nonce = kdf(cmd_key, {as_bytes(kSaltHeaderLenNonce), auth_span, nonce_span});
    len_nonce.resize(12);
    Bytes len_pt = aes128_gcm_open(len_key, len_nonce, enc_len, auth_span);
    if (len_pt.size() != 2) throw Error("bad header length field");
    std::uint16_t payload_len = read_u16(len_pt.data());
    if (rest.size() != static_cast<std::size_t>(payload_len) + 16) {
        throw Error("header payload size mismatch");
    }

    Bytes pay_key = kdf16(cmd_key, {as_bytes(kSaltHeaderKey), auth_span, nonce_span});
    Bytes pay_nonce = kdf(cmd_key, {as_bytes(kSaltHeaderNonce), auth_span, nonce_span});
    pay_nonce.resize(12);
    return aes128_gcm_open(pay_key, pay_nonce, rest, auth_span);
}

std::uint16_t decrypt_response_header_length(const SessionKeys& keys,
                                             std::span<const std::uint8_t> ct18) {
    Bytes key = kdf16(keys.response_body_key, {as_bytes(kSaltRespLenKey)});
    Bytes nonce = kdf(keys.response_body_iv, {as_bytes(kSaltRespLenNonce)});
    nonce.resize(12);
    Bytes pt = aes128_gcm_open(key, nonce, ct18);
    if (pt.size() != 2) throw Error("bad response header length");
    return read_u16(pt.data());
}

ResponseHeader decrypt_response_header(const SessionKeys& keys,
                                       std::span<const std::uint8_t> ct_with_tag,
                                       std::uint8_t expected_echo) {
    Bytes key = kdf16(keys.response_body_key, {as_bytes(kSaltRespPayloadKey)});
    Bytes nonce = kdf(keys.response_body_iv, {as_bytes(kSaltRespPayloadNonce)});
    nonce.resize(12);
    Bytes payload = aes128_gcm_open(key, nonce, ct_with_tag);
    if (payload.size() < 4) throw Error("response header payload too short");
    if (payload[0] != expected_echo) {
        throw Error("response header echo mismatch: server did not accept our header");
    }
    ResponseHeader h;
    h.option = payload[1];
    h.command_id = payload[2];
    return h;
}

// ---- ResponseHeaderReader ----

void ResponseHeaderReader::feed(std::span<const std::uint8_t> data) {
    if (failed_ || done_ || data.empty()) return;
    if (off_ == buf_.size()) {
        buf_.clear();
        off_ = 0;
    }
    buf_.insert(buf_.end(), data.begin(), data.end());
}

ResponseHeaderReader::Event ResponseHeaderReader::next(ResponseHeader& out, std::string& err) {
    err.clear();
    if (failed_) {
        err = "response header reader is in failed state";
        return Event::Error;
    }
    if (done_) { // idempotent: repeated calls return the same parsed result
        out = parsed_;
        return Event::Ready;
    }
    if (!keys_) {
        failed_ = true;
        err = "response header reader not bound to session keys";
        return Event::Error;
    }

    // First section: 18 bytes (2B length ciphertext + 16B tag)
    if (!have_len_) {
        if (available() < 18) return Event::NeedMore;
        try {
            payload_len_ = decrypt_response_header_length(*keys_, {buf_.data() + off_, 18});
        } catch (const Error& e) {
            failed_ = true;
            err = e.what();
            return Event::Error;
        }
        if (payload_len_ < 4 || payload_len_ > 1024) {
            failed_ = true;
            err = "unreasonable response header length " + std::to_string(payload_len_);
            return Event::Error;
        }
        off_ += 18;
        have_len_ = true;
    }

    // Second section: payload_len_ + 16B tag
    const std::size_t need = static_cast<std::size_t>(payload_len_) + 16;
    if (available() < need) return Event::NeedMore;
    try {
        // Echo byte mismatch (including UUID rejected by the server) is
        // thrown here
        parsed_ = decrypt_response_header(*keys_, {buf_.data() + off_, need}, expected_echo_);
    } catch (const Error& e) {
        failed_ = true;
        err = e.what();
        return Event::Error;
    }
    off_ += need;
    done_ = true;
    out = parsed_;
    return Event::Ready;
}

Bytes ResponseHeaderReader::take_remaining() {
    Bytes rest(buf_.begin() + static_cast<std::ptrdiff_t>(off_), buf_.end());
    buf_.clear();
    off_ = 0;
    return rest;
}

} // namespace vmess
