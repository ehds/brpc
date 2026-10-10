#include "vmess/ws_frame.hpp"

namespace vmess {
namespace {

// Read a big-endian integer (caller must have ensured enough bytes)
std::uint64_t read_be(const std::uint8_t* p, std::size_t n) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) v = (v << 8) | p[i];
    return v;
}

bool is_control(std::uint8_t op) { return (op & 0x08) != 0; }

} // namespace

void WsFrameReader::feed(std::span<const std::uint8_t> data) {
    if (failed_ || data.empty()) return;
    // Drop the consumed prefix first to avoid repeated moves
    if (off_ == buf_.size()) {
        buf_.clear();
        off_ = 0;
    }
    buf_.insert(buf_.end(), data.begin(), data.end());
}

void WsFrameReader::compact() {
    if (off_ == 0) return;
    if (off_ == buf_.size()) {
        buf_.clear();
        off_ = 0;
    } else if (off_ >= 8192) {
        // Move data only once enough has accumulated, to amortize the O(n) cost
        buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(off_));
        off_ = 0;
    }
}

WsFrameReader::Event WsFrameReader::next(Bytes& payload, std::string& err) {
    // Note: do **not** clear payload here. On NeedMore the content the caller
    // fetched last time must be preserved, otherwise the common pattern
    // "get Data → call once more to confirm nothing is left" would lose data.
    // payload is only wholly overwritten via assign when a frame has been
    // successfully parsed.
    err.clear();
    if (failed_) {
        err = "frame reader is in failed state";
        return Event::Error;
    }

    // ---- Fixed 2-byte frame header ----
    if (available() < 2) return Event::NeedMore;
    const std::uint8_t b0 = buf_[off_];
    const std::uint8_t b1 = buf_[off_ + 1];

    const bool fin = (b0 & 0x80) != 0;
    const std::uint8_t rsv = static_cast<std::uint8_t>(b0 & 0x70);
    const std::uint8_t op = static_cast<std::uint8_t>(b0 & 0x0F);
    const bool masked = (b1 & 0x80) != 0;
    std::uint64_t len = b1 & 0x7F;
    std::size_t hdr = 2;

    // We negotiated no extensions (no Sec-WebSocket-Extensions sent), so RSV
    // must be 0
    if (rsv != 0) {
        failed_ = true;
        err = "RSV bits set without negotiated extension";
        return Event::Error;
    }
    // Server→client frames must not be masked (RFC 6455 §5.1)
    if (masked) {
        failed_ = true;
        err = "server frame must not be masked";
        return Event::Error;
    }
    // Reserved opcodes: 0x3-0x7, 0xB-0xF
    if ((op >= 0x3 && op <= 0x7) || op >= 0xB) {
        failed_ = true;
        err = "reserved opcode " + std::to_string(op);
        return Event::Error;
    }

    // ---- Extended length ----
    if (len == 126) {
        if (available() < 4) return Event::NeedMore;
        len = read_be(buf_.data() + off_ + 2, 2);
        hdr = 4;
    } else if (len == 127) {
        if (available() < 10) return Event::NeedMore;
        len = read_be(buf_.data() + off_ + 2, 8);
        hdr = 10;
        // RFC 6455 §5.2: the high bit of a 64-bit length must be 0
        if (len >> 63) {
            failed_ = true;
            err = "64-bit frame length high bit set";
            return Event::Error;
        }
    }

    if (len > kMaxFrameLen) {
        failed_ = true;
        err = "frame too large: " + std::to_string(len);
        return Event::Error;
    }

    // ---- Control frame constraints (RFC 6455 §5.5): length ≤ 125, no fragmentation ----
    if (is_control(op)) {
        if (len > 125) {
            failed_ = true;
            err = "control frame payload too long: " + std::to_string(len);
            return Event::Error;
        }
        if (!fin) {
            failed_ = true;
            err = "fragmented control frame";
            return Event::Error;
        }
    }

    // ---- Frame body ----
    if (available() < hdr + len) return Event::NeedMore;

    const std::uint8_t* body = buf_.data() + off_ + hdr;
    payload.assign(body, body + len);
    off_ += hdr + static_cast<std::size_t>(len);
    compact();

    switch (op) {
    case 0x8: return Event::Close;
    case 0x9: return Event::Ping;
    case 0xA: return Event::Pong;
    default: return Event::Data; // 0x0 continuation / 0x1 text / 0x2 binary
    }
}

} // namespace vmess
