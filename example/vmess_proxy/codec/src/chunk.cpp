#include "vmess/chunk.hpp"

#include "vmess/crypto.hpp"

namespace vmess {

ChunkCodec::ChunkCodec(const std::uint8_t* key16, const std::uint8_t* iv16)
    : key_(key16, key16 + 16), nonce_base_(iv16, iv16 + 16) {}

std::array<std::uint8_t, 12> ChunkCodec::next_nonce() {
    // GenerateChunkNonce: BE16 counter written into the first two bytes of
    // the 16B base IV, take the first 12B
    std::array<std::uint8_t, 12> nonce{};
    std::copy(nonce_base_.begin(), nonce_base_.begin() + 12, nonce.begin());
    nonce[0] = static_cast<std::uint8_t>(counter_ >> 8);
    nonce[1] = static_cast<std::uint8_t>(counter_);
    ++counter_; // wraps naturally like Go's uint16
    return nonce;
}

Bytes ChunkCodec::seal(std::span<const std::uint8_t> payload) {
    auto nonce = next_nonce();
    Bytes sealed = aes128_gcm_seal(key_, nonce, payload);

    Bytes wire;
    wire.reserve(2 + sealed.size());
    auto size = static_cast<std::uint16_t>(sealed.size()); // payload + 16 tag
    wire.push_back(static_cast<std::uint8_t>(size >> 8));
    wire.push_back(static_cast<std::uint8_t>(size));
    wire.insert(wire.end(), sealed.begin(), sealed.end());
    return wire;
}

Bytes ChunkCodec::open(std::span<const std::uint8_t> sealed_with_tag) {
    auto nonce = next_nonce();
    return aes128_gcm_open(key_, nonce, sealed_with_tag);
}

Bytes seal_stream(ChunkCodec& codec, std::span<const std::uint8_t> data,
                  std::size_t max_payload) {
    Bytes out;
    out.reserve(data.size() + (data.size() / max_payload + 1) * 18);
    std::size_t off = 0;
    while (off < data.size()) {
        std::size_t n = std::min(max_payload, data.size() - off);
        Bytes chunk = codec.seal({data.data() + off, n});
        out.insert(out.end(), chunk.begin(), chunk.end());
        off += n;
    }
    return out;
}

// ---- ChunkReader ----

void ChunkReader::feed(std::span<const std::uint8_t> data) {
    if (failed_ || eof_ || data.empty()) return;
    if (off_ == buf_.size()) {
        buf_.clear();
        off_ = 0;
    }
    buf_.insert(buf_.end(), data.begin(), data.end());
}

void ChunkReader::compact() {
    if (off_ == 0) return;
    if (off_ == buf_.size()) {
        buf_.clear();
        off_ = 0;
    } else if (off_ >= 8192) {
        buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(off_));
        off_ = 0;
    }
}

ChunkReader::Event ChunkReader::next(Bytes& out, std::string& err) {
    // Do not clear out: on NeedMore/Eof/Error the caller's previous result
    // must be preserved
    err.clear();
    if (failed_) {
        err = "chunk reader is in failed state";
        return Event::Error;
    }
    if (eof_) return Event::Eof;
    if (!codec_) {
        failed_ = true;
        err = "chunk reader not bound to a codec";
        return Event::Error;
    }

    // ---- 2-byte plaintext length header ----
    if (available() < 2) return Event::NeedMore;
    const auto size = static_cast<std::uint16_t>((buf_[off_] << 8) | buf_[off_ + 1]);

    // size < 16 cannot hold the GCM tag, must be corruption
    if (size < 16) {
        failed_ = true;
        err = "corrupt chunk size " + std::to_string(size);
        return Event::Error;
    }

    // Terminating chunk: consume only the 2-byte length header; the 16-byte
    // tag is **neither read nor decrypted**, and the codec counter is not
    // incremented — matching Xray's read side, which returns io.EOF before
    // calling auth.Open (readInternal in common/crypto/auth.go). One extra
    // increment would skew the nonces of all subsequent chunks.
    if (size == 16) {
        off_ += 2;
        eof_ = true;
        compact();
        return Event::Eof;
    }

    if (available() < 2u + size) return Event::NeedMore;

    try {
        out = codec_->open({buf_.data() + off_ + 2, size});
    } catch (const Error& e) {
        failed_ = true;
        err = e.what();
        return Event::Error;
    }
    off_ += 2u + size;
    compact();
    return Event::Data;
}

} // namespace vmess
