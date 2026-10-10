#pragma once
#include <array>
#include <cstdint>
#include <span>

#include "common.hpp"

namespace vmess {

// VMess chunked AEAD transport (RequestOptionChunkStream=0x01, plaintext length):
//   wire chunk = [2B size BE][AES-128-GCM(size−16 bytes payload) + 16B tag]
//   terminating chunk: size = 0x0010 (empty payload); the read side treats
//   0010 as end of stream
// Nonce: based on the 16B base IV; before each Seal/Open the uint16 counter
// is written big-endian into the first two bytes and the first 12 bytes are
// taken. The counter starts at 0 and increments per chunk, independently per
// direction.
class ChunkCodec {
public:
    ChunkCodec() = default;
    ChunkCodec(const std::uint8_t* key16, const std::uint8_t* iv16);

    // Seal one complete wire chunk (including the 2B length header),
    // counter +1. seal({}) is the terminating chunk (00 10 + 16B tag).
    Bytes seal(std::span<const std::uint8_t> payload);

    // Open sealed+tag data whose length header has already been stripped,
    // counter +1; throws Error on tag failure
    Bytes open(std::span<const std::uint8_t> sealed_with_tag);

    std::uint16_t counter() const { return counter_; }

private:
    std::array<std::uint8_t, 12> next_nonce();

    Bytes key_;
    Bytes nonce_base_; // 16B
    std::uint16_t counter_ = 0;
};

// Seal data of arbitrary length, split into chunks of max_payload (used on
// the write side; no terminating chunk)
Bytes seal_stream(ChunkCodec& codec, std::span<const std::uint8_t> data,
                  std::size_t max_payload = 8174);

// Incremental chunk parser (read direction).
//
// Same design motivation as WsFrameReader: a pure state machine that does no
// I/O, so it can be driven either by a blocking transport (feed on read) or
// by edge-triggered callbacks (feed whenever data arrives) — a prerequisite
// for migrating the data plane onto brpc::Socket. GCM requires the
// **complete** chunk before decryption, so "buffer, then emit one chunk at a
// time once enough" must be modeled explicitly; it cannot be papered over
// with blocking read_exact.
//
// Not thread-safe: one instance should be used by a single thread only
// (corresponding to the read direction of one connection).
class ChunkReader {
public:
    enum class Event {
        NeedMore, // less than one complete chunk buffered
        Data,     // out holds one chunk's plaintext
        Eof,      // terminating chunk received (size == 16)
        Error,    // illegal size or GCM verification failure; err carries the reason, enters terminal state
    };

    ChunkReader() = default;

    // Bind the codec used for decryption (the counter lives in the codec, so
    // it must be independent of the sending side). Calling next() before
    // binding yields Error.
    void bind(ChunkCodec& codec) { codec_ = &codec; }

    void feed(std::span<const std::uint8_t> data);

    // Take out the next complete chunk. On NeedMore/Eof/Error **out is left
    // unchanged** (same contract as WsFrameReader, so that "call once more to
    // confirm nothing is left" does not lose the previous result).
    Event next(Bytes& out, std::string& err);

    bool eof() const { return eof_; }
    bool failed() const { return failed_; }
    std::size_t buffered() const { return buf_.size() - off_; }

private:
    std::size_t available() const { return buf_.size() - off_; }
    void compact();

    ChunkCodec* codec_ = nullptr;
    Bytes buf_;
    std::size_t off_ = 0;
    bool eof_ = false;
    bool failed_ = false;
};

} // namespace vmess
