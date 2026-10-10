#pragma once
#include <cstdint>
#include <span>
#include <string>

#include "common.hpp"

namespace vmess {

// Incremental WebSocket frame parser (RFC 6455, client side).
//
// A pure state machine that does no I/O: the caller feed()s raw bytes, then
// repeatedly calls next() to obtain events until NeedMore is returned. This
// design lets the same frame logic be driven either by a **blocking
// transport** (feed on read) or by **edge-triggered callbacks** (feed
// whenever data arrives) — a prerequisite for migrating the data plane onto
// brpc::Socket.
//
// Not thread-safe: one parser instance should be used by a single thread only
// (corresponding to the read direction of one connection).
class WsFrameReader {
public:
    enum class Event {
        NeedMore, // insufficient buffered data, feed more bytes
        Data,     // data frame (binary 0x2 / text 0x1 / continuation 0x0, all treated as data)
        Ping,     // 0x9, caller should reply with Pong
        Pong,     // 0xA, usually ignored
        Close,    // 0x8, first 2 payload bytes are the status code (if present)
        Error,    // protocol error; err carries the reason, parser enters terminal state
    };

    // Append raw bytes. Ignored once in the terminal state.
    void feed(std::span<const std::uint8_t> data);

    // Take out the next event. On Data/Ping/Pong/Close, payload is wholly
    // overwritten with the frame content. On NeedMore or Error **payload is
    // left unchanged** — so the pattern "after getting data, call once more to
    // confirm nothing is left" does not lose the previous result.
    // On Error, err carries the reason.
    Event next(Bytes& payload, std::string& err);

    bool failed() const { return failed_; }
    std::size_t buffered() const { return buf_.size() - off_; }

    // Per-frame upper bound, prevents a peer from exhausting memory with huge frames
    static constexpr std::uint64_t kMaxFrameLen = 1u << 20;

private:
    std::size_t available() const { return buf_.size() - off_; }
    // Drop the consumed prefix to keep the buffer from growing unboundedly;
    // only moves data once enough has accumulated
    void compact();

    Bytes buf_;
    std::size_t off_ = 0;
    bool failed_ = false;
};

} // namespace vmess
