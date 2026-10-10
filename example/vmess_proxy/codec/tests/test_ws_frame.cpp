// WsFrameReader tests: the core value of an incremental frame parser is that
// it **can be fed arbitrarily fragmented input**, so these tests heavily use
// byte-by-byte / segment-by-segment feeding, covering paths the old one-shot
// blocking read could never exercise.
#include <cstdio>
#include <string>

#include "vmess/ws_frame.hpp"

using namespace vmess;

static int failures = 0;

static void check(const char* name, bool ok, const std::string& detail = {}) {
    if (!ok) {
        std::printf("FAIL %s%s%s\n", name, detail.empty() ? "" : " → ", detail.c_str());
        ++failures;
    }
}

static Bytes b(std::string_view s) { return Bytes(s.begin(), s.end()); }

// Build a server-side frame (unmasked, FIN=1, most compact length encoding
// by default)
static Bytes frame(std::uint8_t opcode, const Bytes& payload, bool fin = true, bool masked = false,
                   std::uint8_t rsv = 0, int force_len_form = 0) {
    Bytes f;
    f.push_back(static_cast<std::uint8_t>((fin ? 0x80 : 0) | rsv | (opcode & 0x0F)));

    std::uint64_t n = payload.size();
    std::uint8_t lenbits;
    Bytes ext;
    if (force_len_form == 2 || (force_len_form == 0 && n >= 126 && n <= 65535)) {
        lenbits = 126;
        ext.push_back(static_cast<std::uint8_t>(n >> 8));
        ext.push_back(static_cast<std::uint8_t>(n));
    } else if (force_len_form == 8 || (force_len_form == 0 && n > 65535)) {
        lenbits = 127;
        for (int i = 7; i >= 0; --i) ext.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
    } else {
        lenbits = static_cast<std::uint8_t>(n);
    }
    f.push_back(static_cast<std::uint8_t>((masked ? 0x80 : 0) | lenbits));
    f.insert(f.end(), ext.begin(), ext.end());
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

// Feed once and drain all events
static std::vector<WsFrameReader::Event> drain(WsFrameReader& r, Bytes& last_payload) {
    std::vector<WsFrameReader::Event> evs;
    std::string err;
    for (int i = 0; i < 64; ++i) {
        auto ev = r.next(last_payload, err);
        if (ev == WsFrameReader::Event::NeedMore) break;
        evs.push_back(ev);
        if (ev == WsFrameReader::Event::Error) break;
    }
    return evs;
}

int main() {
    using E = WsFrameReader::Event;

    // ---- 1. Single frame fed all at once ----
    {
        WsFrameReader r;
        Bytes p;
        r.feed(frame(0x2, b("hello")));
        auto evs = drain(r, p);
        check("single frame -> Data", evs.size() == 1 && evs[0] == E::Data);
        check("single frame content", std::string(p.begin(), p.end()) == "hello");
    }

    // ---- 2. Byte-by-byte feeding (core: any fragmentation must work) ----
    {
        Bytes wire = frame(0x2, b("incremental-feed"));
        WsFrameReader r;
        Bytes p;
        std::string err;
        int needmore = 0;
        E last = E::NeedMore;
        for (std::size_t i = 0; i < wire.size(); ++i) {
            r.feed({wire.data() + i, 1});
            last = r.next(p, err);
            if (last == E::NeedMore) ++needmore;
        }
        check("byte-by-byte feed eventually yields Data", last == E::Data, err);
        check("byte-by-byte feed content intact",
              std::string(p.begin(), p.end()) == "incremental-feed");
        check("NeedMore was indeed reported midway", needmore > 0, std::to_string(needmore));
    }

    // ---- 3. Split into two segments at every possible cut point ----
    {
        Bytes wire = frame(0x2, b("split-at-every-offset"), true, false, 0, 2); // force the 126 form
        bool all_ok = true;
        for (std::size_t cut = 1; cut < wire.size(); ++cut) {
            WsFrameReader r;
            Bytes p;
            std::string err;
            r.feed({wire.data(), cut});
            if (r.next(p, err) != E::NeedMore) { all_ok = false; break; }
            r.feed({wire.data() + cut, wire.size() - cut});
            if (r.next(p, err) != E::Data || std::string(p.begin(), p.end()) !=
                                                "split-at-every-offset") {
                all_ok = false;
                break;
            }
        }
        check("correct at every cut point (incl. the 126 extended length split)", all_ok);
    }

    // ---- 4. Multiple frames fed at once ----
    {
        WsFrameReader r;
        Bytes p;
        Bytes wire = frame(0x2, b("one"));
        auto f2 = frame(0x2, b("two"));
        wire.insert(wire.end(), f2.begin(), f2.end());
        r.feed(wire);
        auto evs = drain(r, p);
        check("multiple frames -> two Data events",
              evs.size() == 2 && evs[0] == E::Data && evs[1] == E::Data);
        check("NeedMore after multiple frames", r.buffered() == 0);
    }

    // ---- 5. Control frames interleaved between data frames ----
    {
        WsFrameReader r;
        Bytes p;
        Bytes wire = frame(0x2, b("d1"));
        auto ping = frame(0x9, b("pq"));
        auto pong = frame(0xA, Bytes{});
        auto d2 = frame(0x2, b("d2"));
        wire.insert(wire.end(), ping.begin(), ping.end());
        wire.insert(wire.end(), pong.begin(), pong.end());
        wire.insert(wire.end(), d2.begin(), d2.end());
        r.feed(wire);
        auto evs = drain(r, p);
        check("Data/Ping/Pong/Data order correct",
              evs.size() == 4 && evs[0] == E::Data && evs[1] == E::Ping && evs[2] == E::Pong &&
                  evs[3] == E::Data);
    }

    // ---- 6. Close frame with status code ----
    {
        WsFrameReader r;
        Bytes p;
        Bytes payload = {0x03, 0xE8}; // 1000 = normal closure
        r.feed(frame(0x8, payload));
        auto evs = drain(r, p);
        check("Close event", evs.size() == 1 && evs[0] == E::Close);
        check("Close status code readable", p.size() == 2 && p[0] == 0x03 && p[1] == 0xE8);
    }

    // ---- 7. Long frame using the 127 form ----
    {
        Bytes big(70000);
        for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<std::uint8_t>(i & 0xFF);
        WsFrameReader r;
        Bytes p;
        r.feed(frame(0x2, big));
        auto evs = drain(r, p);
        check("127-form long frame -> Data", evs.size() == 1 && evs[0] == E::Data);
        check("127-form long frame content matches", p == big);
    }

    // ---- 8. Zero-length data frame ----
    {
        WsFrameReader r;
        Bytes p;
        r.feed(frame(0x2, Bytes{}));
        auto evs = drain(r, p);
        check("zero-length data frame -> Data with empty payload",
              evs.size() == 1 && evs[0] == E::Data && p.empty());
    }

    // ---- 9. Protocol errors ----
    {
        WsFrameReader r;
        Bytes p;
        std::string err;
        r.feed(frame(0x2, b("x"), true, /*masked=*/true));
        check("masked server frame -> Error", r.next(p, err) == E::Error && !err.empty());
        check("failed state after error", r.failed());
        r.feed(frame(0x2, b("y")));
        check("feed ignored in failed state, next still reports Error",
              r.next(p, err) == E::Error);
    }
    {
        WsFrameReader r;
        Bytes p;
        std::string err;
        r.feed(frame(0x2, b("x"), true, false, /*rsv=*/0x40));
        check("RSV bits set -> Error", r.next(p, err) == E::Error);
    }
    {
        WsFrameReader r;
        Bytes p;
        std::string err;
        r.feed(frame(0x3, b("x"))); // reserved opcode
        check("reserved opcode 0x3 -> Error", r.next(p, err) == E::Error);
    }
    {
        WsFrameReader r;
        Bytes p;
        std::string err;
        Bytes hdr = {0x89, 126, 0x00, 0xC8}; // Ping, but declares 200 bytes (>125)
        r.feed(hdr);
        check("control frame payload over 125 -> Error", r.next(p, err) == E::Error);
    }
    {
        WsFrameReader r;
        Bytes p;
        std::string err;
        r.feed(frame(0x9, b("pq"), /*fin=*/false)); // fragmented control frame
        check("fragmented control frame -> Error", r.next(p, err) == E::Error);
    }
    {
        WsFrameReader r;
        Bytes p;
        std::string err;
        // 64-bit length with the high bit set
        Bytes hdr = {0x82, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0};
        r.feed(hdr);
        check("64-bit length high bit set -> Error", r.next(p, err) == E::Error);
    }
    {
        WsFrameReader r;
        Bytes p;
        std::string err;
        // Declared length over kMaxFrameLen (no need to actually send that
        // many bytes; the length check comes first)
        std::uint64_t huge = WsFrameReader::kMaxFrameLen + 1;
        Bytes hdr = {0x82, 0xFF};
        for (int i = 7; i >= 0; --i) hdr.push_back(static_cast<std::uint8_t>(huge >> (8 * i)));
        r.feed(hdr);
        check("oversized frame -> Error", r.next(p, err) == E::Error);
    }

    // ---- 10. A long run of small frames fed continuously (verifies compact
    // loses no bytes) ----
    {
        WsFrameReader r;
        Bytes p;
        std::string err;
        Bytes expect;
        int got = 0;
        for (int i = 0; i < 2000; ++i) {
            Bytes payload(50, static_cast<std::uint8_t>(i & 0xFF));
            expect.insert(expect.end(), payload.begin(), payload.end());
            r.feed(frame(0x2, payload));
            // Drain after each fed frame, simulating a realistic pumping pace
            while (r.next(p, err) == E::Data) {
                got += static_cast<int>(p.size());
            }
        }
        check("2000 frames total byte count correct", got == 2000 * 50, std::to_string(got));
        check("buffer finally drained", r.buffered() == 0, std::to_string(r.buffered()));
    }

    // ---- 11. Fragmented message (FIN=0 + continuation frame) is currently
    // treated as independent data (known limitation) ----
    {
        WsFrameReader r;
        Bytes p;
        Bytes wire = frame(0x1, b("frag1"), /*fin=*/false);
        auto cont = frame(0x0, b("frag2"), true);
        wire.insert(wire.end(), cont.begin(), cont.end());
        r.feed(wire);
        auto evs = drain(r, p);
        check("fragments returned as two Data events (not reassembled, known limitation)",
              evs.size() == 2);
    }

    if (failures == 0) std::puts("test_ws_frame: all passed");
    return failures == 0 ? 0 : 1;
}
