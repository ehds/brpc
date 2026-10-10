// ChunkReader tests: the incremental chunk parser.
// The core value is that it can be **fed arbitrarily fragmented input** — the
// old blocking read_exact implementation could not be tested this way.
// Two invariants are guarded above all:
//   1. The terminating chunk consumes only the 2-byte length header, and the
//      codec counter is **not incremented**
//   2. NeedMore/Eof/Error leave the out parameter intact
#include <cstdio>
#include <string>

#include "vmess/chunk.hpp"
#include "vmess/common.hpp"

using namespace vmess;

static int failures = 0;

static void check(const char* name, bool ok, const std::string& detail = {}) {
    if (!ok) {
        std::printf("FAIL %s%s%s\n", name, detail.empty() ? "" : " → ", detail.c_str());
        ++failures;
    }
}

namespace {

std::array<std::uint8_t, 16> make_key() {
    std::array<std::uint8_t, 16> k{};
    for (std::size_t i = 0; i < 16; ++i) k[i] = static_cast<std::uint8_t>(i * 7 + 3);
    return k;
}

std::array<std::uint8_t, 16> make_iv() {
    std::array<std::uint8_t, 16> v{};
    for (std::size_t i = 0; i < 16; ++i) v[i] = static_cast<std::uint8_t>(0xA0 + i);
    return v;
}

// Feed byte by byte and collect all plaintext
bool feed_bytewise(ChunkReader& r, const Bytes& wire, Bytes& plain, std::string& err) {
    using E = ChunkReader::Event;
    Bytes out;
    for (std::size_t i = 0; i < wire.size(); ++i) {
        r.feed({wire.data() + i, 1});
        while (true) {
            auto ev = r.next(out, err);
            if (ev == E::Data) {
                plain.insert(plain.end(), out.begin(), out.end());
                continue;
            }
            if (ev == E::Error) return false;
            break; // NeedMore or Eof
        }
    }
    return true;
}

} // namespace

int main() {
    using E = ChunkReader::Event;
    auto key = make_key();
    auto iv = make_iv();

    // ---- 1. Single chunk fed all at once ----
    {
        ChunkCodec w(key.data(), iv.data());
        Bytes abc = {'a', 'b', 'c'};
        Bytes wire = w.seal(abc);

        ChunkCodec rx(key.data(), iv.data());
        ChunkReader r;
        r.bind(rx);
        r.feed(wire);
        Bytes out;
        std::string err;
        check("single chunk -> Data", r.next(out, err) == E::Data, err);
        check("single chunk content", out == abc);
        check("next after single chunk -> NeedMore", r.next(out, err) == E::NeedMore);
        // Critical: NeedMore must not clear out
        check("NeedMore preserves previous result", out == abc);
    }

    // ---- 2. Byte-by-byte feeding ----
    {
        ChunkCodec w(key.data(), iv.data());
        Bytes wire;
        Bytes expect;
        for (int i = 0; i < 5; ++i) {
            Bytes payload(37, static_cast<std::uint8_t>('A' + i));
            auto c = w.seal(payload);
            wire.insert(wire.end(), c.begin(), c.end());
            expect.insert(expect.end(), payload.begin(), payload.end());
        }

        ChunkCodec rx(key.data(), iv.data());
        ChunkReader r;
        r.bind(rx);
        Bytes plain, err_out;
        std::string err;
        check("byte-by-byte feed without error", feed_bytewise(r, wire, plain, err));
        check("byte-by-byte feed content matches", plain == expect,
              "got " + std::to_string(plain.size()) + " want " + std::to_string(expect.size()));
    }

    // ---- 3. Split into two segments at every cut point ----
    {
        ChunkCodec w(key.data(), iv.data());
        Bytes wire = w.seal(Bytes(100, 0x5A));
        bool all_ok = true;
        for (std::size_t cut = 1; cut < wire.size(); ++cut) {
            ChunkCodec rx(key.data(), iv.data());
            ChunkReader r;
            r.bind(rx);
            Bytes out;
            std::string err;
            r.feed({wire.data(), cut});
            if (r.next(out, err) != E::NeedMore) { all_ok = false; break; }
            r.feed({wire.data() + cut, wire.size() - cut});
            if (r.next(out, err) != E::Data || out.size() != 100) { all_ok = false; break; }
        }
        check("correct at every cut point (incl. the 2-byte length header split in half)",
              all_ok);
    }

    // ---- 4. Multiple chunks fed at once ----
    {
        ChunkCodec w(key.data(), iv.data());
        Bytes wire;
        auto c1 = w.seal(Bytes(10, 1));
        auto c2 = w.seal(Bytes(20, 2));
        auto c3 = w.seal(Bytes{}); // terminating chunk
        wire.insert(wire.end(), c1.begin(), c1.end());
        wire.insert(wire.end(), c2.begin(), c2.end());
        wire.insert(wire.end(), c3.begin(), c3.end());

        ChunkCodec rx(key.data(), iv.data());
        ChunkReader r;
        r.bind(rx);
        r.feed(wire);
        Bytes out;
        std::string err;
        check("1st Data", r.next(out, err) == E::Data && out.size() == 10);
        check("2nd Data", r.next(out, err) == E::Data && out.size() == 20);
        check("3rd is Eof", r.next(out, err) == E::Eof);
        check("eof() is true", r.eof());
        check("next after Eof is still Eof", r.next(out, err) == E::Eof);
        // The terminating chunk consumes only the 2-byte header, so the rx
        // counter should stop at 2 (two data chunks)
        check("terminating chunk does not increment counter", rx.counter() == 2,
              std::to_string(rx.counter()));
    }

    // ---- 5. A 2-byte terminating header alone must yield Eof immediately,
    // without waiting for the tag ----
    {
        ChunkCodec rx(key.data(), iv.data());
        ChunkReader r;
        r.bind(rx);
        Bytes head = {0x00, 0x10};
        r.feed(head);
        Bytes out;
        std::string err;
        check("2-byte terminating header alone -> Eof (no wait for tag)",
              r.next(out, err) == E::Eof, err);
        check("counter is 0 since open was never called", rx.counter() == 0);
    }

    // ---- 6. Tamper detection ----
    {
        ChunkCodec w(key.data(), iv.data());
        Bytes wire = w.seal(Bytes(32, 0x11));
        wire[5] ^= 0xFF;
        ChunkCodec rx(key.data(), iv.data());
        ChunkReader r;
        r.bind(rx);
        r.feed(wire);
        Bytes out;
        std::string err;
        check("tampered -> Error", r.next(out, err) == E::Error && !err.empty());
        check("failed state after error", r.failed());
        r.feed(wire);
        check("keeps reporting Error in failed state", r.next(out, err) == E::Error);
    }

    // ---- 7. size < 16 (cannot hold the tag) ----
    {
        ChunkCodec rx(key.data(), iv.data());
        ChunkReader r;
        r.bind(rx);
        Bytes bad = {0x00, 0x0F, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        r.feed(bad);
        Bytes out;
        std::string err;
        check("size<16 -> Error", r.next(out, err) == E::Error);
    }

    // ---- 8. Codec not bound ----
    {
        ChunkReader r;
        Bytes out;
        std::string err;
        Bytes hdr = {0x00, 0x20};
        r.feed(hdr);
        check("not bound -> Error", r.next(out, err) == E::Error && !err.empty());
    }

    // ---- 9. Large data volume (verifies compact loses no bytes) ----
    {
        ChunkCodec w(key.data(), iv.data());
        Bytes wire, expect;
        for (int i = 0; i < 2000; ++i) {
            Bytes payload(600, static_cast<std::uint8_t>(i & 0xFF));
            auto c = w.seal(payload);
            wire.insert(wire.end(), c.begin(), c.end());
            expect.insert(expect.end(), payload.begin(), payload.end());
        }
        ChunkCodec rx(key.data(), iv.data());
        ChunkReader r;
        r.bind(rx);
        Bytes plain;
        std::string err;
        // Feed 4096 bytes at a time, simulating a realistic read pace
        std::size_t off = 0;
        Bytes out;
        while (off < wire.size()) {
            std::size_t n = std::min<std::size_t>(4096, wire.size() - off);
            r.feed({wire.data() + off, n});
            off += n;
            while (r.next(out, err) == E::Data) plain.insert(plain.end(), out.begin(), out.end());
        }
        check("2000 chunks (1.2MB) content matches", plain == expect,
              "got " + std::to_string(plain.size()));
        check("counter matches chunk count", rx.counter() == 2000, std::to_string(rx.counter()));
    }

    // ---- 10. Feed is ignored after Eof ----
    {
        ChunkCodec rx(key.data(), iv.data());
        ChunkReader r;
        r.bind(rx);
        Bytes term = {0x00, 0x10};
        r.feed(term);
        Bytes out;
        std::string err;
        (void)r.next(out, err);
        std::size_t before = r.buffered();
        Bytes extra = {1, 2, 3, 4};
        r.feed(extra);
        check("feed ignored after Eof", r.buffered() == before);
    }

    if (failures == 0) std::puts("test_chunk_reader: all passed");
    return failures == 0 ? 0 : 1;
}
