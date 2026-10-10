// Chunk codec tests: roundtrip, terminating chunk, nonce counter, splitting,
// tamper resistance
#include <cstdio>
#include <cstring>

#include "vmess/chunk.hpp"
#include "vmess/common.hpp"
#include "vmess/crypto.hpp"

using namespace vmess;

static int failures = 0;

static void check(const char* name, bool ok) {
    if (!ok) {
        std::printf("FAIL %s\n", name);
        ++failures;
    }
}

// Simulate the read side: decode chunk by chunk (including length headers)
// from the wire buffer, concatenating the data; terminates on 0010
static bool read_stream(ChunkCodec& codec, std::span<const std::uint8_t> wire, Bytes& out,
                        bool expect_terminal) {
    std::size_t off = 0;
    bool terminal = false;
    while (off < wire.size()) {
        if (off + 2 > wire.size()) return false;
        std::uint16_t size = static_cast<std::uint16_t>((wire[off] << 8) | wire[off + 1]);
        off += 2;
        if (size == 16) { // terminating chunk (the 16B tag after it is not
                          // consumed, matching the Go read side)
            terminal = true;
            break;
        }
        if (off + size > wire.size()) return false;
        try {
            Bytes payload = codec.open({wire.data() + off, size});
            out.insert(out.end(), payload.begin(), payload.end());
        } catch (const Error&) {
            return false;
        }
        off += size;
    }
    return terminal == expect_terminal;
}

int main() {
    std::array<std::uint8_t, 16> key{};
    std::array<std::uint8_t, 16> iv{};
    for (std::size_t i = 0; i < 16; ++i) {
        key[i] = static_cast<std::uint8_t>(i);
        iv[i] = static_cast<std::uint8_t>(0xA0 + i);
    }

    // ---- Golden vector: bit-for-bit identical to the Xray
    // AuthenticationWriter ----
    // Generated via: go run . chunk (key=demoKey, iv=00..0f,
    // payload="Hello VMess Chunk")
    {
        auto gk = from_hex("66e41ad47fa745fbfd1e97325e93dbf4");
        std::array<std::uint8_t, 16> giv{};
        for (std::size_t i = 0; i < 16; ++i) giv[i] = static_cast<std::uint8_t>(i);
        ChunkCodec w(gk.data(), giv.data());
        Bytes payload = {'H', 'e', 'l', 'l', 'o', ' ', 'V', 'M', 'e', 's', 's',
                         ' ', 'C', 'h', 'u', 'n', 'k'};
        Bytes wire = w.seal(payload);
        Bytes golden = from_hex(
            "0021c5c382e4a45c96995a4ebdea4e0df0e7adfec96988775bb4cadb15bdca52997624");
        check("golden vector vs xray writer", wire == golden);
    }

    // ---- Single chunk roundtrip ----
    {
        ChunkCodec w(key.data(), iv.data());
        ChunkCodec r(key.data(), iv.data());
        Bytes data = {1, 2, 3, 4, 5};
        Bytes wire = w.seal(data);
        check("single chunk wire size", wire.size() == 2 + 5 + 16);
        Bytes out;
        check("single chunk roundtrip", read_stream(r, wire, out, false) && out == data);
        check("counter synced", w.counter() == 1 && r.counter() == 1);
    }

    // ---- Multiple chunks + terminating chunk ----
    {
        ChunkCodec w(key.data(), iv.data());
        ChunkCodec r(key.data(), iv.data());
        Bytes wire;
        Bytes data(1000);
        secure_random(data);
        wire = seal_stream(w, data, 300); // 4 pieces
        Bytes term = w.seal({});           // terminating chunk
        check("terminal is 00 10 + tag", term.size() == 18 && term[0] == 0x00 && term[1] == 0x10);
        wire.insert(wire.end(), term.begin(), term.end());

        Bytes out;
        check("multi chunk roundtrip", read_stream(r, wire, out, true) && out == data);
        check("chunk count", w.counter() == 5);
    }

    // ---- Independent counters: each direction increments from 0 on its own ----
    {
        ChunkCodec tx(key.data(), iv.data());
        ChunkCodec rx(key.data(), iv.data());
        (void)tx.seal(Bytes(10, 1));
        (void)tx.seal(Bytes(10, 2));
        // rx's counter stays 0 while unused
        check("rx counter untouched", rx.counter() == 0);
    }

    // ---- Tamper detection ----
    {
        ChunkCodec w(key.data(), iv.data());
        Bytes wire = w.seal(Bytes(32, 0x5A));
        wire[5] ^= 0xFF; // tamper with the ciphertext
        ChunkCodec r(key.data(), iv.data());
        Bytes out;
        check("tampered chunk rejected", !read_stream(r, wire, out, false));
    }

    // ---- Large data splitting roundtrip ----
    {
        ChunkCodec w(key.data(), iv.data());
        ChunkCodec r(key.data(), iv.data());
        Bytes data(20000);
        secure_random(data);
        Bytes wire = seal_stream(w, data);
        Bytes out;
        check("20k stream roundtrip", read_stream(r, wire, out, false) && out == data);
        check("20k chunk count", w.counter() == 3); // 8174+8174+3652
    }

    // ---- Empty input: seal_stream produces no chunks ----
    {
        ChunkCodec w(key.data(), iv.data());
        check("empty stream no chunks", seal_stream(w, {}).empty() && w.counter() == 0);
    }

    if (failures == 0) std::puts("test_chunk: all passed");
    return failures == 0 ? 0 : 1;
}
