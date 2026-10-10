// Header codec tests: roundtrip + interoperability with the Xray Go
// implementation.
//
// Interop vector provenance (tools/gen_vectors, calling the Xray-core
// authoritative implementation):
//   demoKey = KDF16("Demo Key for Auth ID Test", "Demo Path for Auth ID Test")
//           = 66e41ad47fa745fbfd1e97325e93dbf4
//   go_seal = SealVMessAEADHeader(demoKey, "Test Header") one-shot output
#include <cstdio>
#include <cstring>

#include "vmess/crypto.hpp"
#include "vmess/header.hpp"
#include "vmess/kdf.hpp"

using namespace vmess;

static int failures = 0;

static void check(const char* name, bool ok, const std::string& detail = {}) {
    if (!ok) {
        std::printf("FAIL %s%s%s\n", name, detail.empty() ? "" : " → ", detail.c_str());
        ++failures;
    }
}

int main(int argc, char** argv) {
    // Interop helper mode: print "Test Header" sealed with demoKey (for
    // verification via `go run . open`)
    if (argc > 1 && std::strcmp(argv[1], "--print-sealed") == 0) {
        auto cmd_key = from_hex("66e41ad47fa745fbfd1e97325e93dbf4");
        Bytes payload = {'T', 'e', 's', 't', ' ', 'H', 'e', 'a', 'd', 'e', 'r'};
        Bytes rand4 = {1, 2, 3, 4};
        Bytes nonce8(8, 9);
        auto sealed = seal_request_header(cmd_key, payload, 1700000000, rand4, nonce8);
        std::printf("%s\n", to_hex(sealed).c_str());
        return 0;
    }

    // Interop helper mode: build a full request header from a real
    // UUID/target and print hex (for verification via
    // `go run . decode <uuid> <hex>` using the Xray server-side decoder)
    if (argc > 4 && std::strcmp(argv[1], "--print-real-header") == 0) {
        Uuid uuid = Uuid::parse(argv[2]);
        RequestOptions opt;
        opt.address = argv[3];
        opt.port = static_cast<std::uint16_t>(std::stoi(argv[4]));
        SessionKeys keys;
        std::printf("%s\n", to_hex(build_request_header(uuid, opt, keys)).c_str());
        return 0;
    }

    // Interop helper mode: print the AuthID of fixed inputs (for verification
    // via `go run . authid`)
    if (argc > 1 && std::strcmp(argv[1], "--print-authid") == 0) {
        auto cmd_key = from_hex("66e41ad47fa745fbfd1e97325e93dbf4");
        Bytes rand4 = {1, 2, 3, 4};
        std::printf("%s\n", to_hex(make_auth_id(cmd_key, 1700000000, rand4)).c_str());
        return 0;
    }

    const auto demo_key = from_hex("66e41ad47fa745fbfd1e97325e93dbf4");

    // ---- Interop 1: C++ can decode "Test Header" from Go
    // SealVMessAEADHeader output ----
    {
        auto wire = from_hex(
            "52c6e0f59330a57e30c8dfcfe640c64f595b49ba7d3c456fe24d4818c09010f9c5cffc2b16ef6f0b2e393b"
            "92e218eb98ee4e85e4cb745a17460477de3456eb155b210266e4");
        auto payload = open_request_header(demo_key, wire);
        std::string got(payload.begin(), payload.end());
        check("interop go-seal -> cpp-open", got == "Test Header");
    }

    // ---- Interop 2: C++ seal (fixed randomness) → verified via
    // `go run . open` (manual step during development) ----
    // Roundtrip self-check:
    {
        auto payload = from_hex("deadbeef01");
        Bytes rand4 = {1, 2, 3, 4};
        Bytes nonce8(8, 9);
        auto wire = seal_request_header(demo_key, payload, 1700000000, rand4, nonce8);
        check("cpp seal->open roundtrip", open_request_header(demo_key, wire) == payload);
    }

    // ---- AuthID: determinism on fixed inputs + structural self-check ----
    {
        Bytes rand4 = {1, 2, 3, 4};
        auto auth = make_auth_id(demo_key, 1700000000, rand4);
        check("auth id deterministic", auth == make_auth_id(demo_key, 1700000000, rand4));
        check("auth id size", auth.size() == 16);
        // A change in ts should change the authID
        check("auth id ts-sensitive", auth != make_auth_id(demo_key, 1700000001, rand4));
        // `go run . authid <hex>` should print ts=1700000000 crc_ok=true
        // (manual step during development)
    }

    // ---- Request header payload encoding (field-by-field assertions on the §4 layout) ----
    {
        SessionKeys keys{};
        std::fill(keys.request_body_iv.begin(), keys.request_body_iv.end(), 0xAB);
        std::fill(keys.request_body_key.begin(), keys.request_body_key.end(), 0xCD);
        keys.response_header = 0x42;
        keys.padding_len = 3;

        RequestOptions opt;
        opt.address = "example.com";
        opt.port = 80;

        Bytes padding = {0x01, 0x02, 0x03};
        auto payload = encode_request_payload(opt, keys, padding);

        check("payload version", payload[0] == 0x01);
        check("payload iv", std::equal(keys.request_body_iv.begin(), keys.request_body_iv.end(),
                                       payload.begin() + 1));
        check("payload key", std::equal(keys.request_body_key.begin(), keys.request_body_key.end(),
                                        payload.begin() + 17));
        check("payload echo", payload[33] == 0x42);
        check("payload option", payload[34] == 0x01);
        check("payload security", payload[35] == ((3 << 4) | 3));
        check("payload reserved", payload[36] == 0);
        check("payload command", payload[37] == 0x01);
        check("payload port", payload[38] == 0 && payload[39] == 80);
        check("payload addr type", payload[40] == 0x02);
        check("payload domain len", payload[41] == 11);
        check("payload padding", payload[53] == 0x01 && payload[55] == 0x03);
        // FNV check: recomputing over the first 56 bytes (with the trailing 4
        // truncated) should equal the last 4 bytes
        check("payload fnv",
              fnv1a32({payload.data(), payload.size() - 4}) ==
                  (static_cast<std::uint32_t>(payload[56]) << 24 |
                   static_cast<std::uint32_t>(payload[57]) << 16 |
                   static_cast<std::uint32_t>(payload[58]) << 8 |
                   static_cast<std::uint32_t>(payload[59])));
        check("payload total len", payload.size() == 60);
    }

    // ---- IPv4 / IPv6 address encoding ----
    {
        SessionKeys keys{}; // padding_len = 0
        RequestOptions opt;
        opt.address = "1.2.3.4";
        opt.port = 443;
        auto p4 = encode_request_payload(opt, keys, {});
        check("ipv4 type", p4[38] == 0x01 && p4[39] == 0xBB && p4[40] == 0x01);
        check("ipv4 bytes", p4[41] == 1 && p4[42] == 2 && p4[43] == 3 && p4[44] == 4);

        opt.address = "::1";
        auto p6 = encode_request_payload(opt, keys, {});
        check("ipv6 type", p6[40] == 0x03);
        check("ipv6 bytes", p6[41 + 15] == 1);
    }

    // ---- build_request_header full-flow roundtrip ----
    {
        Uuid uuid = Uuid::parse("b831381d-6324-4d53-ad4f-8cda48b30811");
        RequestOptions opt;
        opt.address = "example.com";
        opt.port = 80;
        SessionKeys keys;
        auto wire = build_request_header(uuid, opt, keys);
        auto payload = open_request_header(uuid.cmd_key(), wire);
        // Re-open and check key fields
        check("full roundtrip iv",
              std::equal(keys.request_body_iv.begin(), keys.request_body_iv.end(),
                         payload.begin() + 1));
        check("full roundtrip echo", payload[33] == keys.response_header);
        check("full roundtrip domain", payload[41] == 11);
        // Response derived key consistency
        auto rk = sha256(keys.request_body_key);
        check("resp key derived",
              std::equal(rk.begin(), rk.begin() + 16, keys.response_body_key.begin()));
    }

    // ---- Response header decryption: hand-crafted server response ----
    {
        SessionKeys keys{};
        std::fill(keys.response_body_key.begin(), keys.response_body_key.end(), 0x11);
        std::fill(keys.response_body_iv.begin(), keys.response_body_iv.end(), 0x22);
        keys.response_header = 0x42;

        // Length section
        Bytes len_pt = {0x00, 0x04};
        auto len_key = kdf16(keys.response_body_key, {as_bytes("AEAD Resp Header Len Key")});
        auto len_nonce = kdf(keys.response_body_iv, {as_bytes("AEAD Resp Header Len IV")});
        len_nonce.resize(12);
        auto enc_len = aes128_gcm_seal(len_key, len_nonce, len_pt);
        check("resp len decrypt", decrypt_response_header_length(keys, enc_len) == 4);

        // Payload section: echo + option + cmdID=0 + len=0
        Bytes resp_pt = {0x42, 0x00, 0x00, 0x00};
        auto pay_key = kdf16(keys.response_body_key, {as_bytes("AEAD Resp Header Key")});
        auto pay_nonce = kdf(keys.response_body_iv, {as_bytes("AEAD Resp Header IV")});
        pay_nonce.resize(12);
        auto enc_pay = aes128_gcm_seal(pay_key, pay_nonce, resp_pt);
        auto hdr = decrypt_response_header(keys, enc_pay, 0x42);
        check("resp header parsed", hdr.option == 0 && hdr.command_id == 0);

        // Echo mismatch must be reported as an error
        bool threw = false;
        try { (void)decrypt_response_header(keys, enc_pay, 0x43); } catch (const Error&) {
            threw = true;
        }
        check("resp echo mismatch rejected", threw);
    }

    // ---- ResponseHeaderReader: incremental parsing ----
    // Build the response header wire format a server would send:
    // 18B length section + (len+16)B payload section
    auto build_resp_wire = [](const SessionKeys& keys, std::uint16_t declared_len,
                              const Bytes& payload, bool corrupt_len) {
        auto len_key = kdf16(keys.response_body_key, {as_bytes("AEAD Resp Header Len Key")});
        auto len_nonce = kdf(keys.response_body_iv, {as_bytes("AEAD Resp Header Len IV")});
        len_nonce.resize(12);
        Bytes len_pt = {static_cast<std::uint8_t>(declared_len >> 8),
                        static_cast<std::uint8_t>(declared_len)};
        Bytes enc_len = aes128_gcm_seal(len_key, len_nonce, len_pt);
        if (corrupt_len) enc_len[3] ^= 0xFF;

        auto pay_key = kdf16(keys.response_body_key, {as_bytes("AEAD Resp Header Key")});
        auto pay_nonce = kdf(keys.response_body_iv, {as_bytes("AEAD Resp Header IV")});
        pay_nonce.resize(12);
        Bytes enc_pay = aes128_gcm_seal(pay_key, pay_nonce, payload);

        Bytes wire = enc_len;
        wire.insert(wire.end(), enc_pay.begin(), enc_pay.end());
        return wire;
    };

    SessionKeys rk{};
    std::fill(rk.response_body_key.begin(), rk.response_body_key.end(), 0x11);
    std::fill(rk.response_body_iv.begin(), rk.response_body_iv.end(), 0x22);
    rk.response_header = 0x42;
    const Bytes resp_payload = {0x42, 0x00, 0x00, 0x00}; // echo + option + cmdID + cmdLen

    {
        using E = ResponseHeaderReader::Event;
        Bytes wire = build_resp_wire(rk, 4, resp_payload, false);
        check("resp wire size = 18 + 20", wire.size() == 38);

        // Feed all at once
        {
            ResponseHeaderReader rd;
            rd.bind(rk, 0x42);
            rd.feed(wire);
            ResponseHeader h;
            std::string err;
            check("resp reader -> Ready", rd.next(h, err) == E::Ready, err);
            check("resp reader option/cmdID", h.option == 0 && h.command_id == 0);
            check("resp reader done()", rd.done());
            // Idempotent
            ResponseHeader h2;
            check("resp reader Ready idempotent", rd.next(h2, err) == E::Ready && h2.option == 0);
            check("resp reader no leftover", rd.take_remaining().empty());
        }

        // Feed byte by byte
        {
            ResponseHeaderReader rd;
            rd.bind(rk, 0x42);
            ResponseHeader h;
            std::string err;
            E last = E::NeedMore;
            int needmore = 0;
            for (std::size_t i = 0; i < wire.size(); ++i) {
                rd.feed({wire.data() + i, 1});
                last = rd.next(h, err);
                if (last == E::NeedMore) ++needmore;
            }
            check("resp reader byte-by-byte -> Ready", last == E::Ready, err);
            check("resp reader reported NeedMore midway", needmore > 0);
        }

        // At every split point
        {
            bool all_ok = true;
            for (std::size_t cut = 1; cut < wire.size(); ++cut) {
                ResponseHeaderReader rd;
                rd.bind(rk, 0x42);
                ResponseHeader h;
                std::string err;
                rd.feed({wire.data(), cut});
                if (rd.next(h, err) != E::NeedMore) { all_ok = false; break; }
                rd.feed({wire.data() + cut, wire.size() - cut});
                if (rd.next(h, err) != E::Ready) { all_ok = false; break; }
            }
            check("resp reader correct at every split point (incl. the 18B boundary cut in half)",
                  all_ok);
        }

        // Leftover bytes must be handed back intact (servers often send the
        // response header together with the first batch of data)
        {
            Bytes with_extra = wire;
            Bytes tail = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
            with_extra.insert(with_extra.end(), tail.begin(), tail.end());
            ResponseHeaderReader rd;
            rd.bind(rk, 0x42);
            rd.feed(with_extra);
            ResponseHeader h;
            std::string err;
            check("with trailing bytes -> Ready", rd.next(h, err) == E::Ready);
            check("leftover byte count correct", rd.buffered() == tail.size());
            check("take_remaining content matches", rd.take_remaining() == tail);
            check("buffer cleared after take_remaining", rd.buffered() == 0);
        }

        // Echo mismatch
        {
            ResponseHeaderReader rd;
            rd.bind(rk, 0x43); // expected value differs from the server's 0x42
            rd.feed(wire);
            ResponseHeader h;
            std::string err;
            check("echo mismatch -> Error", rd.next(h, err) == E::Error && !err.empty());
        }

        // Tampered length section
        {
            Bytes bad = build_resp_wire(rk, 4, resp_payload, /*corrupt_len=*/true);
            ResponseHeaderReader rd;
            rd.bind(rk, 0x42);
            rd.feed(bad);
            ResponseHeader h;
            std::string err;
            check("tampered length section -> Error", rd.next(h, err) == E::Error);
        }

        // Implausible declared length (>1024)
        {
            Bytes huge = build_resp_wire(rk, 2000, resp_payload, false);
            ResponseHeaderReader rd;
            rd.bind(rk, 0x42);
            rd.feed(huge);
            ResponseHeader h;
            std::string err;
            check("implausible length -> Error", rd.next(h, err) == E::Error);
        }

        // Not bound
        {
            ResponseHeaderReader rd;
            rd.feed(wire);
            ResponseHeader h;
            std::string err;
            check("not bound -> Error", rd.next(h, err) == E::Error && !err.empty());
        }
    }

    if (failures == 0) std::puts("test_header: all passed");
    return failures == 0 ? 0 : 1;
}
