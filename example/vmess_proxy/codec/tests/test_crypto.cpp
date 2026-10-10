// Crypto layer unit tests: all using public standard vectors (RFC 1321 /
// FIPS 180 / RFC 4231 / FIPS 197 / NIST GCM / known CRC and FNV values)
#include <cassert>
#include <cstdio>
#include <cstring>

#include "vmess/crypto.hpp"

using namespace vmess;

static int failures = 0;

#define CHECK_EQ(actual, expected)                                                        \
    do {                                                                                  \
        if ((actual) != (expected)) {                                                     \
            std::printf("FAIL %s:%d\n  actual:   %s\n  expected: %s\n", __FILE__,         \
                        __LINE__, to_hex(actual).c_str(), to_hex(expected).c_str());      \
            ++failures;                                                                   \
        }                                                                                 \
    } while (0)

static Bytes str(std::string_view s) {
    return Bytes(s.begin(), s.end());
}

int main() {
    // ---- MD5 (RFC 1321) ----
    CHECK_EQ(md5(str("")), from_hex("d41d8cd98f00b204e9800998ecf8427e"));
    CHECK_EQ(md5(str("abc")), from_hex("900150983cd24fb0d6963f7d28e17f72"));

    // ---- SHA-256 (FIPS 180-2) ----
    CHECK_EQ(sha256(str("")), from_hex(
                                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(sha256(str("abc")), from_hex(
                                     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    // ---- HMAC-SHA256 (RFC 4231 Test Case 2) ----
    CHECK_EQ(hmac_sha256(str("Jefe"), str("what do ya want for nothing?")),
             from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));

    // ---- AES-128-ECB single block (FIPS 197 Appendix C.1) ----
    {
        auto key = from_hex("000102030405060708090a0b0c0d0e0f");
        auto pt = from_hex("00112233445566778899aabbccddeeff");
        CHECK_EQ(aes128_ecb_encrypt_block(key, pt),
                 from_hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }

    // ---- AES-128-GCM (NIST GCM spec Test Case 1/3) ----
    {
        // TC1: zero key/zero IV/empty plaintext -> the zero-IV tag
        auto key = Bytes(16, 0);
        auto nonce = Bytes(12, 0);
        auto sealed = aes128_gcm_seal(key, nonce, {});
        CHECK_EQ(sealed, from_hex("58e2fccefa7e3061367f1d57a4e7455a"));
        auto opened = aes128_gcm_open(key, nonce, sealed);
        assert(opened.empty());
    }
    {
        // TC3: 4 blocks of plaintext
        auto key = from_hex("feffe9928665731c6d6a8f9467308308");
        auto nonce = from_hex("cafebabefacedbaddecaf888");
        auto pt = from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                           "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
                           "1aafd255");
        auto expect = from_hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                               "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
                               "4d5c2af327cd64a62cf35abd2ba6fab4");
        auto sealed = aes128_gcm_seal(key, nonce, pt);
        CHECK_EQ(sealed, expect);
        CHECK_EQ(aes128_gcm_open(key, nonce, sealed), pt);
        // A tampered tag must fail
        auto bad = sealed;
        bad[bad.size() - 1] ^= 0x01;
        bool threw = false;
        try { aes128_gcm_open(key, nonce, bad); } catch (const Error&) { threw = true; }
        if (!threw) { std::puts("FAIL: tampered GCM tag was accepted"); ++failures; }
    }

    // ---- CRC-32 IEEE ----
    if (crc32_ieee(str("123456789")) != 0xCBF43926u) {
        std::printf("FAIL crc32: %08x\n", crc32_ieee(str("123456789")));
        ++failures;
    }

    // ---- FNV-1a 32 ----
    if (fnv1a32({}) != 0x811C9DC5u) { std::puts("FAIL fnv1a32 empty"); ++failures; }
    if (fnv1a32(str("a")) != 0xE40C292Cu) { std::puts("FAIL fnv1a32 'a'"); ++failures; }
    if (fnv1a32(str("foobar")) != 0xBF9CF968u) { std::puts("FAIL fnv1a32 'foobar'"); ++failures; }

    // ---- Basic properties of the RNG ----
    {
        Bytes a(32), b(32);
        secure_random(a);
        secure_random(b);
        if (a == b || Bytes(32, 0) == a) { std::puts("FAIL secure_random"); ++failures; }
    }

    if (failures == 0) std::puts("test_crypto: all passed");
    return failures == 0 ? 0 : 1;
}
