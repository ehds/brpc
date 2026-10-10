#pragma once
#include <cstddef>
#include <cstdint>
#include <span>

#include "common.hpp"

namespace vmess {

// ---- Hashing ----
Bytes md5(std::span<const std::uint8_t> data);
Bytes sha256(std::span<const std::uint8_t> data);
Bytes hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data);

// ---- Symmetric encryption ----

// AES-128-GCM. Nonce is a fixed 12 bytes; returns ciphertext + 16B tag.
// aad may be empty.
Bytes aes128_gcm_seal(std::span<const std::uint8_t> key,   // 16B
                      std::span<const std::uint8_t> nonce, // 12B
                      std::span<const std::uint8_t> plaintext,
                      std::span<const std::uint8_t> aad = {});

// Input is ciphertext + 16B tag; throws vmess::Error on tag verification
// failure.
Bytes aes128_gcm_open(std::span<const std::uint8_t> key,   // 16B
                      std::span<const std::uint8_t> nonce, // 12B
                      std::span<const std::uint8_t> ciphertext_with_tag,
                      std::span<const std::uint8_t> aad = {});

// AES-128-ECB encryption of a single 16-byte block (no padding) — used for
// AuthID.
Bytes aes128_ecb_encrypt_block(std::span<const std::uint8_t> key,   // 16B
                               std::span<const std::uint8_t> block); // 16B

// ---- Checksums ----
std::uint32_t crc32_ieee(std::span<const std::uint8_t> data);
std::uint32_t fnv1a32(std::span<const std::uint8_t> data);

// ---- Randomness ----
void secure_random(std::span<std::uint8_t> out);

} // namespace vmess
