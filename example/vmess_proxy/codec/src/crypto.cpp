#include "vmess/crypto.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>

namespace vmess {
namespace {

// RAII wrapper for EVP contexts
struct EvpCtxDeleter {
    void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); }
};
using EvpCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCtxDeleter>;

Bytes digest_one_shot(const EVP_MD* md, std::span<const std::uint8_t> data) {
    Bytes out(static_cast<std::size_t>(EVP_MD_get_size(md)));
    unsigned int outlen = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &outlen, md, nullptr) != 1 ||
        outlen != out.size()) {
        throw Error("EVP_Digest failed");
    }
    return out;
}

} // namespace

Bytes md5(std::span<const std::uint8_t> data) {
    return digest_one_shot(EVP_md5(), data);
}

Bytes sha256(std::span<const std::uint8_t> data) {
    return digest_one_shot(EVP_sha256(), data);
}

Bytes hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned int outlen = 0;
    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(),
             data.size(), out.data(), &outlen) == nullptr) {
        throw Error("HMAC failed");
    }
    out.resize(outlen);
    return out;
}

Bytes aes128_gcm_seal(std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
                      std::span<const std::uint8_t> plaintext, std::span<const std::uint8_t> aad) {
    if (key.size() != 16) throw Error("aes128_gcm_seal: key must be 16 bytes");
    if (nonce.size() != 12) throw Error("aes128_gcm_seal: nonce must be 12 bytes");

    EvpCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw Error("EVP_CIPHER_CTX_new failed");

    Bytes out(plaintext.size() + 16); // ciphertext + tag
    int outlen = 0, total = 0;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw Error("aes128_gcm_seal: init failed");
    }
    if (!aad.empty() &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &outlen, aad.data(), static_cast<int>(aad.size())) != 1) {
        throw Error("aes128_gcm_seal: aad failed");
    }
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), out.data(), &outlen, plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1) {
            throw Error("aes128_gcm_seal: encrypt failed");
        }
        total += outlen;
    }
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + total, &outlen) != 1) {
        throw Error("aes128_gcm_seal: final failed");
    }
    total += outlen;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, out.data() + total) != 1) {
        throw Error("aes128_gcm_seal: get tag failed");
    }
    return out;
}

Bytes aes128_gcm_open(std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
                      std::span<const std::uint8_t> ciphertext_with_tag,
                      std::span<const std::uint8_t> aad) {
    if (key.size() != 16) throw Error("aes128_gcm_open: key must be 16 bytes");
    if (nonce.size() != 12) throw Error("aes128_gcm_open: nonce must be 12 bytes");
    if (ciphertext_with_tag.size() < 16) throw Error("aes128_gcm_open: missing tag");

    const std::size_t ctlen = ciphertext_with_tag.size() - 16;
    EvpCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw Error("EVP_CIPHER_CTX_new failed");

    Bytes out(ctlen);
    int outlen = 0, total = 0;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        throw Error("aes128_gcm_open: init failed");
    }
    if (!aad.empty() &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &outlen, aad.data(), static_cast<int>(aad.size())) != 1) {
        throw Error("aes128_gcm_open: aad failed");
    }
    if (ctlen > 0) {
        if (EVP_DecryptUpdate(ctx.get(), out.data(), &outlen, ciphertext_with_tag.data(),
                              static_cast<int>(ctlen)) != 1) {
            throw Error("aes128_gcm_open: decrypt failed");
        }
        total += outlen;
    }
    // Final returns 0 when tag verification fails
    std::array<std::uint8_t, 16> tag{};
    std::copy(ciphertext_with_tag.begin() + ctlen, ciphertext_with_tag.end(), tag.begin());
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), out.data() + total, &outlen) != 1) {
        throw Error("aes128_gcm_open: authentication failed");
    }
    return out;
}

Bytes aes128_ecb_encrypt_block(std::span<const std::uint8_t> key, std::span<const std::uint8_t> block) {
    if (key.size() != 16 || block.size() != 16) {
        throw Error("aes128_ecb_encrypt_block: key and block must be 16 bytes");
    }

    EvpCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw Error("EVP_CIPHER_CTX_new failed");

    Bytes out(16);
    int outlen = 0;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1 ||
        EVP_EncryptUpdate(ctx.get(), out.data(), &outlen, block.data(), 16) != 1 ||
        outlen != 16) {
        throw Error("aes128_ecb_encrypt_block: failed");
    }
    return out;
}

std::uint32_t crc32_ieee(std::span<const std::uint8_t> data) {
    // Reflected polynomial 0xEDB88320 (IEEE 802.3), identical to Go
    // crc32.ChecksumIEEE
    static std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            t[i] = c;
        }
        return t;
    }();

    std::uint32_t crc = 0xFFFFFFFFu;
    for (auto b : data) {
        crc = table[(crc ^ b) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

std::uint32_t fnv1a32(std::span<const std::uint8_t> data) {
    // FNV-1a 32-bit: offset 2166136261, prime 16777619, identical to Go
    // hash/fnv New32a
    constexpr std::uint32_t kOffset = 2166136261u;
    constexpr std::uint32_t kPrime = 16777619u;
    std::uint32_t h = kOffset;
    for (auto b : data) {
        h ^= b;
        h *= kPrime;
    }
    return h;
}

void secure_random(std::span<std::uint8_t> out) {
    if (out.empty()) return;
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw Error("RAND_bytes failed");
    }
}

} // namespace vmess
