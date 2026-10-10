#include "vmess/kdf.hpp"

#include <openssl/evp.h>

#include <memory>

#include "vmess/common.hpp"

// Xray's KDF is an odd "chained HMAC" construction (proxy/vmess/aead/kdf.go):
//   hmacf = hmac.New(sha256, "VMess AEAD KDF")
//   for v in path: hmacf = hmac.New(closure with hmacf as both inner/outer, v)
//   hmacf.Write(key); return hmacf.Sum()
//
// Because outer points at the previous-layer HMAC itself, the side effects of
// Go hmac's Sum/Reset (Reset of outer, marshaled state caching) cascade into
// the previous layer's state, so it cannot be expressed as a simple nested
// HMAC formula. This file mimics, verbatim, the object semantics of Go 1.27
// crypto/hmac (the fips140 implementation):
//   Sum:   in=inner.Sum(); outer.Reset()+Write(opad) (or restore via Unmarshal);
//          outer.Write(in); return outer.Sum()
//   Reset: inner.Reset()+Write(ipad); if both inner and outer are marshalable,
//          cache both states
// Note: the HMAC object itself does not implement marshal (stated explicitly
// in the crypto/hmac docs); only a bare SHA-256 does.
namespace vmess {
namespace {

constexpr std::size_t kSha256Block = 64;

// Go hash.Hash object model (Write / non-destructive Sum / Reset / optional marshal)
struct HashObj {
    virtual ~HashObj() = default;
    virtual void write(std::span<const std::uint8_t> p) = 0;
    virtual void sum(Bytes& out) = 0; // append the digest of the current state to out
    virtual void reset() = 0;
    virtual bool marshalable() const { return false; }
    virtual std::shared_ptr<struct HashState> marshal() const { throw Error("not marshalable"); }
    virtual void unmarshal(const struct HashState&) { throw Error("not marshalable"); }
};

struct HashState {
    EVP_MD_CTX* ctx = nullptr;
    ~HashState() { EVP_MD_CTX_free(ctx); }
};

// Bare SHA-256 (equivalent to Go sha256.digest)
struct Sha256Obj : HashObj {
    EVP_MD_CTX* ctx;

    Sha256Obj() : ctx(EVP_MD_CTX_new()) {
        if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            throw Error("SHA256 init failed");
        }
    }
    ~Sha256Obj() override { EVP_MD_CTX_free(ctx); }
    Sha256Obj(const Sha256Obj&) = delete;
    Sha256Obj& operator=(const Sha256Obj&) = delete;

    void write(std::span<const std::uint8_t> p) override {
        if (EVP_DigestUpdate(ctx, p.data(), p.size()) != 1) throw Error("SHA256 update failed");
    }

    void sum(Bytes& out) override {
        EVP_MD_CTX* snapshot = EVP_MD_CTX_new();
        if (!snapshot || EVP_MD_CTX_copy_ex(snapshot, ctx) != 1) {
            throw Error("SHA256 snapshot failed");
        }
        std::uint8_t buf[EVP_MAX_MD_SIZE];
        unsigned len = 0;
        EVP_DigestFinal_ex(snapshot, buf, &len);
        EVP_MD_CTX_free(snapshot);
        out.insert(out.end(), buf, buf + len);
    }

    void reset() override {
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) throw Error("SHA256 reset failed");
    }

    bool marshalable() const override { return true; }
    std::shared_ptr<HashState> marshal() const override {
        auto s = std::make_shared<HashState>();
        s->ctx = EVP_MD_CTX_new();
        if (!s->ctx || EVP_MD_CTX_copy_ex(s->ctx, ctx) != 1) throw Error("SHA256 marshal failed");
        return s;
    }
    void unmarshal(const HashState& s) override {
        if (EVP_MD_CTX_copy_ex(ctx, s.ctx) != 1) throw Error("SHA256 unmarshal failed");
    }
};

// Faithful simulation of Go crypto/hmac; inner/outer can be any HashObj
// (in the KDF they point to the same object)
struct HmacObj : HashObj {
    std::shared_ptr<HashObj> inner;
    std::shared_ptr<HashObj> outer;
    Bytes ipad, opad; // 64B blocks derived from the key
    bool marshaled = false;
    std::shared_ptr<HashState> ipad_state, opad_state; // state cache after marshaling

    HmacObj(std::shared_ptr<HashObj> in, std::shared_ptr<HashObj> out,
            std::span<const std::uint8_t> key)
        : inner(std::move(in)), outer(std::move(out)), ipad(kSha256Block, 0),
          opad(kSha256Block, 0) {
        if (key.size() > kSha256Block) throw Error("HMAC key too long for KDF use");
        for (std::size_t i = 0; i < key.size(); ++i) {
            ipad[i] = static_cast<std::uint8_t>(key[i]);
            opad[i] = static_cast<std::uint8_t>(key[i]);
        }
        for (std::size_t i = 0; i < kSha256Block; ++i) {
            ipad[i] ^= 0x36;
            opad[i] ^= 0x5C;
        }
        // Finishing step of Go hmac.New: hm.inner.Write(hm.ipad)
        inner->write(ipad);
    }

    void write(std::span<const std::uint8_t> p) override { inner->write(p); }

    void sum(Bytes& out) override {
        Bytes d;
        inner->sum(d);
        if (marshaled) {
            outer->unmarshal(*opad_state);
        } else {
            outer->reset();
            outer->write(opad);
        }
        outer->write(d);
        outer->sum(out);
    }

    void reset() override {
        if (marshaled) {
            inner->unmarshal(*ipad_state);
            return;
        }
        inner->reset();
        inner->write(ipad);
        // Go: cache states only when both inner and outer are marshalable
        // (an HMAC object is not marshalable)
        if (inner->marshalable() && outer->marshalable()) {
            ipad_state = inner->marshal();
            outer->reset();
            outer->write(opad);
            opad_state = outer->marshal();
            marshaled = true;
        }
    }
};

} // namespace

Bytes kdf(std::span<const std::uint8_t> key,
          std::initializer_list<std::span<const std::uint8_t>> path) {
    constexpr std::string_view kKdfSalt = "VMess AEAD KDF";

    // h0 = hmac.New(sha256.New, []byte("VMess AEAD KDF"))
    std::shared_ptr<HashObj> hmacf =
        std::make_shared<HmacObj>(std::make_shared<Sha256Obj>(), std::make_shared<Sha256Obj>(),
                                  as_bytes(kKdfSalt));

    // Each path element: the new HMAC's inner/outer both point to the
    // previous layer's object (Go's hash2 closure wrapper is just a type
    // formality; behavior matches the bare object)
    for (auto v : path) {
        hmacf = std::make_shared<HmacObj>(hmacf, hmacf, v);
    }

    hmacf->write(key);
    Bytes out;
    hmacf->sum(out);
    return out;
}

Bytes kdf16(std::span<const std::uint8_t> key,
            std::initializer_list<std::span<const std::uint8_t>> path) {
    Bytes out = kdf(key, path);
    out.resize(16);
    return out;
}

} // namespace vmess
