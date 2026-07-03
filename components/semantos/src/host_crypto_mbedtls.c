// host_crypto_mbedtls.c — concrete implementation of the crypto host imports
// backed by the mbedTLS component that ships with ESP-IDF.
//
// The cell-engine embedded WASM blob declares these as extern "host"
// functions (see packages/cell-engine/src/host.zig). The runtime backend
// (WAMR in the public edge kit) binds them to the wrappers defined here.
//
// Note on sizes: SHA-256 output is 32 bytes, RIPEMD160 output is 20 bytes,
// HASH160 output is 20 bytes (SHA-256 → RIPEMD-160), HASH256 output is
// 32 bytes (SHA-256 twice). The WASM side guarantees the output buffers
// are large enough; we do not bounds-check them.

#include "semantos_internal.h"
#include "sdkconfig.h"

#include "mbedtls/sha256.h"
#include "mbedtls/sha1.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"

#include <string.h>
#include <stdbool.h>

#if CONFIG_SEMANTOS_LOG_HOST_CALLS
#  define CRYPTO_TRACE(fmt, ...) ESP_LOGI(SEMANTOS_TAG, "crypto: " fmt, ##__VA_ARGS__)
#else
#  define CRYPTO_TRACE(fmt, ...) do {} while (0)
#endif

// ── Module-static secp256k1 group ─────────────────────────────────────────
//
// Loaded once on first checksig call, then reused for every subsequent
// verify.  This matches the pattern in cell_sig.c (cm_sig_verify uses a
// single static s_grp and verifies thousands of cell-frame signatures per
// hour without issue).
//
// Empirical finding (2026-05-21, C6 board): mbedtls_ecdsa_verify returns
// -0x4E00 (VERIFY_FAILED) when grp is allocated on the local call stack
// and loaded fresh inside the WAMR execution environment, even though the
// same hash + r + s + Q passes via cm_sig_verify's static group.  Making
// the group module-static (same as cell_sig.c) eliminates the discrepancy.
static bool            s_secp256k1_ready = false;
static mbedtls_ecp_group s_secp256k1_grp;

// Must be called before any checksig / checkmultisig operation.
// Safe to call multiple times; initialises exactly once.
static int secp256k1_grp_init(void) {
    if (s_secp256k1_ready) return 0;
    mbedtls_ecp_group_init(&s_secp256k1_grp);
    int rc = mbedtls_ecp_group_load(&s_secp256k1_grp, MBEDTLS_ECP_DP_SECP256K1);
    if (rc != 0) {
        ESP_LOGE(SEMANTOS_TAG,
                 "secp256k1_grp_init: ecp_group_load failed -0x%04x", (unsigned)-rc);
        mbedtls_ecp_group_free(&s_secp256k1_grp);
        return rc;
    }
    s_secp256k1_ready = true;
    return 0;
}

void semantos_host_sha256(const uint8_t *data, uint32_t data_len, uint8_t *out32) {
    CRYPTO_TRACE("sha256 len=%u", (unsigned)data_len);
    mbedtls_sha256(data, data_len, out32, /*is224=*/0);
}

void semantos_host_hash256(const uint8_t *data, uint32_t data_len, uint8_t *out32) {
    CRYPTO_TRACE("hash256 len=%u", (unsigned)data_len);
    uint8_t first[32];
    mbedtls_sha256(data, data_len, first, 0);
    mbedtls_sha256(first, sizeof(first), out32, 0);
}

void semantos_host_hash160(const uint8_t *data, uint32_t data_len, uint8_t *out20) {
    CRYPTO_TRACE("hash160 len=%u", (unsigned)data_len);
    uint8_t sha_out[32];
    mbedtls_sha256(data, data_len, sha_out, 0);
    mbedtls_ripemd160(sha_out, sizeof(sha_out), out20);
}

void semantos_host_ripemd160(const uint8_t *data, uint32_t data_len, uint8_t *out20) {
    CRYPTO_TRACE("ripemd160 len=%u", (unsigned)data_len);
    mbedtls_ripemd160(data, data_len, out20);
}

void semantos_host_sha1(const uint8_t *data, uint32_t data_len, uint8_t *out20) {
    CRYPTO_TRACE("sha1 len=%u", (unsigned)data_len);
    mbedtls_sha1(data, data_len, out20);
}

// ── checksig ────────────────────────────────────────────────────────────
//
// Verify a Bitcoin-style ECDSA signature over `msg` using a secp256k1
// public key. `pk` is expected in the usual 33- or 65-byte SEC encoding,
// `sig` in DER (the most common Bitcoin Script sighash type suffix byte
// is stripped by the caller before reaching the kernel — we assume a
// clean DER signature here).
//
// For the edge kit we keep this simple: any key or signature we cannot
// parse returns 0 (verification failed). Feel free to flesh out the error
// propagation if you care.

uint32_t semantos_host_checksig(const uint8_t *pk, uint32_t pk_len,
                                const uint8_t *msg, uint32_t msg_len,
                                const uint8_t *sig, uint32_t sig_len) {
    CRYPTO_TRACE("checksig pk_len=%u msg_len=%u sig_len=%u",
                 (unsigned)pk_len, (unsigned)msg_len, (unsigned)sig_len);

    // Ensure the module-static secp256k1 group is ready.  Doing this once at
    // module level (rather than fresh each call) matches cell_sig.c's pattern
    // and avoids the VERIFY_FAILED observed when the group was allocated on
    // the local stack inside the WAMR execution environment.
    if (secp256k1_grp_init() != 0) return 0;

    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    uint32_t ok = 0;

    if (mbedtls_ecp_point_read_binary(&s_secp256k1_grp, &Q, pk, pk_len) != 0) {
        ESP_LOGE(SEMANTOS_TAG, "checksig: ecp_point_read_binary failed");
        goto done;
    }

    // msg is the pre-hashed 32-byte BIP-143 sighash from the Zig kernel.
    // The embedded engine always pre-computes the sighash, so msg_len == 32
    // in normal operation.  Hash the message first only as a safety fallback.
    const uint8_t *hash = msg;
    uint8_t hash_buf[32];
    if (msg_len != 32) {
        mbedtls_sha256(msg, msg_len, hash_buf, 0);
        hash = hash_buf;
    }

    // DER ECDSA sig:  0x30 LEN 0x02 R_LEN <R> 0x02 S_LEN <S>
    //
    // Parse manually so we can call mbedtls_ecdsa_verify directly with the
    // module-static group — the same low-level API used by cm_sig_verify.
    if (sig_len >= 8 && sig[0] == 0x30) {
        size_t total_len = sig[1];
        if (total_len == sig_len - 2 && sig[2] == 0x02) {
            size_t r_len = sig[3];
            if (4 + r_len + 2 <= sig_len && sig[4 + r_len] == 0x02) {
                size_t s_len = sig[4 + r_len + 1];
                const uint8_t *r_bytes = sig + 4;
                const uint8_t *s_bytes = sig + 4 + r_len + 2;
                if (4 + r_len + 2 + s_len == sig_len) {
                    mbedtls_mpi r, s;
                    mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
                    int er = mbedtls_mpi_read_binary(&r, r_bytes, r_len);
                    int es = mbedtls_mpi_read_binary(&s, s_bytes, s_len);
                    if (er == 0 && es == 0) {
                        int vr = mbedtls_ecdsa_verify(
                            &s_secp256k1_grp, hash, 32, &Q, &r, &s);
                        ok = (vr == 0) ? 1 : 0;
                    } else {
                        ESP_LOGE(SEMANTOS_TAG,
                                 "checksig mpi_read failed er=%d es=%d",
                                 er, es);
                    }
                    mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
                } else {
                    ESP_LOGE(SEMANTOS_TAG,
                             "checksig DER length check failed:"
                             " 4+r_len+2+s_len=%zu sig_len=%u",
                             4 + r_len + 2 + s_len, (unsigned)sig_len);
                }
            }
        } else {
            ESP_LOGE(SEMANTOS_TAG,
                     "checksig DER parse failed: total_len=%zu sig_len-2=%u"
                     " sig[2]=0x%02x",
                     total_len, (unsigned)(sig_len - 2), sig[2]);
        }
    } else {
        ESP_LOGE(SEMANTOS_TAG,
                 "checksig: not DER (sig[0]=0x%02x sig_len=%u)",
                 sig[0], (unsigned)sig_len);
    }

done:
    mbedtls_ecp_point_free(&Q);
    return ok;
}

// ── checkmultisig ──────────────────────────────────────────────────────
//
// Verify at least `threshold` signatures out of `sigs_count` against
// `pks_count` public keys. Bitcoin-Script-style semantics: signatures are
// verified in order, each matched to a key scanned forward, failing as
// soon as the remaining keys cannot satisfy the threshold.
//
// Keys and sigs are packed length-prefixed: a single byte `len`, followed
// by `len` bytes of key/sig data, repeated `count` times. This matches
// what the embedded-profile kernel produces for the WASM-extern shape.

static uint32_t read_item(const uint8_t **cursor, const uint8_t *end,
                          const uint8_t **out_ptr, uint32_t *out_len) {
    if (*cursor >= end) return 0;
    uint32_t len = **cursor;
    (*cursor)++;
    if (*cursor + len > end) return 0;
    *out_ptr = *cursor;
    *out_len = len;
    *cursor += len;
    return 1;
}

uint32_t semantos_host_checkmultisig(const uint8_t *pks, uint32_t pks_count,
                                     const uint8_t *sigs, uint32_t sigs_count,
                                     const uint8_t *msg, uint32_t msg_len,
                                     uint32_t threshold) {
    CRYPTO_TRACE("checkmultisig pks=%u sigs=%u threshold=%u",
                 (unsigned)pks_count, (unsigned)sigs_count, (unsigned)threshold);
    if (secp256k1_grp_init() != 0) return 0;

    if (threshold == 0) return 1;
    if (sigs_count < threshold) return 0;

    // For the edge kit we bound things loosely; the kernel would be a
    // better place to enforce tight limits.
    const uint8_t *pk_cursor  = pks;
    const uint8_t *pk_end     = pks  + (pks_count  * 72);   /* upper bound */
    const uint8_t *sig_cursor = sigs;
    const uint8_t *sig_end    = sigs + (sigs_count * 80);   /* upper bound */

    uint32_t verified = 0;
    uint32_t remaining_keys = pks_count;

    while (verified < threshold && remaining_keys > 0) {
        const uint8_t *sig_ptr; uint32_t sig_len;
        if (!read_item(&sig_cursor, sig_end, &sig_ptr, &sig_len)) return 0;

        // Walk forward through keys until one verifies this signature.
        int consumed = 0;
        while (remaining_keys > 0) {
            const uint8_t *pk_ptr; uint32_t pk_len;
            if (!read_item(&pk_cursor, pk_end, &pk_ptr, &pk_len)) return 0;
            remaining_keys--;

            if (semantos_host_checksig(pk_ptr, pk_len, msg, msg_len, sig_ptr, sig_len)) {
                verified++;
                consumed = 1;
                break;
            }
        }
        if (!consumed) return 0;
    }

    return verified >= threshold ? 1 : 0;
}

uint32_t semantos_host_sign(const uint8_t *sk, uint32_t sk_len,
                            const uint8_t *msg, uint32_t msg_len,
                            uint8_t *out, uint32_t out_buf_len,
                            uint32_t *out_len) {
    (void)sk;
    (void)sk_len;
    (void)msg;
    (void)msg_len;
    (void)out;
    (void)out_buf_len;
    if (out_len) *out_len = 0;
    // Edge devices should verify/broadcast pre-signed cells by default, not
    // hold wallet-tier private keys. Apps that intentionally keep keys on the
    // device can replace this fail-closed stub.
    return 0;
}
