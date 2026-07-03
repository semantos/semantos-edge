// cell_sig.h — ECDSA-secp256k1 sign + verify for cell-mesh radio frames.
//
// Same crypto curve as the cell-engine's OP_CHECKSIG (BSV-style). Uses
// mbedTLS underneath. Deterministic signing per RFC 6979 — no entropy
// required at sign time, useful on an MCU where the RNG might be cold.
//
// Wire format: signatures are 64-byte raw (r || s), 32 bytes each, big-
// endian. Public keys are 33-byte compressed (0x02/0x03 prefix + x). These
// formats minimise radio payload vs DER (~70-72 bytes) and uncompressed
// pubkeys (65 bytes).
//
// Convention: the caller computes the message hash (typically SHA-256 of
// a 1024-byte cell + 4-byte cell_id) and passes the 32-byte digest to
// sign/verify. Keeps this module curve-only; no hash policy embedded.
//
// IDF-only: this file depends on mbedTLS. Host tests for cell_sig itself
// are not provided here — the curve math is well-trodden; we test the
// integration on-device.

#pragma once

#include "cell_wire.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CM_SIG_PRIVKEY_BYTES       32u
#define CM_SIG_PUBKEY_COMPRESSED   33u
#define CM_SIG_BYTES               64u   // r || s, 32+32 big-endian

// Initialize the secp256k1 ECP group. Idempotent. Returns 0 on success.
int cm_sig_init(void);

// Sign a 32-byte message hash with a 32-byte secp256k1 private key.
// Produces a 64-byte raw r||s signature.
// Returns 0 on success, negative on error.
int cm_sig_sign(const uint8_t privkey[CM_SIG_PRIVKEY_BYTES],
                const uint8_t msg_hash[32],
                uint8_t       out_sig[CM_SIG_BYTES]);

// Verify a 64-byte raw r||s signature against a 33-byte compressed pubkey
// and a 32-byte message hash. Returns 0 on valid, negative on invalid or
// error.
//
// Note: this parses the compressed pubkey on every call (decompresses y,
// validates point on curve). For hot paths with a stable verifying key,
// use cm_sig_pubkey_load + cm_sig_verify_prepared to skip the parse.
int cm_sig_verify(const uint8_t pubkey_compressed[CM_SIG_PUBKEY_COMPRESSED],
                  const uint8_t msg_hash[32],
                  const uint8_t sig[CM_SIG_BYTES]);

// Opaque prepared-pubkey handle. Holds the parsed (decompressed)
// mbedTLS ECP point so the verify hot path can skip per-call parsing.
// Treat as opaque; size is exposed so the caller can allocate.
typedef struct cm_sig_pubkey_s cm_sig_pubkey_t;

// Allocate + parse a pubkey once. Returns 0 on success, negative on
// error. On success, `*out` must later be freed with cm_sig_pubkey_free.
int cm_sig_pubkey_load(const uint8_t pubkey_compressed[CM_SIG_PUBKEY_COMPRESSED],
                       cm_sig_pubkey_t **out);
void cm_sig_pubkey_free(cm_sig_pubkey_t *pub);

// Verify with a pre-parsed pubkey. In theory this saves the compressed-
// pubkey parse (a mod-p square root + point-on-curve check) per call.
//
// EMPIRICAL FINDING (ESP32-C6, ESP-IDF v5.3.1, mbedTLS HW SHA+MPI on):
// the prepared path actually measured 30-75 µs SLOWER than plain
// cm_sig_verify across 30-iter benches on two devices. Likely cause:
// heap-allocated point loses cache locality vs a stack-fresh one, and
// mbedtls_ecdsa_verify's internal comb-precompute is rebuilt per call
// either way. The API stays for cleanliness and for ports where it
// might win, but on C6 there's no measurable speedup — use plain
// cm_sig_verify in hot paths until this changes.
int cm_sig_verify_prepared(const cm_sig_pubkey_t *pub,
                           const uint8_t msg_hash[32],
                           const uint8_t sig[CM_SIG_BYTES]);

// Derive the 33-byte compressed public key from a 32-byte private key.
// Useful for tests and provisioning tools. Production device flows should
// prefer verifier-only keys on-device and keep spending keys off-device.
// Returns 0 on success, negative on error.
int cm_sig_derive_pubkey(const uint8_t privkey[CM_SIG_PRIVKEY_BYTES],
                         uint8_t out_pubkey_compressed[CM_SIG_PUBKEY_COMPRESSED]);

// Helper: SHA-256 over the 1024 canonical cell bytes. Returns the
// 32-byte digest that should be passed to cm_sig_sign / cm_sig_verify.
// The signature binds the cell content; replay protection lives at a
// higher layer (cell timestamp window + ring-buffer dedup).
void cm_sig_hash_cell(const uint8_t cell[CM_CELL_SIZE],
                      uint8_t out_hash[32]);

#ifdef __cplusplus
}
#endif
