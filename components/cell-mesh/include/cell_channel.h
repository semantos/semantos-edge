// cell_channel.h — payment-channel state machine carried in linear cells.
//
// Foundation for the lightbulb-channel scenario: a user funds a 2-of-2
// multisig, then exchanges off-chain commitment cells that shift sats
// from user → device as service is delivered. The latest valid
// commitment is the channel's "current state" — older ones are
// invalid by construction.
//
// This module provides:
//   1. Three cell-payload codecs: channel_open / channel_commitment /
//      channel_close.
//   2. A per-channel state machine with linearity enforcement.
//
// What linearity means here, concretely:
//   * `seq` must strictly increase with each new commitment. Old or
//     duplicate commitments are rejected.
//   * `device_share` must monotonically non-decrease (the device only
//     ever gets paid more across commitment updates within a channel).
//   * device_share + user_share must never exceed total_capacity.
//   * `expiry_ms` must be in the future at the time of receipt.
//
// What this module does NOT do (deferred to brain/wallet-headers):
//   * Validate the underlying 2-of-2 funding UTXO exists on chain.
//   * Broadcast the final close tx to BSV.
//   * Cryptographically verify the commitment signatures (the radio
//     layer already verifies the cell signature; the wallet/BSV side
//     would also check the commitment-script signatures on settlement).
//
// Pure C, no IDF dependency — host-testable.

#pragma once

#include "cell_wire.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── Channel state ────────────────────────────────────────────────────

typedef enum {
    CM_CHAN_CLOSED  = 0,  // no channel; or final commitment broadcast
    CM_CHAN_OPEN    = 1,  // channel_open accepted; no commitment yet
    CM_CHAN_ACTIVE  = 2,  // current commitment within expiry
    CM_CHAN_EXPIRED = 3,  // current commitment past expiry; awaiting close
} cm_channel_state_t;

typedef struct {
    cm_channel_state_t state;

    // Set on apply_open.
    uint8_t  channel_id[16];
    uint8_t  peer_pubkey[33];
    uint32_t total_capacity;
    uint64_t open_locktime_ms;

    // Set on apply_commitment (zeroed when state == CLOSED or OPEN).
    uint32_t current_seq;
    uint32_t device_share;
    uint32_t user_share;
    uint64_t expiry_ms;

    // Telemetry — for logs + tests.
    uint32_t commitments_received;
    uint32_t commitments_rejected;
} cm_channel_t;

// ── Wire encodings ───────────────────────────────────────────────────

#define CM_CHANNEL_OPEN_PAYLOAD_BYTES        61u
// Commitment wire format (68 bytes):
//   channel_id[16] | seq[4] | device_share[4] | user_share[4] |
//   expiry_ms[8]   | cert_hash[32]
// cert_hash = SHA-256(capability cert payload) — binds each payment hop to the
// specific BRC-42 capability cert that authorised the relay key (BRC-108).
#define CM_CHANNEL_COMMITMENT_PAYLOAD_BYTES  68u
#define CM_CHANNEL_CLOSE_PAYLOAD_BYTES       24u

typedef struct {
    uint8_t  channel_id[16];
    uint8_t  peer_pubkey[33];   // compressed secp256k1
    uint64_t initial_locktime_ms;
    uint32_t total_capacity;
} cm_channel_open_t;

typedef struct {
    uint8_t  channel_id[16];
    uint32_t seq;
    uint32_t device_share;
    uint32_t user_share;
    uint64_t expiry_ms;
    uint8_t  cert_hash[32];  // SHA-256(cap cert payload) — BRC-108 binding
} cm_channel_commitment_t;

typedef struct {
    uint8_t  channel_id[16];
    uint32_t final_seq;
    uint32_t final_device_share;
} cm_channel_close_t;

int cm_channel_open_encode      (const cm_channel_open_t       *in,  uint8_t out[CM_CHANNEL_OPEN_PAYLOAD_BYTES]);
int cm_channel_open_decode      (const uint8_t in[CM_CHANNEL_OPEN_PAYLOAD_BYTES],       cm_channel_open_t       *out);
int cm_channel_commitment_encode(const cm_channel_commitment_t *in,  uint8_t out[CM_CHANNEL_COMMITMENT_PAYLOAD_BYTES]);
int cm_channel_commitment_decode(const uint8_t in[CM_CHANNEL_COMMITMENT_PAYLOAD_BYTES], cm_channel_commitment_t *out);
int cm_channel_close_encode     (const cm_channel_close_t      *in,  uint8_t out[CM_CHANNEL_CLOSE_PAYLOAD_BYTES]);
int cm_channel_close_decode     (const uint8_t in[CM_CHANNEL_CLOSE_PAYLOAD_BYTES],      cm_channel_close_t      *out);

// ── State machine ────────────────────────────────────────────────────

void cm_channel_init(cm_channel_t *c);

// Result codes for apply_* functions.
typedef enum {
    CM_CHAN_OK             =  0,
    CM_CHAN_ERR_BAD_STATE  = -1,  // state machine doesn't allow this transition
    CM_CHAN_ERR_BAD_ID     = -2,  // channel_id doesn't match
    CM_CHAN_ERR_STALE_SEQ  = -3,  // commitment seq <= current_seq
    CM_CHAN_ERR_NON_MONO   = -4,  // device_share decreased
    CM_CHAN_ERR_OVERFLOW   = -5,  // device_share + user_share > total_capacity
    CM_CHAN_ERR_EXPIRED    = -6,  // expiry_ms already past at receipt
    CM_CHAN_ERR_SEQ_MATCH  = -7,  // close.final_seq != current_seq
} cm_channel_rc_t;

// Open a channel. Only valid when c->state == CM_CHAN_CLOSED. Records
// peer_pubkey + total_capacity + locktime. Transitions to OPEN.
cm_channel_rc_t cm_channel_apply_open(cm_channel_t *c,
                                       const cm_channel_open_t *op);

// Apply a commitment update. Valid when state is OPEN or ACTIVE.
// Enforces: channel_id matches, seq strictly increases, device_share
// monotonically non-decreases, device+user <= capacity, expiry > now.
// Transitions to ACTIVE.
//
// `now_ms` is the host monotonic clock — used for the expiry check.
// If the new expiry is in the past at receipt, the commitment is
// rejected and the channel state is unchanged.
cm_channel_rc_t cm_channel_apply_commitment(cm_channel_t *c,
                                             const cm_channel_commitment_t *cm,
                                             uint64_t now_ms);

// Close the channel. Valid when state is ACTIVE or EXPIRED. Requires
// close.final_seq == current_seq and close.final_device_share ==
// current device_share (the close cell carries the same numbers the
// channel currently holds — a sanity tie to the latest commitment).
// Transitions to CLOSED.
cm_channel_rc_t cm_channel_apply_close(cm_channel_t *c,
                                        const cm_channel_close_t *cl);

// Mark the channel EXPIRED if state is ACTIVE and now_ms > expiry_ms.
// No-op otherwise. Caller invokes from a periodic tick.
void cm_channel_tick_expiry(cm_channel_t *c, uint64_t now_ms);

// ── BSV on-chain binding helpers ─────────────────────────────────────
//
// The bridge/wallet layer derives channel_id as the first 16 bytes of the
// funding txid (display/hex order).  This function validates that binding:
// returns true when channel_id == txid_display_bytes[0..16].
//
// The firmware itself never makes network calls to confirm the UTXO exists
// (that's the wallet/brain layer's job); it validates the derivation
// convention only, so the channel can't be opened with an arbitrary id that
// doesn't correspond to ANY real txid shape.
//
// txid_display: 32 bytes, txid in display order (as returned by ARC /v1/tx).
bool cm_channel_validate_utxo_ref(const uint8_t channel_id[16],
                                   const uint8_t txid_display[32]);

#ifdef __cplusplus
}
#endif
