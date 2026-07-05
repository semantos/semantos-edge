// cell_forward_v1.h — channel-gated SRv6-style forwarding.
//
// Extends cellmesh.forward.v0 with pre-signed per-hop payment commitments.
// The source (user/wallet) pre-computes one cm_channel_commitment_t for
// each hop when building the route, embeds them all in the cell, and each
// relay/destination verifies its own commitment before forwarding.
//
// Project rule: devices verify + act; wallets sign. The source pre-signs
// commitments for the whole route; per-hop minting is the wrong shape.
// There is no signing on-device, only cm_channel_apply_commitment
// (verify + accept).
//
// Wire layout (192-byte header + variable inner):
//
//   offset  size  field
//   0       16    flow_id              — end-to-end flow identifier
//   16      1     hop_index            — 0-indexed; advances on each forward step
//   17      1     total_hops           — expected total hops (encoded by source)
//   18      1     segments_remaining   — entries left in segments[]; capped at 4
//   19      1     hop_verb             — same encoding as forward.v0
//   20      4     inner_payload_len    — LE; ≤ 448
//   24      24    segments[4][6]       — next-hop MACs; unused slots zeroed
//   48      272   hop_commitments[4][68] — per-hop cm_channel_commitment_t
//                   Each 68-byte slot:
//                     0-15:  channel_id[16]
//                     16-19: seq          (LE u32)
//                     20-23: device_share (LE u32)
//                     24-27: user_share   (LE u32)
//                     28-35: expiry_ms    (LE u64)
//                     36-67: cert_hash[32]  SHA-256(cap cert payload) BRC-108 binding
//                   hop_commitments[i] is consumed by the device at hop i
//                   (fwd.hop_index == i before cm_forward_v1_step is called).
//                   Unused slots zeroed by the source.
//   320     ≤448  inner_payload
//
// Channel-check semantics at each hop:
//   1. Identify own hop index (fwd.hop_index before step).
//   2. Decode hop_commitments[hop_index] → cm_channel_commitment_t.
//   3. cm_channel_apply_commitment(my_channel, &commitment, now_ms).
//   4. If not CM_CHAN_OK → DROP (log "CHANNEL REJECT: rc=%d").
//   5. Else → apply hop_verb, step, re-emit (or deliver).
//
// The channel itself must be OPEN or ACTIVE (state machine enforces
// linearity: seq strictly increases, device_share monotone non-decreasing).
// Channel open is done out-of-band via cellmesh.channel.open.v0.
//
// Zig-backed C ABI, no IDF dependency — host-testable.

#pragma once

#include "cell_forward.h"
#include "cell_channel.h"

#ifdef __cplusplus
extern "C" {
#endif

// ── Wire constants ───────────────────────────────────────────────────

// 4 hops × 68 bytes each (cm_channel_commitment_t on the wire, includes cert_hash[32])
#define CM_FORWARD_V1_COMMIT_SLOT_BYTES  68u
#define CM_FORWARD_V1_COMMIT_ARRAY_BYTES (CM_FORWARD_MAX_HOPS * CM_FORWARD_V1_COMMIT_SLOT_BYTES)  // 272

// v1 header = v0 header + commitment array
#define CM_FORWARD_V1_HEADER_BYTES  (CM_FORWARD_HEADER_BYTES + CM_FORWARD_V1_COMMIT_ARRAY_BYTES)  // 320

// Maximum inner payload bytes for a v1 cell
#define CM_FORWARD_V1_MAX_INNER_BYTES  (CM_PAYLOAD_SIZE - CM_FORWARD_V1_HEADER_BYTES)  // 448

// ── Struct ───────────────────────────────────────────────────────────

typedef struct {
    // ── v0 fields (identical layout) ────────────────────────────────
    uint8_t       flow_id[16];
    uint8_t       hop_index;
    uint8_t       total_hops;
    uint8_t       segments_remaining;
    cm_hop_verb_t hop_verb;
    uint8_t       segments[CM_FORWARD_MAX_HOPS][6];

    // ── v1 extension ─────────────────────────────────────────────────
    // hop_commitments[i] is the payment commitment the source pre-signed
    // for the device at hop i.  The relay at hop i checks this before
    // forwarding; unused slots are zero-initialised.
    cm_channel_commitment_t hop_commitments[CM_FORWARD_MAX_HOPS];

    // ── shared payload ───────────────────────────────────────────────
    uint32_t inner_payload_len;
    uint8_t  inner_payload[CM_FORWARD_V1_MAX_INNER_BYTES];
} cm_forward_v1_t;

// ── Codec ────────────────────────────────────────────────────────────

// Encode a forward.v1 struct into the cell payload region.
// *out_used = CM_FORWARD_V1_HEADER_BYTES + inner_payload_len on success.
// Returns 0 on success, -1 on bad args / inner_payload_len > 576 /
// segments_remaining > CM_FORWARD_MAX_HOPS.
int cm_forward_v1_encode(const cm_forward_v1_t *in,
                         uint8_t out[CM_PAYLOAD_SIZE],
                         size_t *out_used);

// Decode from the cell payload region.
// Returns 0 on success, -1 on bad args / corrupt header.
int cm_forward_v1_decode(const uint8_t in[CM_PAYLOAD_SIZE],
                         size_t in_used,
                         cm_forward_v1_t *out);

// Advance the forward cell one hop — identical semantics to cm_forward_step.
// The caller is responsible for checking the channel commitment BEFORE
// calling this (see channel-check semantics in the header comment).
cm_forward_step_rc_t cm_forward_v1_step(cm_forward_v1_t *fwd,
                                         uint8_t out_next_mac[6]);

#ifdef __cplusplus
}
#endif
