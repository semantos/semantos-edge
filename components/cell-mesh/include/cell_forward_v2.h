// cell_forward_v2.h — forward.v2: routing state as a separate continuation cell.
//
// Motivation (see docs/design/SEMANTIC-ROUTING-SUBSTRATE.md §10.5):
//   forward.v1 embeds its 320-byte routing header (48B v0 + 272B hop commitments)
//   directly in the primary cell's payload region, leaving only 448 bytes for
//   application content.  forward.v2 moves routing state to a dedicated
//   "routing continuation" cell so the primary cell recovers its full budget.
//
// ── 2-cell burst protocol ────────────────────────────────────────────────────
//
//   The bridge always sends two 1024-byte cells back-to-back:
//
//   Cell A  (cellmesh.forward.v2)       — primary cell, application content
//   Cell B  (cellmesh.routing.cont.v0)  — routing continuation, routing + payment data
//
//   Cells are correlated by their matching `flow_id[16]`.  Each relay device
//   buffers Cell A until Cell B (same flow_id) arrives, then processes both
//   together.  Re-emission also sends both cells in sequence.
//
// ── Cell A wire layout (768-byte payload region) ─────────────────────────────
//
//   offset  size  field
//   0       16    flow_id               — correlates with Cell B
//   16       1    hop_index             — 0-indexed; advances on each forward step
//   17       1    total_hops
//   18       1    hop_verb              — same encoding as forward.v0/v1
//   19       1    flags                 — bit 0: routing_cont_follows (always 1 for v2)
//   20       4    inner_payload_len     — LE u32; ≤ 744
//   24     ≤744   inner_payload
//
// ── Cell B wire layout (768-byte payload region) ─────────────────────────────
//
//   offset  size  field
//   0       16    flow_id               — must match Cell A's flow_id
//   16       1    hop_index             — must match Cell A's hop_index (sanity)
//   17       1    segments_remaining    — entries left in segments[]; ≤ 4
//   18       6    reserved              — zero
//   24      24    segments[4][6]        — next-hop MACs; unused slots zeroed
//   48     272    hop_commitments[4][68]  — per-hop cm_channel_commitment_t (same as v1)
//                   Each 68-byte slot: channel_id(16) + seq(4) + device_share(4) +
//                   user_share(4) + expiry_ms(8) + cert_hash[32]
//   320     448   (unused / padding)
//
// ── Budget comparison ─────────────────────────────────────────────────────────
//
//   forward.v1:  320B routing header → 448B inner payload headroom
//   forward.v2:    24B primary header → 744B inner payload headroom  (+296 bytes)
//
// Zig-backed C ABI, no IDF dependency — host-testable.

#pragma once

#include "cell_forward.h"
#include "cell_channel.h"

#ifdef __cplusplus
extern "C" {
#endif

// ── Type name strings (SHA-256 hashed at init time) ──────────────────────────

#define CM_FORWARD_V2_TYPE_NAME       "cellmesh.forward.v2"
#define CM_ROUTING_CONT_V0_TYPE_NAME  "cellmesh.routing.cont.v0"

// ── Cell A: primary constants ─────────────────────────────────────────────────

#define CM_FORWARD_V2_HEADER_BYTES     24u
#define CM_FORWARD_V2_MAX_INNER_BYTES  (CM_PAYLOAD_SIZE - CM_FORWARD_V2_HEADER_BYTES)  // 744

// flags byte (Cell A offset 19)
#define CM_FWD_V2_FLAG_ROUTING_CONT   0x01u   // routing continuation cell follows

// ── Cell B: routing continuation constants ───────────────────────────────────

// Each commitment slot is the same 68-byte layout as forward.v1.
#define CM_ROUTING_CONT_COMMIT_SLOT_BYTES  68u
#define CM_ROUTING_CONT_COMMIT_ARRAY_BYTES \
    (CM_FORWARD_MAX_HOPS * CM_ROUTING_CONT_COMMIT_SLOT_BYTES)   // 272

// Offset of the segments array in Cell B payload
#define CM_ROUTING_CONT_OFF_SEGMENTS    24u
// Offset of the commitments array in Cell B payload
#define CM_ROUTING_CONT_OFF_COMMITS     48u
// Total bytes of routing data in Cell B payload (fixed)
#define CM_ROUTING_CONT_USED_BYTES      320u

// ── Structs ───────────────────────────────────────────────────────────────────

// Cell A — application payload carrier
typedef struct {
    uint8_t       flow_id[16];
    uint8_t       hop_index;
    uint8_t       total_hops;
    cm_hop_verb_t hop_verb;
    uint8_t       flags;             // CM_FWD_V2_FLAG_ROUTING_CONT always set
    uint32_t      inner_payload_len; // bytes of inner_payload that are valid
    uint8_t       inner_payload[CM_FORWARD_V2_MAX_INNER_BYTES];
} cm_forward_v2_t;

// Cell B — routing and payment continuation
typedef struct {
    uint8_t                  flow_id[16];
    uint8_t                  hop_index;          // must match Cell A
    uint8_t                  segments_remaining; // entries in segments[] that are valid
    uint8_t                  reserved[6];
    uint8_t                  segments[CM_FORWARD_MAX_HOPS][6];
    cm_channel_commitment_t  hop_commitments[CM_FORWARD_MAX_HOPS];
} cm_routing_cont_t;

// ── Codec: Cell A ─────────────────────────────────────────────────────────────

// Encode a cm_forward_v2_t into the 768-byte cell payload region.
// Returns 0 on success, -1 on NULL / inner_payload_len > 744.
// *out_used = CM_FORWARD_V2_HEADER_BYTES + inner_payload_len on success.
int cm_forward_v2_encode(const cm_forward_v2_t *in,
                         uint8_t out[CM_PAYLOAD_SIZE],
                         size_t *out_used);

// Decode from the 768-byte cell payload region.
// Returns 0 on success, -1 on NULL / bad header.
int cm_forward_v2_decode(const uint8_t in[CM_PAYLOAD_SIZE],
                         size_t in_used,
                         cm_forward_v2_t *out);

// ── Codec: Cell B ─────────────────────────────────────────────────────────────

// Encode a cm_routing_cont_t into the 768-byte cell payload region.
// Returns 0 on success, -1 on NULL / segments_remaining > 4.
// *out_used = CM_ROUTING_CONT_USED_BYTES on success (always 320).
int cm_routing_cont_encode(const cm_routing_cont_t *in,
                           uint8_t out[CM_PAYLOAD_SIZE],
                           size_t *out_used);

// Decode from the 768-byte cell payload region.
// Returns 0 on success, -1 on NULL / segments_remaining > 4.
int cm_routing_cont_decode(const uint8_t in[CM_PAYLOAD_SIZE],
                           size_t in_used,
                           cm_routing_cont_t *out);

// ── Burst step ────────────────────────────────────────────────────────────────

// Process a fully-paired (Cell A + Cell B) forward.v2 burst.
// Advances both cells by one hop:
//   - If routing->segments_remaining == 0: delivers locally (returns DELIVERED).
//   - Otherwise: pops segments[0] → out_next_mac, shifts segments left,
//     decrements segments_remaining, increments hop_index in both structs.
//     Returns NEXT; caller re-encodes and re-emits both cells.
//
// Does NOT perform channel commitment verification — the caller MUST call
// cm_channel_apply_commitment(&my_channel, &routing->hop_commitments[hop],
// now_ms) BEFORE this function and DROP if the result is not CM_CHAN_OK.
cm_forward_step_rc_t cm_forward_v2_step(cm_forward_v2_t *primary,
                                         cm_routing_cont_t *routing,
                                         uint8_t out_next_mac[6]);

#ifdef __cplusplus
}
#endif
