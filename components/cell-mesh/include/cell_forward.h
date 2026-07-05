// cell_forward.h — SRv6-style cell-routed forwarding.
//
// A `cellmesh.forward.v0` cell carries an opaque inner payload plus
// a `segments` list of next-hop MAC addresses. At each hop:
//
//   1. The receiving device decodes the forward cell.
//   2. It pops segments[0] — that's the next hop's MAC.
//   3. If segments_remaining was 0 before pop, this hop is the
//      destination; the inner payload is delivered locally.
//   4. Otherwise the device re-encodes the cell (segments shifted,
//      hop_index incremented) and broadcasts it; the next hop's
//      ESP-NOW MAC filter picks it up.
//
// This is the routing half. The payment half (channel commitments
// debited at each hop) lives in cell_channel — combining them is
// what gives you incentivized mesh forwarding. This module is
// trust-checkable per-hop on its own (each hop verifies the cell
// signature before forwarding); the channel side adds the economic
// constraint that a forwarding device only forwards if upstream paid.
//
// Wire format of the cell payload (48-byte header + variable inner):
//
//   offset  size  field
//   0       16    flow_id              — end-to-end flow identifier
//   16      1     hop_index            — 0-indexed; advances on each forward step
//   17      1     total_hops           — expected total hops (encoded by source)
//   18      1     segments_remaining   — entries left in segments[]; capped at 4
//   19      1     hop_verb             — side-effect applied at EVERY hop (0 = none)
//   20      4     inner_payload_len    — LE; ≤ 720
//   24      24    segments[4][6]       — next-hop MACs; unused slots zeroed
//   48      ≤720  inner_payload
//
// hop_verb semantics (applied at every intermediate hop AND the destination):
//
//   CM_HOP_VERB_NONE         (0)  pure routing, no side-effect [default; was reserved=0]
//   CM_HOP_VERB_EVAL_RULES   (1)  evaluate local tap rules at this hop → blink wave visible
//                                 across the path as the cell traverses device-by-device
//   CM_HOP_VERB_INSTALL_RULE (2)  install inner_payload as a rule on this hop; inner_payload
//                                 must be ≥ CM_RULE_ENCODED_SIZE bytes encoded by cm_rule_encode.
//                                 "reprogram every node in the path with one broadcast"
//
// hop_verb is set once by the source and carried unchanged through all hops
// (cm_forward_step does not modify it). Unknown verb values are treated as
// CM_HOP_VERB_NONE — cell still routes normally.
//
// Zig-backed C ABI, no IDF dependency — host-testable. The mesh_demo wires this
// into the receive callback for end-to-end on-device routing.

#pragma once

#include "cell_wire.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CM_FORWARD_MAX_HOPS          4u
#define CM_FORWARD_HEADER_BYTES      48u
#define CM_FORWARD_MAX_INNER_BYTES   720u

// ── hop_verb — per-hop side-effect opcode ────────────────────────────
typedef enum {
    CM_HOP_VERB_NONE         = 0,  // pure routing (default, backward-compat with reserved=0)
    CM_HOP_VERB_EVAL_RULES   = 1,  // fire local tap rules at each hop → blink wave
    CM_HOP_VERB_INSTALL_RULE = 2,  // install inner_payload as a rule (≥139 bytes)
} cm_hop_verb_t;

typedef struct {
    uint8_t       flow_id[16];
    uint8_t       hop_index;
    uint8_t       total_hops;
    uint8_t       segments_remaining;
    cm_hop_verb_t hop_verb;   // carried unchanged across all hops; 0 = no-op
    uint8_t       segments[CM_FORWARD_MAX_HOPS][6];
    uint32_t      inner_payload_len;
    uint8_t       inner_payload[CM_FORWARD_MAX_INNER_BYTES];
} cm_forward_t;

// Encode into the 768-byte cell payload region. `out_used` returns the
// number of bytes actually written (header + inner_payload_len). The
// remainder of `out` is NOT zeroed by this function — the caller (which
// is typically about to memcpy into a cm_cell payload region) should
// memset(out + *out_used, 0, CM_PAYLOAD_SIZE - *out_used) if needed.
// Returns 0 on success, -1 on bad args / inner_payload_len > 720 /
// segments_remaining > MAX_HOPS.
int cm_forward_encode(const cm_forward_t *in,
                      uint8_t out[CM_PAYLOAD_SIZE],
                      size_t *out_used);

// Decode from a 768-byte cell payload region. `in_used` is the actual
// bytes-of-interest (the rest of the cell payload is treated as zero
// padding). Returns 0 on success, -1 on bad args / corrupt header.
int cm_forward_decode(const uint8_t in[CM_PAYLOAD_SIZE],
                      size_t in_used,
                      cm_forward_t *out);

typedef enum {
    CM_FWD_NEXT      =  0,  // segments[0] popped → out_next_mac set; re-emit to that MAC
    CM_FWD_DELIVERED =  1,  // segments_remaining was 0 at entry → inner_payload is the local delivery
    CM_FWD_ERR_BAD   = -1,  // NULL inputs or impossible header state
} cm_forward_step_rc_t;

// Advance the forward cell one hop:
//   - If segments_remaining == 0: deliver locally; return DELIVERED.
//   - Otherwise: copy segments[0] into out_next_mac, shift segments
//     left by one, decrement segments_remaining, increment hop_index;
//     return NEXT.
//
// Caller re-encodes after a NEXT result and broadcasts the new cell.
cm_forward_step_rc_t cm_forward_step(cm_forward_t *fwd, uint8_t out_next_mac[6]);

#ifdef __cplusplus
}
#endif
