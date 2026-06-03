// cell_forward_v2.c — forward.v2 codec + burst step.  Pure C, no IDF dependency.

#include "cell_forward_v2.h"
#include "cell_wire.h"

#include <string.h>

// ── Cell A offsets ────────────────────────────────────────────────────────────
#define A_OFF_FLOW_ID           0u
#define A_OFF_HOP_INDEX         16u
#define A_OFF_TOTAL_HOPS        17u
#define A_OFF_HOP_VERB          18u
#define A_OFF_FLAGS             19u
#define A_OFF_INNER_PAYLOAD_LEN 20u
#define A_OFF_INNER_PAYLOAD     24u

_Static_assert(CM_FORWARD_V2_HEADER_BYTES == A_OFF_INNER_PAYLOAD,
               "v2 primary header size mismatch");
_Static_assert(A_OFF_INNER_PAYLOAD + CM_FORWARD_V2_MAX_INNER_BYTES == CM_PAYLOAD_SIZE,
               "v2 primary inner payload size mismatch");

// ── Cell B offsets ────────────────────────────────────────────────────────────
#define B_OFF_FLOW_ID           0u
#define B_OFF_HOP_INDEX         16u
#define B_OFF_SEGS_REMAINING    17u
#define B_OFF_RESERVED          18u   // 6 bytes
#define B_OFF_SEGMENTS          24u   // 4 × 6 = 24 bytes
#define B_OFF_COMMITS           48u   // 4 × 68 = 272 bytes
#define B_USED                  320u  // CM_ROUTING_CONT_USED_BYTES

_Static_assert(B_OFF_SEGMENTS   == CM_ROUTING_CONT_OFF_SEGMENTS, "seg offset mismatch");
_Static_assert(B_OFF_COMMITS    == CM_ROUTING_CONT_OFF_COMMITS,  "commit offset mismatch");
_Static_assert(B_USED           == CM_ROUTING_CONT_USED_BYTES,   "routing cont size mismatch");
_Static_assert(B_OFF_COMMITS + CM_ROUTING_CONT_COMMIT_ARRAY_BYTES == B_USED,
               "routing cont payload size mismatch");

// ── Cell A encode ─────────────────────────────────────────────────────────────

int cm_forward_v2_encode(const cm_forward_v2_t *in,
                         uint8_t out[CM_PAYLOAD_SIZE],
                         size_t *out_used) {
    if (!in || !out || !out_used) return -1;
    if (in->inner_payload_len > CM_FORWARD_V2_MAX_INNER_BYTES) return -1;

    memcpy(out + A_OFF_FLOW_ID,           in->flow_id, 16);
    out[A_OFF_HOP_INDEX]   = in->hop_index;
    out[A_OFF_TOTAL_HOPS]  = in->total_hops;
    out[A_OFF_HOP_VERB]    = (uint8_t)in->hop_verb;
    out[A_OFF_FLAGS]       = in->flags | CM_FWD_V2_FLAG_ROUTING_CONT;
    cm_write_u32(out + A_OFF_INNER_PAYLOAD_LEN, in->inner_payload_len);

    if (in->inner_payload_len > 0) {
        memcpy(out + A_OFF_INNER_PAYLOAD, in->inner_payload, in->inner_payload_len);
    }

    *out_used = A_OFF_INNER_PAYLOAD + in->inner_payload_len;
    return 0;
}

// ── Cell A decode ─────────────────────────────────────────────────────────────

int cm_forward_v2_decode(const uint8_t in[CM_PAYLOAD_SIZE],
                         size_t in_used,
                         cm_forward_v2_t *out) {
    if (!in || !out) return -1;
    if (in_used < CM_FORWARD_V2_HEADER_BYTES) return -1;

    memset(out, 0, sizeof(*out));

    memcpy(out->flow_id, in + A_OFF_FLOW_ID, 16);
    out->hop_index        = in[A_OFF_HOP_INDEX];
    out->total_hops       = in[A_OFF_TOTAL_HOPS];
    out->hop_verb         = (cm_hop_verb_t)in[A_OFF_HOP_VERB];
    out->flags            = in[A_OFF_FLAGS];
    out->inner_payload_len = cm_read_u32(in + A_OFF_INNER_PAYLOAD_LEN);

    if (out->inner_payload_len > CM_FORWARD_V2_MAX_INNER_BYTES) return -1;
    if (A_OFF_INNER_PAYLOAD + (size_t)out->inner_payload_len > in_used) return -1;

    if (out->inner_payload_len > 0) {
        memcpy(out->inner_payload, in + A_OFF_INNER_PAYLOAD, out->inner_payload_len);
    }
    return 0;
}

// ── Cell B encode ─────────────────────────────────────────────────────────────

int cm_routing_cont_encode(const cm_routing_cont_t *in,
                           uint8_t out[CM_PAYLOAD_SIZE],
                           size_t *out_used) {
    if (!in || !out || !out_used) return -1;
    if (in->segments_remaining > CM_FORWARD_MAX_HOPS) return -1;

    memcpy(out + B_OFF_FLOW_ID,     in->flow_id, 16);
    out[B_OFF_HOP_INDEX]        = in->hop_index;
    out[B_OFF_SEGS_REMAINING]   = in->segments_remaining;
    memset(out + B_OFF_RESERVED, 0, 6);

    for (size_t i = 0; i < CM_FORWARD_MAX_HOPS; i++) {
        memcpy(out + B_OFF_SEGMENTS + i * 6, in->segments[i], 6);
    }
    for (size_t i = 0; i < CM_FORWARD_MAX_HOPS; i++) {
        cm_channel_commitment_encode(
            &in->hop_commitments[i],
            out + B_OFF_COMMITS + i * CM_ROUTING_CONT_COMMIT_SLOT_BYTES);
    }

    *out_used = B_USED;
    return 0;
}

// ── Cell B decode ─────────────────────────────────────────────────────────────

int cm_routing_cont_decode(const uint8_t in[CM_PAYLOAD_SIZE],
                           size_t in_used,
                           cm_routing_cont_t *out) {
    if (!in || !out) return -1;
    if (in_used < B_USED) return -1;

    memset(out, 0, sizeof(*out));

    memcpy(out->flow_id, in + B_OFF_FLOW_ID, 16);
    out->hop_index          = in[B_OFF_HOP_INDEX];
    out->segments_remaining = in[B_OFF_SEGS_REMAINING];

    if (out->segments_remaining > CM_FORWARD_MAX_HOPS) return -1;

    for (size_t i = 0; i < CM_FORWARD_MAX_HOPS; i++) {
        memcpy(out->segments[i], in + B_OFF_SEGMENTS + i * 6, 6);
    }
    for (size_t i = 0; i < CM_FORWARD_MAX_HOPS; i++) {
        cm_channel_commitment_decode(
            in + B_OFF_COMMITS + i * CM_ROUTING_CONT_COMMIT_SLOT_BYTES,
            &out->hop_commitments[i]);
    }
    return 0;
}

// ── Burst step ────────────────────────────────────────────────────────────────

cm_forward_step_rc_t cm_forward_v2_step(cm_forward_v2_t *primary,
                                         cm_routing_cont_t *routing,
                                         uint8_t out_next_mac[6]) {
    if (!primary || !routing || !out_next_mac) return CM_FWD_ERR_BAD;

    // Sanity: hop_index fields must agree
    if (primary->hop_index != routing->hop_index) return CM_FWD_ERR_BAD;

    if (routing->segments_remaining == 0) {
        // This hop is the destination — deliver the inner payload
        return CM_FWD_DELIVERED;
    }

    // Shift segments left by one slot (discarding segments[0] = current relay MAC).
    for (size_t i = 0; i < CM_FORWARD_MAX_HOPS - 1; i++) {
        memcpy(routing->segments[i], routing->segments[i + 1], 6);
    }
    memset(routing->segments[CM_FORWARD_MAX_HOPS - 1], 0, 6);

    routing->segments_remaining--;
    primary->hop_index++;
    routing->hop_index++;   // keep in sync

    // Mirror v1 semantics: DELIVERED when the last segment is consumed
    // (segments_remaining just hit 0 → this device is the destination).
    if (routing->segments_remaining == 0) {
        memset(out_next_mac, 0, 6);
        return CM_FWD_DELIVERED;
    }

    // More hops: next relay MAC is now at segments[0].
    memcpy(out_next_mac, routing->segments[0], 6);
    return CM_FWD_NEXT;
}
