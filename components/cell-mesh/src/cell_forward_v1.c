// cell_forward_v1.c — channel-gated SRv6 forwarding codec. Pure C.

#include "cell_forward_v1.h"
#include "cell_wire.h"

#include <string.h>

// ── Field offsets (same as v0 for 0-47; commitment array is new at 48) ──
#define F1_OFF_FLOW_ID            0u
#define F1_OFF_HOP_INDEX          16u
#define F1_OFF_TOTAL_HOPS         17u
#define F1_OFF_SEGMENTS_REMAINING 18u
#define F1_OFF_HOP_VERB           19u
#define F1_OFF_INNER_PAYLOAD_LEN  20u
#define F1_OFF_SEGMENTS           24u   // 24 bytes (4 × 6)
#define F1_OFF_COMMITMENTS        48u   // 272 bytes (4 × 68 — includes cert_hash[32])
#define F1_OFF_INNER_PAYLOAD      320u  // 48 + 272

// Each commitment slot is CM_CHANNEL_COMMITMENT_PAYLOAD_BYTES = 68 bytes.
// Verify the layout matches at compile time.
_Static_assert(CM_FORWARD_V1_HEADER_BYTES == F1_OFF_INNER_PAYLOAD,
               "v1 header size mismatch");
_Static_assert(CM_FORWARD_V1_COMMIT_SLOT_BYTES == CM_CHANNEL_COMMITMENT_PAYLOAD_BYTES,
               "commitment slot size mismatch");

int cm_forward_v1_encode(const cm_forward_v1_t *in,
                         uint8_t out[CM_PAYLOAD_SIZE],
                         size_t *out_used) {
    if (!in || !out || !out_used) return -1;
    if (in->inner_payload_len > CM_FORWARD_V1_MAX_INNER_BYTES) return -1;
    if (in->segments_remaining > CM_FORWARD_MAX_HOPS) return -1;

    // ── v0-compatible header (bytes 0-47) ────────────────────────────
    memcpy(out + F1_OFF_FLOW_ID, in->flow_id, 16);
    out[F1_OFF_HOP_INDEX]          = in->hop_index;
    out[F1_OFF_TOTAL_HOPS]         = in->total_hops;
    out[F1_OFF_SEGMENTS_REMAINING] = in->segments_remaining;
    out[F1_OFF_HOP_VERB]           = (uint8_t)in->hop_verb;
    cm_write_u32(out + F1_OFF_INNER_PAYLOAD_LEN, in->inner_payload_len);
    for (size_t i = 0; i < CM_FORWARD_MAX_HOPS; i++) {
        memcpy(out + F1_OFF_SEGMENTS + i * 6, in->segments[i], 6);
    }

    // ── per-hop commitment array (bytes 48-319) ───────────────────────
    for (size_t i = 0; i < CM_FORWARD_MAX_HOPS; i++) {
        cm_channel_commitment_encode(
            &in->hop_commitments[i],
            out + F1_OFF_COMMITMENTS + i * CM_FORWARD_V1_COMMIT_SLOT_BYTES);
    }

    // ── inner payload ─────────────────────────────────────────────────
    if (in->inner_payload_len > 0) {
        memcpy(out + F1_OFF_INNER_PAYLOAD, in->inner_payload, in->inner_payload_len);
    }

    *out_used = F1_OFF_INNER_PAYLOAD + in->inner_payload_len;
    return 0;
}

int cm_forward_v1_decode(const uint8_t in[CM_PAYLOAD_SIZE],
                         size_t in_used,
                         cm_forward_v1_t *out) {
    if (!in || !out) return -1;
    if (in_used < CM_FORWARD_V1_HEADER_BYTES) return -1;

    memset(out, 0, sizeof(*out));

    // ── v0-compatible header (bytes 0-47) ────────────────────────────
    memcpy(out->flow_id, in + F1_OFF_FLOW_ID, 16);
    out->hop_index          = in[F1_OFF_HOP_INDEX];
    out->total_hops         = in[F1_OFF_TOTAL_HOPS];
    out->segments_remaining = in[F1_OFF_SEGMENTS_REMAINING];
    out->hop_verb           = (cm_hop_verb_t)in[F1_OFF_HOP_VERB];
    out->inner_payload_len  = cm_read_u32(in + F1_OFF_INNER_PAYLOAD_LEN);

    if (out->segments_remaining > CM_FORWARD_MAX_HOPS) return -1;
    if (out->inner_payload_len  > CM_FORWARD_V1_MAX_INNER_BYTES) return -1;
    if (CM_FORWARD_V1_HEADER_BYTES + (size_t)out->inner_payload_len > in_used) return -1;

    for (size_t i = 0; i < CM_FORWARD_MAX_HOPS; i++) {
        memcpy(out->segments[i], in + F1_OFF_SEGMENTS + i * 6, 6);
    }

    // ── per-hop commitment array (bytes 48-319) ───────────────────────
    for (size_t i = 0; i < CM_FORWARD_MAX_HOPS; i++) {
        if (cm_channel_commitment_decode(
                in + F1_OFF_COMMITMENTS + i * CM_FORWARD_V1_COMMIT_SLOT_BYTES,
                &out->hop_commitments[i]) != 0) {
            return -1;  // shouldn't happen for zeroed slots, but be safe
        }
    }

    // ── inner payload ─────────────────────────────────────────────────
    if (out->inner_payload_len > 0) {
        memcpy(out->inner_payload, in + F1_OFF_INNER_PAYLOAD, out->inner_payload_len);
    }
    return 0;
}

cm_forward_step_rc_t cm_forward_v1_step(cm_forward_v1_t *fwd,
                                         uint8_t out_next_mac[6]) {
    if (!fwd) return CM_FWD_ERR_BAD;

    if (fwd->segments_remaining == 0) {
        if (out_next_mac) memset(out_next_mac, 0, 6);
        return CM_FWD_DELIVERED;
    }
    if (fwd->segments_remaining > CM_FORWARD_MAX_HOPS) return CM_FWD_ERR_BAD;

    // Pop segments[0], shift left (same algorithm as v0).
    for (size_t i = 0; i + 1 < CM_FORWARD_MAX_HOPS; i++) {
        memcpy(fwd->segments[i], fwd->segments[i + 1], 6);
    }
    memset(fwd->segments[CM_FORWARD_MAX_HOPS - 1], 0, 6);

    fwd->segments_remaining -= 1;
    fwd->hop_index          += 1;

    if (fwd->segments_remaining == 0) {
        if (out_next_mac) memset(out_next_mac, 0, 6);
        return CM_FWD_DELIVERED;
    }
    if (out_next_mac) memcpy(out_next_mac, fwd->segments[0], 6);
    return CM_FWD_NEXT;
}
