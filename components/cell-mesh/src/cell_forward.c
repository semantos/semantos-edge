// cell_forward.c — SRv6-style cell-routed forwarding. Pure C.

#include "cell_forward.h"
#include "cell_wire.h"

#include <string.h>

// ── Header field offsets ─────────────────────────────────────────────
#define F_OFF_FLOW_ID            0u
#define F_OFF_HOP_INDEX          16u
#define F_OFF_TOTAL_HOPS         17u
#define F_OFF_SEGMENTS_REMAINING 18u
#define F_OFF_HOP_VERB           19u   // was reserved=0; now carries cm_hop_verb_t
#define F_OFF_INNER_PAYLOAD_LEN  20u
#define F_OFF_SEGMENTS           24u   // 24 bytes (4 × 6)
#define F_OFF_INNER_PAYLOAD      48u

int cm_forward_encode(const cm_forward_t *in,
                      uint8_t out[CM_PAYLOAD_SIZE],
                      size_t *out_used) {
    if (!in || !out || !out_used) return -1;
    if (in->inner_payload_len > CM_FORWARD_MAX_INNER_BYTES) return -1;
    if (in->segments_remaining > CM_FORWARD_MAX_HOPS) return -1;

    memcpy(out + F_OFF_FLOW_ID, in->flow_id, 16);
    out[F_OFF_HOP_INDEX]          = in->hop_index;
    out[F_OFF_TOTAL_HOPS]         = in->total_hops;
    out[F_OFF_SEGMENTS_REMAINING] = in->segments_remaining;
    out[F_OFF_HOP_VERB]           = (uint8_t)in->hop_verb;
    cm_write_u32(out + F_OFF_INNER_PAYLOAD_LEN, in->inner_payload_len);

    for (size_t i = 0; i < CM_FORWARD_MAX_HOPS; i++) {
        memcpy(out + F_OFF_SEGMENTS + i * 6, in->segments[i], 6);
    }

    if (in->inner_payload_len > 0) {
        memcpy(out + F_OFF_INNER_PAYLOAD, in->inner_payload, in->inner_payload_len);
    }

    *out_used = F_OFF_INNER_PAYLOAD + in->inner_payload_len;
    return 0;
}

int cm_forward_decode(const uint8_t in[CM_PAYLOAD_SIZE],
                      size_t in_used,
                      cm_forward_t *out) {
    if (!in || !out) return -1;
    if (in_used < CM_FORWARD_HEADER_BYTES) return -1;

    memset(out, 0, sizeof(*out));
    memcpy(out->flow_id, in + F_OFF_FLOW_ID, 16);
    out->hop_index          = in[F_OFF_HOP_INDEX];
    out->total_hops         = in[F_OFF_TOTAL_HOPS];
    out->segments_remaining = in[F_OFF_SEGMENTS_REMAINING];
    out->hop_verb           = (cm_hop_verb_t)in[F_OFF_HOP_VERB];
    out->inner_payload_len  = cm_read_u32(in + F_OFF_INNER_PAYLOAD_LEN);

    if (out->segments_remaining > CM_FORWARD_MAX_HOPS) return -1;
    if (out->inner_payload_len > CM_FORWARD_MAX_INNER_BYTES) return -1;
    if (CM_FORWARD_HEADER_BYTES + (size_t)out->inner_payload_len > in_used) return -1;

    for (size_t i = 0; i < CM_FORWARD_MAX_HOPS; i++) {
        memcpy(out->segments[i], in + F_OFF_SEGMENTS + i * 6, 6);
    }

    if (out->inner_payload_len > 0) {
        memcpy(out->inner_payload, in + F_OFF_INNER_PAYLOAD, out->inner_payload_len);
    }
    return 0;
}

cm_forward_step_rc_t cm_forward_step(cm_forward_t *fwd, uint8_t out_next_mac[6]) {
    if (!fwd) return CM_FWD_ERR_BAD;

    // Pre-pop: no segments to consume → already at the destination (or
    // a no-route originator that auto-delivers).
    if (fwd->segments_remaining == 0) {
        if (out_next_mac) memset(out_next_mac, 0, 6);
        return CM_FWD_DELIVERED;
    }

    if (fwd->segments_remaining > CM_FORWARD_MAX_HOPS) return CM_FWD_ERR_BAD;

    // Pop segments[0] (the "this hop's marker" — the device just arrived
    // here, so it removes itself from the downstream route). Shift left.
    for (size_t i = 0; i + 1 < CM_FORWARD_MAX_HOPS; i++) {
        memcpy(fwd->segments[i], fwd->segments[i + 1], 6);
    }
    memset(fwd->segments[CM_FORWARD_MAX_HOPS - 1], 0, 6);

    fwd->segments_remaining -= 1;
    fwd->hop_index          += 1;

    // Post-pop: if no more segments, this hop was the final destination —
    // deliver. Otherwise out_next_mac is the new segments[0] (the next
    // downstream hop to re-emit toward).
    if (fwd->segments_remaining == 0) {
        if (out_next_mac) memset(out_next_mac, 0, 6);
        return CM_FWD_DELIVERED;
    }
    if (out_next_mac) memcpy(out_next_mac, fwd->segments[0], 6);
    return CM_FWD_NEXT;
}
