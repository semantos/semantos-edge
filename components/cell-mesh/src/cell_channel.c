// cell_channel.c — payment-channel state machine with linearity
// enforcement. Pure C, no IDF dependency.

#include "cell_channel.h"
#include "cell_wire.h"

#include <string.h>

// ── Wire encoding offsets ──────────────────────────────────────────────

// channel_open (61 bytes)
#define O_OFF_CHANNEL_ID         0u
#define O_OFF_PEER_PUBKEY        16u
#define O_OFF_LOCKTIME_MS        49u
#define O_OFF_CAPACITY           57u

// channel_commitment (68 bytes)
#define C_OFF_CHANNEL_ID         0u
#define C_OFF_SEQ                16u
#define C_OFF_DEVICE_SHARE       20u
#define C_OFF_USER_SHARE         24u
#define C_OFF_EXPIRY_MS          28u
#define C_OFF_CERT_HASH          36u  // 32 bytes — SHA-256(cap cert payload)

// channel_close (24 bytes)
#define K_OFF_CHANNEL_ID         0u
#define K_OFF_FINAL_SEQ          16u
#define K_OFF_FINAL_DEVICE_SHARE 20u

// ── Encoders ──────────────────────────────────────────────────────────

int cm_channel_open_encode(const cm_channel_open_t *in,
                           uint8_t out[CM_CHANNEL_OPEN_PAYLOAD_BYTES]) {
    if (!in || !out) return -1;
    memcpy(out + O_OFF_CHANNEL_ID,  in->channel_id,  16);
    memcpy(out + O_OFF_PEER_PUBKEY, in->peer_pubkey, 33);
    cm_write_u64(out + O_OFF_LOCKTIME_MS, in->initial_locktime_ms);
    cm_write_u32(out + O_OFF_CAPACITY,    in->total_capacity);
    return 0;
}

int cm_channel_open_decode(const uint8_t in[CM_CHANNEL_OPEN_PAYLOAD_BYTES],
                           cm_channel_open_t *out) {
    if (!in || !out) return -1;
    memcpy(out->channel_id,  in + O_OFF_CHANNEL_ID,  16);
    memcpy(out->peer_pubkey, in + O_OFF_PEER_PUBKEY, 33);
    out->initial_locktime_ms = cm_read_u64(in + O_OFF_LOCKTIME_MS);
    out->total_capacity      = cm_read_u32(in + O_OFF_CAPACITY);
    return 0;
}

int cm_channel_commitment_encode(const cm_channel_commitment_t *in,
                                 uint8_t out[CM_CHANNEL_COMMITMENT_PAYLOAD_BYTES]) {
    if (!in || !out) return -1;
    memcpy(out + C_OFF_CHANNEL_ID, in->channel_id, 16);
    cm_write_u32(out + C_OFF_SEQ,          in->seq);
    cm_write_u32(out + C_OFF_DEVICE_SHARE, in->device_share);
    cm_write_u32(out + C_OFF_USER_SHARE,   in->user_share);
    cm_write_u64(out + C_OFF_EXPIRY_MS,    in->expiry_ms);
    memcpy(out + C_OFF_CERT_HASH, in->cert_hash, 32);
    return 0;
}

int cm_channel_commitment_decode(const uint8_t in[CM_CHANNEL_COMMITMENT_PAYLOAD_BYTES],
                                 cm_channel_commitment_t *out) {
    if (!in || !out) return -1;
    memcpy(out->channel_id, in + C_OFF_CHANNEL_ID, 16);
    out->seq          = cm_read_u32(in + C_OFF_SEQ);
    out->device_share = cm_read_u32(in + C_OFF_DEVICE_SHARE);
    out->user_share   = cm_read_u32(in + C_OFF_USER_SHARE);
    out->expiry_ms    = cm_read_u64(in + C_OFF_EXPIRY_MS);
    memcpy(out->cert_hash, in + C_OFF_CERT_HASH, 32);
    return 0;
}

int cm_channel_close_encode(const cm_channel_close_t *in,
                            uint8_t out[CM_CHANNEL_CLOSE_PAYLOAD_BYTES]) {
    if (!in || !out) return -1;
    memcpy(out + K_OFF_CHANNEL_ID, in->channel_id, 16);
    cm_write_u32(out + K_OFF_FINAL_SEQ,           in->final_seq);
    cm_write_u32(out + K_OFF_FINAL_DEVICE_SHARE,  in->final_device_share);
    return 0;
}

int cm_channel_close_decode(const uint8_t in[CM_CHANNEL_CLOSE_PAYLOAD_BYTES],
                            cm_channel_close_t *out) {
    if (!in || !out) return -1;
    memcpy(out->channel_id, in + K_OFF_CHANNEL_ID, 16);
    out->final_seq          = cm_read_u32(in + K_OFF_FINAL_SEQ);
    out->final_device_share = cm_read_u32(in + K_OFF_FINAL_DEVICE_SHARE);
    return 0;
}

// ── State machine ─────────────────────────────────────────────────────

void cm_channel_init(cm_channel_t *c) {
    if (!c) return;
    memset(c, 0, sizeof(*c));
    c->state = CM_CHAN_CLOSED;
}

cm_channel_rc_t cm_channel_apply_open(cm_channel_t *c,
                                       const cm_channel_open_t *op) {
    if (!c || !op) return CM_CHAN_ERR_BAD_STATE;
    if (c->state != CM_CHAN_CLOSED) return CM_CHAN_ERR_BAD_STATE;

    memcpy(c->channel_id,  op->channel_id,  16);
    memcpy(c->peer_pubkey, op->peer_pubkey, 33);
    c->total_capacity   = op->total_capacity;
    c->open_locktime_ms = op->initial_locktime_ms;

    // Reset commitment fields — no commitment yet.
    c->current_seq         = 0;
    c->device_share        = 0;
    c->user_share          = 0;
    c->expiry_ms           = 0;

    c->state = CM_CHAN_OPEN;
    return CM_CHAN_OK;
}

cm_channel_rc_t cm_channel_apply_commitment(cm_channel_t *c,
                                             const cm_channel_commitment_t *cm,
                                             uint64_t now_ms) {
    if (!c || !cm) return CM_CHAN_ERR_BAD_STATE;
    if (c->state != CM_CHAN_OPEN && c->state != CM_CHAN_ACTIVE) {
        c->commitments_rejected++;
        return CM_CHAN_ERR_BAD_STATE;
    }
    if (memcmp(c->channel_id, cm->channel_id, 16) != 0) {
        c->commitments_rejected++;
        return CM_CHAN_ERR_BAD_ID;
    }
    // Linearity: seq must strictly increase.
    if (cm->seq <= c->current_seq) {
        c->commitments_rejected++;
        return CM_CHAN_ERR_STALE_SEQ;
    }
    // Linearity: device_share must monotonically non-decrease.
    if (cm->device_share < c->device_share) {
        c->commitments_rejected++;
        return CM_CHAN_ERR_NON_MONO;
    }
    // Sanity: device + user must not exceed total_capacity.
    if ((uint64_t)cm->device_share + (uint64_t)cm->user_share > (uint64_t)c->total_capacity) {
        c->commitments_rejected++;
        return CM_CHAN_ERR_OVERFLOW;
    }
    // Expiry must be in the future.
    if (cm->expiry_ms <= now_ms) {
        c->commitments_rejected++;
        return CM_CHAN_ERR_EXPIRED;
    }

    c->current_seq  = cm->seq;
    c->device_share = cm->device_share;
    c->user_share   = cm->user_share;
    c->expiry_ms    = cm->expiry_ms;
    c->commitments_received++;
    c->state = CM_CHAN_ACTIVE;
    return CM_CHAN_OK;
}

cm_channel_rc_t cm_channel_apply_close(cm_channel_t *c,
                                        const cm_channel_close_t *cl) {
    if (!c || !cl) return CM_CHAN_ERR_BAD_STATE;
    if (c->state != CM_CHAN_ACTIVE && c->state != CM_CHAN_EXPIRED) {
        return CM_CHAN_ERR_BAD_STATE;
    }
    if (memcmp(c->channel_id, cl->channel_id, 16) != 0) {
        return CM_CHAN_ERR_BAD_ID;
    }
    // Close must reference the current commitment exactly.
    if (cl->final_seq != c->current_seq
        || cl->final_device_share != c->device_share) {
        return CM_CHAN_ERR_SEQ_MATCH;
    }
    c->state = CM_CHAN_CLOSED;
    return CM_CHAN_OK;
}

void cm_channel_tick_expiry(cm_channel_t *c, uint64_t now_ms) {
    if (!c) return;
    if (c->state == CM_CHAN_ACTIVE && now_ms > c->expiry_ms) {
        c->state = CM_CHAN_EXPIRED;
    }
}

// ── BSV on-chain binding helpers ─────────────────────────────────────

bool cm_channel_validate_utxo_ref(const uint8_t channel_id[16],
                                   const uint8_t txid_display[32]) {
    if (!channel_id || !txid_display) return false;
    // channel_id is derived as the first 16 bytes of the funding txid in
    // display (hex) order — the same order ARC /v1/tx returns it.
    return memcmp(channel_id, txid_display, 16) == 0;
}
