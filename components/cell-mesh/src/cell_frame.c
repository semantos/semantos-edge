// cell_frame.c — fragmentation + reassembly of canonical cells over
// ESP-NOW. Pure C, no IDF dependency.

#include "cell_frame.h"
#include "cell_wire.h"  // for cm_read_u16 / cm_write_u32 / etc.

#include <string.h>

// ── Header offsets within a frame ──────────────────────────────────────
#define FH_MAGIC         0u   // 2 bytes
#define FH_FLAGS         2u   // 1 byte
#define FH_FRAME_SEQ     3u   // 1 byte
#define FH_FRAME_COUNT   4u   // 1 byte
#define FH_RESERVED      5u   // 1 byte
#define FH_CELL_ID       6u   // 4 bytes
#define FH_CELL_OFFSET  10u   // 2 bytes
// payload follows at offset 12

// ── Sender side ────────────────────────────────────────────────────────

size_t cm_frame_split(const uint8_t cell[CM_CELL_SIZE],
                      const uint8_t sig[CM_FRAME_SIG_SIZE],
                      uint32_t cell_id,
                      cm_frame_t out_frames[CM_FRAMES_PER_CELL]) {
    if (!cell || !sig || !out_frames) return 0;

    // Concatenate (cell || sig) into the wire payload, then chunk.
    // We build each frame's bytes in-place via two memcpys to avoid an
    // intermediate 1088-byte buffer (saves stack on MCU).
    for (size_t i = 0; i < CM_FRAMES_PER_CELL; i++) {
        cm_frame_t *f = &out_frames[i];

        const uint16_t offset = (uint16_t)(i * CM_FRAME_MAX_PAYLOAD);
        const uint16_t remaining = (offset < CM_FRAME_SIGNED_CELL)
            ? (CM_FRAME_SIGNED_CELL - offset)
            : 0;
        const uint16_t payload_len = (remaining > CM_FRAME_MAX_PAYLOAD)
            ? CM_FRAME_MAX_PAYLOAD
            : remaining;

        // Header.
        cm_write_u16(f->bytes + FH_MAGIC,        CM_FRAME_MAGIC);
        f->bytes[FH_FLAGS]        = CM_FRAME_FLAG_SIGNED;
        f->bytes[FH_FRAME_SEQ]    = (uint8_t)i;
        f->bytes[FH_FRAME_COUNT]  = (uint8_t)CM_FRAMES_PER_CELL;
        f->bytes[FH_RESERVED]     = 0;
        cm_write_u32(f->bytes + FH_CELL_ID,      cell_id);
        cm_write_u16(f->bytes + FH_CELL_OFFSET,  offset);

        // Payload — slice from (cell || sig) by offset.
        // Region [0, CM_CELL_SIZE) maps to `cell`; [CM_CELL_SIZE, 1088) maps to `sig`.
        uint16_t written = 0;
        uint16_t src_offset = offset;
        uint16_t to_write   = payload_len;

        // Part 1: bytes still inside the cell buffer.
        if (src_offset < CM_CELL_SIZE) {
            uint16_t from_cell = CM_CELL_SIZE - src_offset;
            if (from_cell > to_write) from_cell = to_write;
            memcpy(f->bytes + CM_FRAME_HEADER_SIZE + written,
                   cell + src_offset, from_cell);
            written    += from_cell;
            src_offset += from_cell;
            to_write   -= from_cell;
        }
        // Part 2: bytes that fall in the sig region.
        if (to_write > 0) {
            uint16_t sig_offset = src_offset - CM_CELL_SIZE;
            memcpy(f->bytes + CM_FRAME_HEADER_SIZE + written,
                   sig + sig_offset, to_write);
            written += to_write;
        }

        f->len = CM_FRAME_HEADER_SIZE + written;
    }
    return CM_FRAMES_PER_CELL;
}

// ── Receiver side ──────────────────────────────────────────────────────

void cm_reasm_init(cm_reasm_t *r) {
    if (!r) return;
    memset(r, 0, sizeof(*r));
}

// Find an existing slot for (sender_mac, cell_id), or allocate a free
// one. If no free slot, evict the oldest (TTL-pressured).
static cm_reasm_slot_t *acquire_slot(cm_reasm_t *r,
                                     const uint8_t sender_mac[6],
                                     uint32_t cell_id,
                                     uint64_t now_ms) {
    cm_reasm_slot_t *match     = NULL;
    cm_reasm_slot_t *free_slot = NULL;
    cm_reasm_slot_t *oldest    = NULL;
    uint64_t oldest_age = 0;

    for (size_t i = 0; i < CM_REASM_SLOTS; i++) {
        cm_reasm_slot_t *s = &r->slots[i];
        if (s->occupied) {
            // TTL evict in-flight stale entries before the table fills.
            if (now_ms > s->first_seen_ms &&
                (now_ms - s->first_seen_ms) > CM_REASM_TTL_MS) {
                s->occupied = false;
                r->total_dropped++;
            }
        }
        if (s->occupied
            && memcmp(s->sender_mac, sender_mac, 6) == 0
            && s->cell_id == cell_id) {
            match = s;
            break;
        }
        if (!s->occupied && !free_slot) {
            free_slot = s;
        }
        if (s->occupied) {
            uint64_t age = (now_ms > s->first_seen_ms)
                ? (now_ms - s->first_seen_ms) : 0;
            if (!oldest || age > oldest_age) {
                oldest = s;
                oldest_age = age;
            }
        }
    }

    if (match) return match;
    if (free_slot) {
        memcpy(free_slot->sender_mac, sender_mac, 6);
        free_slot->cell_id = cell_id;
        free_slot->frame_count = 0;
        free_slot->received_mask = 0;
        free_slot->first_seen_ms = now_ms;
        free_slot->occupied = true;
        memset(free_slot->buf, 0, sizeof(free_slot->buf));
        return free_slot;
    }
    if (oldest) {
        // Forced eviction: table is full, this incoming cell is fresher
        // than the oldest pending one.
        memcpy(oldest->sender_mac, sender_mac, 6);
        oldest->cell_id = cell_id;
        oldest->frame_count = 0;
        oldest->received_mask = 0;
        oldest->first_seen_ms = now_ms;
        memset(oldest->buf, 0, sizeof(oldest->buf));
        r->total_dropped++;
        return oldest;
    }
    return NULL;
}

cm_reasm_result_t cm_reasm_push(cm_reasm_t *r,
                                const uint8_t *frame_bytes,
                                size_t frame_len,
                                const uint8_t sender_mac[6],
                                uint64_t now_ms,
                                uint8_t out_cell[CM_CELL_SIZE],
                                uint8_t out_sig[CM_FRAME_SIG_SIZE]) {
    if (!r || !frame_bytes) return CM_REASM_BAD_FRAME;
    if (frame_len < CM_FRAME_HEADER_SIZE) {
        r->total_bad_frame++;
        return CM_REASM_BAD_FRAME;
    }
    if (cm_read_u16(frame_bytes + FH_MAGIC) != CM_FRAME_MAGIC) {
        r->total_bad_frame++;
        return CM_REASM_BAD_FRAME;
    }

    uint8_t  frame_seq    = frame_bytes[FH_FRAME_SEQ];
    uint8_t  frame_count  = frame_bytes[FH_FRAME_COUNT];
    uint32_t cell_id      = cm_read_u32(frame_bytes + FH_CELL_ID);
    uint16_t cell_offset  = cm_read_u16(frame_bytes + FH_CELL_OFFSET);
    size_t   payload_len  = frame_len - CM_FRAME_HEADER_SIZE;

    if (frame_count == 0 || frame_count > 8) {
        r->total_bad_frame++;
        return CM_REASM_BAD_FRAME;
    }
    if (frame_seq >= frame_count) {
        r->total_bad_frame++;
        return CM_REASM_BAD_FRAME;
    }
    if ((size_t)cell_offset + payload_len > CM_FRAME_SIGNED_CELL) {
        r->total_bad_frame++;
        return CM_REASM_BAD_FRAME;
    }

    r->total_pushed++;

    cm_reasm_slot_t *slot = acquire_slot(r, sender_mac, cell_id, now_ms);
    if (!slot) return CM_REASM_BAD_FRAME;

    if (slot->frame_count == 0) {
        slot->frame_count = frame_count;
    } else if (slot->frame_count != frame_count) {
        // Sender lied about frame_count between frames; treat as bad.
        slot->occupied = false;
        r->total_bad_frame++;
        return CM_REASM_BAD_FRAME;
    }

    // Idempotent: re-receiving the same frame is a no-op.
    memcpy(slot->buf + cell_offset, frame_bytes + CM_FRAME_HEADER_SIZE, payload_len);
    slot->received_mask |= (uint8_t)(1u << frame_seq);

    // Complete when all frames in the frame_count window are received.
    uint8_t expected_mask = (uint8_t)((1u << frame_count) - 1u);
    if ((slot->received_mask & expected_mask) == expected_mask) {
        if (out_cell) memcpy(out_cell, slot->buf, CM_CELL_SIZE);
        if (out_sig)  memcpy(out_sig,  slot->buf + CM_CELL_SIZE, CM_FRAME_SIG_SIZE);
        slot->occupied = false;
        r->total_reassembled++;
        return CM_REASM_COMPLETE;
    }
    return CM_REASM_INCOMPLETE;
}
