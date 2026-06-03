// cell_frame.h — fragmentation + reassembly of canonical cells over ESP-NOW.
//
// A canonical Semantos cell is 1024 bytes. ESP-NOW frames cap at 250 bytes.
// Cells are also signed with a 64-byte ECDSA-secp256k1 signature appended
// to the cell bytes. So each cell-on-the-wire is 1088 bytes (1024 + 64),
// split across 5 ESP-NOW frames of up to 238 payload bytes each.
//
// Wire format per ESP-NOW frame:
//
//   [ 12-byte frame header ][ up to 238 bytes of (cell + sig) payload ]
//
// Frame header layout (little-endian, all multi-byte fields):
//
//   offset  size  field
//   0       2     magic = 0x5C5C ("cell-mesh frame magic")
//   2       1     flags (bit 0 = signed/unsigned; reserved for future)
//   3       1     frame_seq    — 0..frame_count-1
//   4       1     frame_count  — 1..N (typically 5)
//   5       1     reserved (0)
//   6       4     cell_id      — random per cell, used for reassembly
//   10      2     cell_offset  — byte offset of this frame's payload
//                                inside the full 1088-byte (cell + sig)
//
// Reassembly key: (sender_mac, cell_id). The receiver buffers frames in a
// fixed-size table until all `frame_count` frames have arrived or a TTL
// expires. Out-of-order frames are fine; duplicate frames are idempotent.
//
// Pure C. No IDF dependency — host-testable. ESP-NOW glue lives in
// cell_radio.{h,c}.

#pragma once

#include "cell_wire.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CM_FRAME_MAGIC          0x5C5Cu
#define CM_FRAME_HEADER_SIZE    12u
#define CM_FRAME_MAX_PAYLOAD    238u   // 250 ESP-NOW cap minus header
#define CM_FRAME_SIG_SIZE       64u    // ECDSA-secp256k1 raw r||s
#define CM_FRAME_SIGNED_CELL    (CM_CELL_SIZE + CM_FRAME_SIG_SIZE) // 1088
#define CM_FRAMES_PER_CELL      5u     // ceil(1088 / 238)
#define CM_FRAME_TOTAL_SIZE     (CM_FRAME_HEADER_SIZE + CM_FRAME_MAX_PAYLOAD) // 250

#define CM_FRAME_FLAG_SIGNED    0x01u

// ── Sender side: split a (cell + sig) into ESP-NOW frames ─────────────

typedef struct {
    uint8_t bytes[CM_FRAME_TOTAL_SIZE];
    uint16_t len;  // actual bytes used (last frame is partial)
} cm_frame_t;

// Split a 1024-byte cell + 64-byte signature into 5 ESP-NOW frames.
// `cell_id` should be a fresh random value (the caller picks it — it
// only needs to be unique per-sender within the reassembly TTL window).
// Returns the number of frames produced (CM_FRAMES_PER_CELL on success,
// 0 on bad args).
size_t cm_frame_split(const uint8_t cell[CM_CELL_SIZE],
                      const uint8_t sig[CM_FRAME_SIG_SIZE],
                      uint32_t cell_id,
                      cm_frame_t out_frames[CM_FRAMES_PER_CELL]);

// ── Receiver side: reassembly state ───────────────────────────────────

// How many partially-received cells can be in-flight at once. With three
// XIAOs in a quorum, one per sender + slack is plenty.
#define CM_REASM_SLOTS  6u

typedef struct {
    bool       occupied;
    uint8_t    sender_mac[6];
    uint32_t   cell_id;
    uint8_t    frame_count;
    uint8_t    received_mask;  // bitmask: bit i = frame i received
    uint64_t   first_seen_ms;  // for TTL eviction
    uint8_t    buf[CM_FRAME_SIGNED_CELL]; // assembled cell + sig, in place
} cm_reasm_slot_t;

typedef struct {
    cm_reasm_slot_t slots[CM_REASM_SLOTS];
    uint32_t total_pushed;     // lifetime telemetry
    uint32_t total_reassembled;
    uint32_t total_dropped;    // TTL evictions
    uint32_t total_bad_frame;  // magic mismatch / bad header
} cm_reasm_t;

void cm_reasm_init(cm_reasm_t *r);

// Result of pushing a frame into the reassembler.
typedef enum {
    CM_REASM_INCOMPLETE = 0,  // frame absorbed; more needed
    CM_REASM_COMPLETE,        // this frame completed a cell; out_cell + out_sig set
    CM_REASM_BAD_FRAME,       // header magic/size mismatch
} cm_reasm_result_t;

// Push a single ESP-NOW frame into the reassembler. `now_ms` is the host
// monotonic clock; old in-flight cells are TTL-evicted to keep the table
// from filling up with sender-disappeared partials.
//
// On CM_REASM_COMPLETE, `out_cell` is filled with 1024 bytes of canonical
// cell and `out_sig` with 64 bytes of signature.
cm_reasm_result_t cm_reasm_push(cm_reasm_t *r,
                                const uint8_t *frame_bytes,
                                size_t frame_len,
                                const uint8_t sender_mac[6],
                                uint64_t now_ms,
                                uint8_t out_cell[CM_CELL_SIZE],
                                uint8_t out_sig[CM_FRAME_SIG_SIZE]);

// TTL (ms) — partial cells older than this are evicted when slots fill.
// 1 second is generous: at ESP-NOW broadcast latency (~ms), even on a
// busy mesh all 5 frames should arrive in tens of ms.
#define CM_REASM_TTL_MS  1000u

#ifdef __cplusplus
}
#endif
