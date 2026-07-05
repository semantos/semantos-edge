// cell_mnca.h — MNCA tile compute + incentive quorum for cell-mesh C6 firmware.
//
// Implements the "MNCA incentives" pattern:
//
//   1. Each device maintains a small tile (default 8×8 grid-cells).  On each
//      tick the device applies the MNCA rule and emits an `mnca.tile.v0` cell
//      carrying the next-generation state.
//
//   2. The tile cell IS a forward.v1 inner payload so every hop in the route
//      charges a payment commitment — compute cost = routing fee.
//
//   3. Quorum consensus: the quorum table tracks which (sender MAC, x, y, gen)
//      tuples share the same tile-hash.  When CM_MNCA_QUORUM_K-of-N devices
//      agree on the same tile for a generation, the caller emits a
//      `cellmesh.channel_settle.v0` cell — the economic signal that consensus
//      on this MNCA generation was reached across the mesh.
//
// `mnca.tile.v0` payload layout (matches MncaCellTypeName.TILE_V0 in
// core/protocol-types/src/mnca/cell-types.ts):
//
//   Offset  Size  Field
//   0         2   x           (u16 LE) tile column in global grid
//   2         2   y           (u16 LE) tile row
//   4         4   generation  (u32 LE) MNCA tick counter
//   8         4   rule_id[4]  identifies the rule applied
//   12        4   state_len   (u32 LE) bytes in state_bytes
//   16        N   state_bytes row-major, 1 byte/grid-cell
//
// Zig-backed C ABI, no IDF dependency — host-testable (except the radio broadcast
// path which lives in main.c and uses cm_radio_send_cell).

#pragma once

#include "cell_wire.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── Wire-format constants ─────────────────────────────────────────────────────

#define CM_MNCA_TILE_V0_HDR_BYTES  16u  // header before state_bytes
#define CM_MNCA_MAX_STATE_BYTES    (CM_PAYLOAD_SIZE - CM_MNCA_TILE_V0_HDR_BYTES)  // 752

#define CM_MNCA_TILE_V0_OFF_X           0u
#define CM_MNCA_TILE_V0_OFF_Y           2u
#define CM_MNCA_TILE_V0_OFF_GEN         4u
#define CM_MNCA_TILE_V0_OFF_RULE_ID     8u
#define CM_MNCA_TILE_V0_OFF_STATE_LEN  12u
#define CM_MNCA_TILE_V0_OFF_STATE      16u

// ── Demo tile constants ───────────────────────────────────────────────────────
// An 8×8 interior tile — small enough to compute in < 1 ms on C6, large
// enough to show interesting MNCA dynamics after a few ticks.
#define CM_MNCA_TILE_W    8u
#define CM_MNCA_TILE_H    8u
#define CM_MNCA_TILE_CELLS  (CM_MNCA_TILE_W * CM_MNCA_TILE_H)  // 64

// ── Rule parameters ───────────────────────────────────────────────────────────
// Minimal 2-neighbourhood totalistic rule (integer, deterministic).
// Birth when inner-alive-count in [birthLo, birthHi]; survive when in
// [surviveLo, surviveHi]; state increments by growStep / decrements by decayStep.
typedef struct {
    uint8_t alive_threshold;  // grid-cell >= this is "alive"
    uint8_t inner_radius;     // Moore neighbourhood radius for birth/survive
    uint8_t birth_lo;         // birth if inner alive-count in [lo, hi]
    uint8_t birth_hi;
    uint8_t survive_lo;       // survive if inner alive-count in [lo, hi]
    uint8_t survive_hi;
    uint8_t grow_step;        // +growStep when born or surviving (saturate 255)
    uint8_t decay_step;       // -decayStep when dying (saturate 0)
    uint8_t rule_id[4];       // identifies this rule; baked into tile payload
} cm_mnca_rule_t;

/** Conway-like reference rule (deterministic integer; portable across C6/Pi/Mac). */
extern const cm_mnca_rule_t CM_MNCA_DEFAULT_RULE;

// ── Tile state ────────────────────────────────────────────────────────────────

typedef struct {
    uint16_t x;
    uint16_t y;
    uint32_t generation;
    uint8_t  state[CM_MNCA_TILE_CELLS];  // row-major, 8×8
} cm_mnca_tile_t;

void cm_mnca_tile_init_random(cm_mnca_tile_t *t, uint16_t x, uint16_t y, uint32_t seed);

// Apply one generation of the rule.  Double-buffered: reads current state,
// writes next state into *next.  Returns 0 on success.
int cm_mnca_step(const cm_mnca_tile_t *cur, cm_mnca_tile_t *next, const cm_mnca_rule_t *rule);

// ── Payload encode / decode ───────────────────────────────────────────────────

// Encode tile into a 768-byte CM_PAYLOAD_SIZE payload region.
// Returns the number of bytes written (CM_MNCA_TILE_V0_HDR_BYTES + state_len).
size_t cm_mnca_tile_encode(const cm_mnca_tile_t *t, const cm_mnca_rule_t *rule,
                            uint8_t out[CM_PAYLOAD_SIZE]);

// Decode a payload region into a tile.  Returns 0 on success, -1 on bad data.
int cm_mnca_tile_decode(const uint8_t *payload, size_t payload_len, cm_mnca_tile_t *out);

// Compute the tile state hash (SHA-256 of state_bytes only, not the header).
// `out_hash` receives 32 bytes.  Uses the Zig core SHA-256 — no mbedTLS.
void cm_mnca_tile_hash(const cm_mnca_tile_t *t, uint8_t out_hash[32]);

// ── Quorum table ──────────────────────────────────────────────────────────────

// Quorum slot: tracks one device's tile submission for a given (x, y, gen).
#define CM_MNCA_QUORUM_SLOTS  4u   // max concurrent (x, y, gen) windows tracked
#define CM_MNCA_QUORUM_K      2u   // k-of-n to fire (2 devices must agree)
#define CM_MNCA_QUORUM_TTL_MS 60000u  // evict unresolved windows after 60 s (covers ~20 periods)

typedef struct {
    bool     valid;
    uint16_t x;
    uint16_t y;
    uint32_t generation;
    // Parallel arrays — up to CM_MNCA_QUORUM_K+1 entries.
    uint8_t  seen_count;
    uint8_t  tile_hash[CM_MNCA_QUORUM_K + 1][32];  // hashes seen so far
    uint8_t  sender_mac[CM_MNCA_QUORUM_K + 1][6];  // which device sent which
    uint64_t first_seen_ms;
} cm_mnca_quorum_slot_t;

typedef struct {
    cm_mnca_quorum_slot_t slots[CM_MNCA_QUORUM_SLOTS];
} cm_mnca_quorum_t;

typedef enum {
    CM_MNCA_QUORUM_PENDING = 0,  // not yet K matching hashes
    CM_MNCA_QUORUM_HIT     = 1,  // K devices agree on this tile — fire settlement
} cm_mnca_quorum_rc_t;

void cm_mnca_quorum_init(cm_mnca_quorum_t *q);

/**
 * Record a tile observation from `sender_mac`.  If K devices now have the
 * same tile_hash for the same (x, y, generation), returns CM_MNCA_QUORUM_HIT
 * and the slot is invalidated (fire-once).  Otherwise returns PENDING.
 *
 * `now_ms` is used to evict stale windows.
 */
cm_mnca_quorum_rc_t cm_mnca_quorum_update(cm_mnca_quorum_t *q,
                                           uint16_t x, uint16_t y, uint32_t generation,
                                           const uint8_t tile_hash[32],
                                           const uint8_t sender_mac[6],
                                           uint64_t now_ms);

#ifdef __cplusplus
}
#endif
