// cell_ring.h — fixed-capacity ring buffer of received cells.
//
// Each slot stores the cell exactly as it arrived on the radio — 1024 bytes,
// the canonical wire format, no shadow representation. Host-side metadata
// (peer MAC, host receipt timestamp) lives alongside the cell bytes but
// never replaces them.
//
// Sized for stack allocation in main: CAPACITY * (1024 + ~16) bytes.
// With capacity 16 that's ~16.6KB — comfortable on C6's 512KB SRAM.
//
// Not thread-safe. Caller serializes access.

#pragma once

#include "cell_wire.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Bump capacity here if a larger window is needed.
#define CM_RING_CAPACITY  16u

typedef struct {
    // The cell IS the wire format. Don't add parallel fields for header
    // values — read them via accessors from cell_wire.h.
    uint8_t  cell[CM_CELL_SIZE];

    // Host-side metadata captured at receipt.
    uint8_t  peer_mac[6];        // ESP-NOW sender MAC
    uint64_t received_at_ms;     // host monotonic clock at insertion
    bool     occupied;
} cm_ring_entry_t;

typedef struct {
    cm_ring_entry_t entries[CM_RING_CAPACITY];
    uint32_t next_index;   // monotonic insertion counter; modulo gives slot
    uint32_t total_pushed; // lifetime count, for telemetry
} cm_ring_t;

// Zero a freshly allocated ring.
void cm_ring_init(cm_ring_t *r);

// Insert a complete 1024-byte cell as observed on the wire. No re-packing —
// the cell IS the wire format; we just copy the bytes into the slot.
//
// Overwrites the oldest slot when full.
void cm_ring_push(cm_ring_t *r,
                  const uint8_t cell[CM_CELL_SIZE],
                  const uint8_t peer_mac[6],
                  uint64_t received_at_ms);

// Iterate entries from newest to oldest. `cb` returns false to stop early.
// Returns the number of entries visited.
typedef bool (*cm_ring_visit_fn)(const cm_ring_entry_t *entry, void *userdata);

size_t cm_ring_visit_newest_first(const cm_ring_t *r,
                                  cm_ring_visit_fn cb,
                                  void *userdata);

// Count entries matching `type_hash` (32B SHA-256) that arrived within
// `window_ms` of `now_ms`. The cell's type_hash is read in-place from
// the canonical bytes — no shadow struct.
//
// `distinct_peers_only` collapses duplicate cells from the same peer MAC
// so a single chatty device cannot satisfy a quorum alone.
size_t cm_ring_count_recent(const cm_ring_t *r,
                            const uint8_t type_hash[32],
                            uint64_t now_ms,
                            uint32_t window_ms,
                            bool distinct_peers_only);

#ifdef __cplusplus
}
#endif
