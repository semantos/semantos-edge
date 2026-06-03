// cell_ring.c — fixed-capacity ring of received cells.
//
// Cell bytes are stored canonically (uint8_t[1024]). All header reads go
// through cell_wire.h accessors so there is exactly one representation.

#include "cell_ring.h"

#include <string.h>

void cm_ring_init(cm_ring_t *r) {
    if (!r) return;
    memset(r, 0, sizeof(*r));
}

void cm_ring_push(cm_ring_t *r,
                  const uint8_t cell[CM_CELL_SIZE],
                  const uint8_t peer_mac[6],
                  uint64_t received_at_ms) {
    if (!r || !cell) return;

    uint32_t slot = r->next_index % CM_RING_CAPACITY;
    cm_ring_entry_t *e = &r->entries[slot];

    memcpy(e->cell, cell, CM_CELL_SIZE);
    if (peer_mac) {
        memcpy(e->peer_mac, peer_mac, 6);
    } else {
        memset(e->peer_mac, 0, 6);
    }
    e->received_at_ms = received_at_ms;
    e->occupied       = true;

    r->next_index++;
    r->total_pushed++;
}

size_t cm_ring_visit_newest_first(const cm_ring_t *r,
                                  cm_ring_visit_fn cb,
                                  void *userdata) {
    if (!r || !cb) return 0;

    size_t visited = 0;
    for (size_t i = 0; i < CM_RING_CAPACITY; i++) {
        uint32_t slot = (r->next_index - 1 - (uint32_t)i) % CM_RING_CAPACITY;
        const cm_ring_entry_t *e = &r->entries[slot];
        if (!e->occupied) continue;
        visited++;
        if (!cb(e, userdata)) break;
    }
    return visited;
}

// ── Helper: closure state for cm_ring_count_recent ───────────────────

typedef struct {
    const uint8_t *type_hash;
    uint64_t       now_ms;
    uint32_t       window_ms;
    bool           distinct_peers_only;
    size_t         count;
    uint8_t        seen_peers[CM_RING_CAPACITY][6];
    size_t         seen_peers_n;
} count_recent_ctx_t;

static bool peer_already_seen(count_recent_ctx_t *ctx, const uint8_t mac[6]) {
    for (size_t i = 0; i < ctx->seen_peers_n; i++) {
        if (memcmp(ctx->seen_peers[i], mac, 6) == 0) return true;
    }
    return false;
}

static bool count_recent_cb(const cm_ring_entry_t *e, void *userdata) {
    count_recent_ctx_t *ctx = (count_recent_ctx_t *)userdata;

    // Newest-first iteration: once a cell falls out of window, every
    // further one is older still — stop scanning.
    if (ctx->now_ms < e->received_at_ms) return false;
    uint64_t age_ms = ctx->now_ms - e->received_at_ms;
    if (age_ms > ctx->window_ms) return false;

    // Read type_hash directly from the canonical cell bytes.
    if (memcmp(cm_type_hash(e->cell), ctx->type_hash, 32) != 0) {
        return true; // not a type match; keep scanning
    }

    if (ctx->distinct_peers_only) {
        if (peer_already_seen(ctx, e->peer_mac)) return true;
        if (ctx->seen_peers_n < CM_RING_CAPACITY) {
            memcpy(ctx->seen_peers[ctx->seen_peers_n], e->peer_mac, 6);
            ctx->seen_peers_n++;
        }
    }
    ctx->count++;
    return true;
}

size_t cm_ring_count_recent(const cm_ring_t *r,
                            const uint8_t type_hash[32],
                            uint64_t now_ms,
                            uint32_t window_ms,
                            bool distinct_peers_only) {
    if (!r || !type_hash) return 0;

    count_recent_ctx_t ctx = {
        .type_hash           = type_hash,
        .now_ms              = now_ms,
        .window_ms           = window_ms,
        .distinct_peers_only = distinct_peers_only,
        .count               = 0,
        .seen_peers_n        = 0,
    };
    cm_ring_visit_newest_first(r, count_recent_cb, &ctx);
    return ctx.count;
}
