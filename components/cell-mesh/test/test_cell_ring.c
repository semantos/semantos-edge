// test_cell_ring.c — host-side smoke test for the ring buffer.
//
// Pushes synthetic cells (built in-place via accessors, no shadow struct)
// and asserts quorum-aware counting works correctly.
//
// Compile:
//   cc -I ../include test_cell_ring.c ../src/cell_ring.c ../src/cell_wire.c -o test_cell_ring

#include "cell_ring.h"
#include "cell_wire.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); fails++; } \
    else         { printf("ok:   %s\n", msg); } \
} while (0)

// Helper: assemble a synthetic cell in-place and push it.
// type_byte fills the entire 32-byte type_hash field (so tests can pick
// distinct types by single-byte tags).
static void push_synthetic(cm_ring_t *r,
                           uint8_t type_byte,
                           uint8_t peer_byte,
                           uint64_t ts_ms) {
    uint8_t cell[CM_CELL_SIZE];
    cm_cell_init(cell);
    memset(cm_type_hash_mut(cell), type_byte, 32);
    cm_set_timestamp_ms(cell, ts_ms);

    uint8_t peer_mac[6];
    memset(peer_mac, peer_byte, 6);

    cm_ring_push(r, cell, peer_mac, ts_ms);
}

int main(void) {
    int fails = 0;

    // ── Test 1: empty ring ───────────────────────────────────────────
    {
        cm_ring_t r;
        cm_ring_init(&r);
        CHECK(r.total_pushed == 0, "fresh ring has total_pushed=0");
        size_t visited = cm_ring_visit_newest_first(&r, NULL, NULL);
        CHECK(visited == 0, "visit on empty ring with NULL cb returns 0");
    }

    // ── Test 2: single push then count ───────────────────────────────
    {
        cm_ring_t r;
        cm_ring_init(&r);
        push_synthetic(&r, 0xAA, 0x01, 1000);

        uint8_t target[32];
        memset(target, 0xAA, 32);

        size_t n = cm_ring_count_recent(&r, target, 1500, 600, false);
        CHECK(n == 1, "single cell within window counted");

        n = cm_ring_count_recent(&r, target, 5000, 100, false);
        CHECK(n == 0, "single cell outside window not counted");

        uint8_t other[32];
        memset(other, 0xBB, 32);
        n = cm_ring_count_recent(&r, other, 1500, 600, false);
        CHECK(n == 0, "type mismatch not counted");
    }

    // ── Test 3: quorum across 3 peers ────────────────────────────────
    {
        cm_ring_t r;
        cm_ring_init(&r);
        push_synthetic(&r, 0xAA, 0x01, 1000);
        push_synthetic(&r, 0xAA, 0x02, 1100);
        push_synthetic(&r, 0xAA, 0x03, 1200);

        uint8_t motion[32];
        memset(motion, 0xAA, 32);

        size_t n = cm_ring_count_recent(&r, motion, 1300, 500, false);
        CHECK(n == 3, "3 peers within window all counted");

        n = cm_ring_count_recent(&r, motion, 1300, 500, true);
        CHECK(n == 3, "3 distinct peers counted with distinct mode");
    }

    // ── Test 4: distinct-peers collapses duplicates ─────────────────
    {
        cm_ring_t r;
        cm_ring_init(&r);
        // Same peer chatters 5 times; another peer once.
        push_synthetic(&r, 0xAA, 0x01, 1000);
        push_synthetic(&r, 0xAA, 0x01, 1050);
        push_synthetic(&r, 0xAA, 0x01, 1100);
        push_synthetic(&r, 0xAA, 0x01, 1150);
        push_synthetic(&r, 0xAA, 0x01, 1200);
        push_synthetic(&r, 0xAA, 0x02, 1250);

        uint8_t motion[32];
        memset(motion, 0xAA, 32);

        size_t raw = cm_ring_count_recent(&r, motion, 1300, 500, false);
        CHECK(raw == 6, "raw count includes all duplicates");

        size_t distinct = cm_ring_count_recent(&r, motion, 1300, 500, true);
        CHECK(distinct == 2, "distinct mode collapses chatter to 2 peers");
    }

    // ── Test 5: window exclusion (newest-first early exit) ──────────
    {
        cm_ring_t r;
        cm_ring_init(&r);
        push_synthetic(&r, 0xAA, 0x01, 1000);  // outside window
        push_synthetic(&r, 0xAA, 0x02, 1900);  // inside window
        push_synthetic(&r, 0xAA, 0x03, 1950);  // inside window

        uint8_t motion[32];
        memset(motion, 0xAA, 32);

        // now = 2000, window = 200ms → only [1800..2000] counts
        size_t n = cm_ring_count_recent(&r, motion, 2000, 200, false);
        CHECK(n == 2, "window correctly excludes older cells");
    }

    // ── Test 6: wraparound ───────────────────────────────────────────
    {
        cm_ring_t r;
        cm_ring_init(&r);
        for (int i = 0; i < 20; i++) {
            push_synthetic(&r, 0xAA, (uint8_t)i, 1000 + i);
        }
        CHECK(r.total_pushed == 20, "total_pushed reflects lifetime count");

        uint8_t motion[32];
        memset(motion, 0xAA, 32);
        size_t n = cm_ring_count_recent(&r, motion, 1100, 10000, false);
        CHECK(n == CM_RING_CAPACITY, "wraparound keeps exactly CAPACITY cells");
    }

    // ── Test 7: clock skew handled safely ────────────────────────────
    {
        cm_ring_t r;
        cm_ring_init(&r);
        push_synthetic(&r, 0xAA, 0x01, 5000);

        uint8_t motion[32];
        memset(motion, 0xAA, 32);

        size_t n = cm_ring_count_recent(&r, motion, 1000, 10000, false);
        CHECK(n == 0, "clock skew does not crash, counts 0");
    }

    // ── Test 8: pushed cell bytes are stored canonically ─────────────
    // Confirms we store the wire-format cell itself, not a parsed copy.
    {
        cm_ring_t r;
        cm_ring_init(&r);
        push_synthetic(&r, 0xAA, 0x01, 1234);

        const cm_ring_entry_t *e = &r.entries[0];
        CHECK(cm_is_cell(e->cell, CM_CELL_SIZE) == true, "stored bytes are a valid cell (magic intact)");
        CHECK(cm_timestamp_ms(e->cell)          == 1234, "stored cell's timestamp readable via accessor");

        uint8_t expected_type[32];
        memset(expected_type, 0xAA, 32);
        CHECK(memcmp(cm_type_hash(e->cell), expected_type, 32) == 0, "stored cell's type_hash readable via accessor");
    }

    if (fails == 0) {
        printf("\nAll tests passed.\n");
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", fails);
        return 1;
    }
}
