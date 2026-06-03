/**
 * test_mnca_incentive.c — host tests for the MNCA tile compute + quorum.
 *
 * Tests cm_mnca_step, cm_mnca_tile_encode/decode, cm_mnca_tile_hash,
 * and cm_mnca_quorum_update without any IDF or hardware dependency.
 *
 * Compile + run (no IDF needed):
 *   cc -I ../include test_mnca_incentive.c ../src/cell_mnca.c \
 *      -o test_mnca_incentive && ./test_mnca_incentive
 */

#include "cell_mnca.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

static int s_pass = 0;
static int s_fail = 0;

#define CHECK(cond, label) do {                                              \
    if (cond) { printf("  PASS %s\n", label); s_pass++; }                   \
    else       { printf("  FAIL %s  (line %d)\n", label, __LINE__); s_fail++; } \
} while (0)

// ── Test vectors ─────────────────────────────────────────────────────────────

static const uint8_t MAC_A[6] = { 0x58, 0xe6, 0xc5, 0x1a, 0x8b, 0x28 };
static const uint8_t MAC_B[6] = { 0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0x54 };
static const uint8_t MAC_C[6] = { 0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0xf8 };

// ── T1: tile step determinism ────────────────────────────────────────────────

static void test_tile_step(void) {
    printf("\n[T1] cm_mnca_step determinism\n");

    cm_mnca_tile_t t0, t1, t2;
    cm_mnca_tile_init_random(&t0, 0, 0, 12345);

    cm_mnca_step(&t0, &t1, &CM_MNCA_DEFAULT_RULE);
    cm_mnca_step(&t0, &t2, &CM_MNCA_DEFAULT_RULE);  // same input, same output

    CHECK(t1.generation == 1, "step: generation incremented to 1");
    CHECK(t1.x == t0.x && t1.y == t0.y, "step: x/y preserved");
    CHECK(memcmp(t1.state, t2.state, CM_MNCA_TILE_CELLS) == 0,
          "step: deterministic (two runs identical)");
    CHECK(memcmp(t1.state, t0.state, CM_MNCA_TILE_CELLS) != 0,
          "step: state actually changed (non-trivial rule)");
}

// ── T2: payload encode / decode round-trip ───────────────────────────────────

static void test_encode_decode(void) {
    printf("\n[T2] cm_mnca_tile_encode / decode round-trip\n");

    cm_mnca_tile_t orig, decoded;
    cm_mnca_tile_init_random(&orig, 3, 7, 99999);
    orig.generation = 42;

    uint8_t payload[CM_PAYLOAD_SIZE];
    size_t used = cm_mnca_tile_encode(&orig, &CM_MNCA_DEFAULT_RULE, payload);
    CHECK(used == CM_MNCA_TILE_V0_HDR_BYTES + CM_MNCA_TILE_CELLS,
          "encode: correct byte count");

    int rc = cm_mnca_tile_decode(payload, used, &decoded);
    CHECK(rc == 0, "decode: returns 0");
    CHECK(decoded.x          == orig.x,          "decode: x matches");
    CHECK(decoded.y          == orig.y,          "decode: y matches");
    CHECK(decoded.generation == orig.generation, "decode: generation matches");
    CHECK(memcmp(decoded.state, orig.state, CM_MNCA_TILE_CELLS) == 0,
          "decode: state bytes match");

    // Check rule_id in payload
    CHECK(payload[CM_MNCA_TILE_V0_OFF_RULE_ID + 0] == 'M' &&
          payload[CM_MNCA_TILE_V0_OFF_RULE_ID + 1] == 'N' &&
          payload[CM_MNCA_TILE_V0_OFF_RULE_ID + 2] == 'C' &&
          payload[CM_MNCA_TILE_V0_OFF_RULE_ID + 3] == 'A',
          "encode: rule_id = 'MNCA'");

    // Short payload → decode fails
    CHECK(cm_mnca_tile_decode(payload, CM_MNCA_TILE_V0_HDR_BYTES - 1, &decoded) != 0,
          "decode: short payload → error");
}

// ── T3: tile hash is stable ──────────────────────────────────────────────────

static void test_tile_hash(void) {
    printf("\n[T3] cm_mnca_tile_hash stability\n");

    cm_mnca_tile_t t;
    cm_mnca_tile_init_random(&t, 1, 2, 777);

    uint8_t h1[32], h2[32], hZ[32];
    cm_mnca_tile_hash(&t, h1);
    cm_mnca_tile_hash(&t, h2);

    CHECK(memcmp(h1, h2, 32) == 0, "hash: same tile → same hash (stable)");

    cm_mnca_tile_t t2 = t;
    t2.state[0] ^= 1;  // flip one bit
    cm_mnca_tile_hash(&t2, hZ);
    CHECK(memcmp(h1, hZ, 32) != 0, "hash: different state → different hash");
}

// ── T4: quorum miss (only 1 device) ─────────────────────────────────────────

static void test_quorum_miss_single(void) {
    printf("\n[T4] quorum miss — only 1 device\n");

    cm_mnca_quorum_t q;
    cm_mnca_quorum_init(&q);

    cm_mnca_tile_t t;
    cm_mnca_tile_init_random(&t, 0, 0, 42);
    uint8_t h[32];
    cm_mnca_tile_hash(&t, h);

    cm_mnca_quorum_rc_t rc = cm_mnca_quorum_update(&q, 0, 0, 0, h, MAC_A, 1000);
    CHECK(rc == CM_MNCA_QUORUM_PENDING, "1 device → PENDING (no quorum)");
}

// ── T5: quorum hit — 2 devices agree ────────────────────────────────────────

static void test_quorum_hit_two(void) {
    printf("\n[T5] quorum hit — 2 devices agree\n");

    cm_mnca_quorum_t q;
    cm_mnca_quorum_init(&q);

    cm_mnca_tile_t t;
    cm_mnca_tile_init_random(&t, 2, 0, 100);
    uint8_t h[32];
    cm_mnca_tile_hash(&t, h);

    cm_mnca_quorum_rc_t rc1 = cm_mnca_quorum_update(&q, 2, 0, 1, h, MAC_A, 1000);
    CHECK(rc1 == CM_MNCA_QUORUM_PENDING, "device A → PENDING");

    cm_mnca_quorum_rc_t rc2 = cm_mnca_quorum_update(&q, 2, 0, 1, h, MAC_B, 2000);
    CHECK(rc2 == CM_MNCA_QUORUM_HIT, "device B same hash → HIT (2-of-3 quorum)");

    // After hit, slot is invalidated — same hash from C should not re-fire
    cm_mnca_quorum_rc_t rc3 = cm_mnca_quorum_update(&q, 2, 0, 1, h, MAC_C, 3000);
    CHECK(rc3 == CM_MNCA_QUORUM_PENDING, "fire-once: after HIT, new slot starts PENDING");
}

// ── T6: quorum miss — 2 devices disagree ────────────────────────────────────

static void test_quorum_miss_disagree(void) {
    printf("\n[T6] quorum miss — 2 devices disagree\n");

    cm_mnca_quorum_t q;
    cm_mnca_quorum_init(&q);

    cm_mnca_tile_t tA, tB;
    cm_mnca_tile_init_random(&tA, 5, 0, 1);
    cm_mnca_tile_init_random(&tB, 5, 0, 2);  // different seed → different state
    tA.generation = tB.generation = 7;

    uint8_t hA[32], hB[32];
    cm_mnca_tile_hash(&tA, hA);
    cm_mnca_tile_hash(&tB, hB);

    // Ensure the two hashes actually differ (very high probability with different seeds)
    // If by cosmic chance they match, the test would fail on the PENDING assertion below.

    cm_mnca_quorum_rc_t rc1 = cm_mnca_quorum_update(&q, 5, 0, 7, hA, MAC_A, 1000);
    cm_mnca_quorum_rc_t rc2 = cm_mnca_quorum_update(&q, 5, 0, 7, hB, MAC_B, 2000);
    CHECK(rc1 == CM_MNCA_QUORUM_PENDING, "device A → PENDING");
    CHECK(rc2 == CM_MNCA_QUORUM_PENDING, "device B (different hash) → PENDING (no quorum)");
}

// ── T7: duplicate sender ignored ────────────────────────────────────────────

static void test_quorum_replay_protection(void) {
    printf("\n[T7] quorum replay protection (duplicate sender)\n");

    cm_mnca_quorum_t q;
    cm_mnca_quorum_init(&q);

    cm_mnca_tile_t t;
    cm_mnca_tile_init_random(&t, 1, 1, 55);
    uint8_t h[32];
    cm_mnca_tile_hash(&t, h);

    cm_mnca_quorum_update(&q, 1, 1, 3, h, MAC_A, 1000);
    // Same sender re-sends — should be ignored (no quorum from 2 MAC_A entries)
    cm_mnca_quorum_rc_t rc = cm_mnca_quorum_update(&q, 1, 1, 3, h, MAC_A, 2000);
    CHECK(rc == CM_MNCA_QUORUM_PENDING, "duplicate sender ignored → PENDING");
}

// ── T8: quorum TTL eviction ──────────────────────────────────────────────────

static void test_quorum_ttl(void) {
    printf("\n[T8] quorum TTL eviction\n");

    cm_mnca_quorum_t q;
    cm_mnca_quorum_init(&q);

    cm_mnca_tile_t t;
    cm_mnca_tile_init_random(&t, 0, 0, 77);
    uint8_t h[32];
    cm_mnca_tile_hash(&t, h);

    // Device A submits at t=0
    cm_mnca_quorum_update(&q, 0, 0, 9, h, MAC_A, 0);
    // Device B submits at t = TTL + 1 (stale window)
    uint64_t stale_ms = CM_MNCA_QUORUM_TTL_MS + 1;
    // The eviction happens during update: the A slot is evicted, B creates a fresh slot.
    cm_mnca_quorum_rc_t rc = cm_mnca_quorum_update(&q, 0, 0, 9, h, MAC_B, stale_ms);
    // Slot was evicted so B starts fresh → PENDING (only 1 entry in new slot)
    CHECK(rc == CM_MNCA_QUORUM_PENDING,
          "stale slot evicted; late device B starts fresh → PENDING");
}

// ── main ─────────────────────────────────────────────────────────────────────

int main(void) {
    printf("=== test_mnca_incentive ===\n");
    test_tile_step();
    test_encode_decode();
    test_tile_hash();
    test_quorum_miss_single();
    test_quorum_hit_two();
    test_quorum_miss_disagree();
    test_quorum_replay_protection();
    test_quorum_ttl();
    printf("\n=== %d passed, %d failed ===\n", s_pass, s_fail);
    return s_fail ? 1 : 0;
}
