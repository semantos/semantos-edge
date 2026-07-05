// test_cell_rules.c — host-side smoke test for the rules engine.
//
// Run through the Zig C-ABI harness:
//   ../cell-mesh-zig/run-c-abi-tests.sh

#include "cell_rules.h"
#include "cell_wire.h"
#include "cell_ring.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); fails++; } \
    else         { printf("ok:   %s\n", msg); } \
} while (0)

static void make_cell_of_type(uint8_t cell[CM_CELL_SIZE], uint8_t type_pattern) {
    cm_cell_init(cell);
    memset(cm_type_hash_mut(cell), type_pattern, 32);
}

int main(void) {
    int fails = 0;

    // ── Test 1: fresh table accepts a rule ────────────────────────────
    {
        cm_rules_t rules;
        cm_rules_init(&rules);

        cm_rule_t r = {0};
        r.trigger_kind = CM_TRIGGER_ON_TYPE;
        memset(r.trigger_type_hash, 0xAA, 32);
        r.effect.kind = CM_EFFECT_BLINK;
        r.effect.as.blink.duration_ms = 200;

        int slot = cm_rules_install(&rules, &r);
        CHECK(slot == 0, "first install lands at slot 0");
        CHECK(rules.entries[0].occupied, "slot is occupied");
    }

    // ── Test 2: rule fires on matching type ────────────────────────────
    {
        cm_rules_t rules;
        cm_rules_init(&rules);

        cm_rule_t r = {0};
        r.trigger_kind = CM_TRIGGER_ON_TYPE;
        memset(r.trigger_type_hash, 0xAA, 32);
        r.effect.kind = CM_EFFECT_BLINK;
        r.effect.as.blink.duration_ms = 300;
        cm_rules_install(&rules, &r);

        uint8_t cell[CM_CELL_SIZE];
        make_cell_of_type(cell, 0xAA);

        cm_effect_t effects[CM_RULES_MAX];
        size_t n = cm_rules_evaluate(&rules, NULL, cell, 0, effects);
        CHECK(n == 1, "one effect fired");
        CHECK(effects[0].kind == CM_EFFECT_BLINK, "effect kind is blink");
        CHECK(effects[0].as.blink.duration_ms == 300, "blink duration carried through");
        CHECK(rules.total_fired == 1, "telemetry: 1 fired");
        CHECK(rules.total_evaluated == 1, "telemetry: 1 evaluated");
    }

    // ── Test 3: non-matching type produces no effects ──────────────────
    {
        cm_rules_t rules;
        cm_rules_init(&rules);

        cm_rule_t r = {0};
        r.trigger_kind = CM_TRIGGER_ON_TYPE;
        memset(r.trigger_type_hash, 0xAA, 32);
        r.effect.kind = CM_EFFECT_BLINK;
        r.effect.as.blink.duration_ms = 100;
        cm_rules_install(&rules, &r);

        uint8_t cell[CM_CELL_SIZE];
        make_cell_of_type(cell, 0xBB);   // different type

        cm_effect_t effects[CM_RULES_MAX];
        size_t n = cm_rules_evaluate(&rules, NULL, cell, 0, effects);
        CHECK(n == 0,                "no effects fired");
        CHECK(rules.total_fired == 0, "telemetry: nothing fired");
        CHECK(rules.total_evaluated == 1, "evaluation still counted");
    }

    // ── Test 4: multiple rules can fire on the same cell ───────────────
    {
        cm_rules_t rules;
        cm_rules_init(&rules);

        // Two rules, both triggered on the same type, with different effects.
        cm_rule_t r1 = {0};
        r1.trigger_kind = CM_TRIGGER_ON_TYPE;
        memset(r1.trigger_type_hash, 0xCC, 32);
        r1.effect.kind = CM_EFFECT_BLINK;
        r1.effect.as.blink.duration_ms = 500;

        cm_rule_t r2 = {0};
        r2.trigger_kind = CM_TRIGGER_ON_TYPE;
        memset(r2.trigger_type_hash, 0xCC, 32);
        r2.effect.kind = CM_EFFECT_EMIT;
        memset(r2.effect.as.emit.type_hash, 0xEE, 32);
        r2.effect.as.emit.payload_len = 4;
        r2.effect.as.emit.payload[0] = 0xDE;
        r2.effect.as.emit.payload[1] = 0xAD;

        cm_rules_install(&rules, &r1);
        cm_rules_install(&rules, &r2);

        uint8_t cell[CM_CELL_SIZE];
        make_cell_of_type(cell, 0xCC);

        cm_effect_t effects[CM_RULES_MAX];
        size_t n = cm_rules_evaluate(&rules, NULL, cell, 0, effects);
        CHECK(n == 2, "both rules fired");
        // Order matches install order:
        CHECK(effects[0].kind == CM_EFFECT_BLINK, "first effect is blink");
        CHECK(effects[1].kind == CM_EFFECT_EMIT,  "second effect is emit");
        CHECK(effects[1].as.emit.payload[0] == 0xDE, "emit payload preserved");
        CHECK(rules.total_fired == 2, "telemetry: 2 fired");
    }

    // ── Test 5: rule removal works ─────────────────────────────────────
    {
        cm_rules_t rules;
        cm_rules_init(&rules);

        cm_rule_t r = {0};
        r.trigger_kind = CM_TRIGGER_ON_TYPE;
        memset(r.trigger_type_hash, 0xDD, 32);
        r.effect.kind = CM_EFFECT_BLINK;
        r.effect.as.blink.duration_ms = 50;
        int slot = cm_rules_install(&rules, &r);

        uint8_t cell[CM_CELL_SIZE];
        make_cell_of_type(cell, 0xDD);

        cm_effect_t effects[CM_RULES_MAX];
        CHECK(cm_rules_evaluate(&rules, NULL, cell, 0, effects) == 1, "rule fires before removal");

        int rc = cm_rules_remove(&rules, (size_t)slot);
        CHECK(rc == 0, "remove returns 0");
        CHECK(cm_rules_evaluate(&rules, NULL, cell, 0, effects) == 0, "rule does not fire after removal");
    }

    // ── Test 6: table-full case ────────────────────────────────────────
    {
        cm_rules_t rules;
        cm_rules_init(&rules);

        for (size_t i = 0; i < CM_RULES_MAX; i++) {
            cm_rule_t r = {0};
            r.trigger_kind = CM_TRIGGER_ON_TYPE;
            r.trigger_type_hash[0] = (uint8_t)i;
            r.effect.kind = CM_EFFECT_BLINK;
            r.effect.as.blink.duration_ms = 100;
            int slot = cm_rules_install(&rules, &r);
            CHECK(slot == (int)i, "fill installs in order");
        }

        cm_rule_t overflow = {0};
        overflow.trigger_kind = CM_TRIGGER_ON_TYPE;
        overflow.effect.kind = CM_EFFECT_BLINK;
        overflow.effect.as.blink.duration_ms = 100;
        int rc = cm_rules_install(&rules, &overflow);
        CHECK(rc == -1, "install on full table returns -1");
    }

    // ── Test 7: bad inputs rejected gracefully ─────────────────────────
    {
        cm_rules_t rules;
        cm_rules_init(&rules);
        cm_rule_t r = {0};
        // trigger_kind = NONE
        r.effect.kind = CM_EFFECT_BLINK;
        CHECK(cm_rules_install(&rules, &r) == -1, "install with trigger=NONE rejected");

        r.trigger_kind = CM_TRIGGER_ON_TYPE;
        r.effect.kind = CM_EFFECT_NONE;
        CHECK(cm_rules_install(&rules, &r) == -1, "install with effect=NONE rejected");

        CHECK(cm_rules_install(NULL, &r) == -1, "install with NULL rules rejected");
        CHECK(cm_rules_install(&rules, NULL) == -1, "install with NULL rule rejected");
    }

    // ── Test 8: quorum trigger fires when N distinct peers seen ────────
    {
        cm_rules_t rules;  cm_rules_init(&rules);
        cm_ring_t  ring;   cm_ring_init(&ring);

        // Install: fire BLINK when 2 distinct peers send type 0x77 within 500 ms.
        cm_rule_t r = {0};
        r.trigger_kind          = CM_TRIGGER_QUORUM;
        memset(r.trigger_type_hash, 0x77, 32);
        r.quorum_n              = 2;
        r.quorum_window_ms      = 500;
        r.quorum_distinct_peers = true;
        r.effect.kind           = CM_EFFECT_BLINK;
        r.effect.as.blink.duration_ms = 250;
        cm_rules_install(&rules, &r);

        // Build a cell of the matching type.
        uint8_t cell[CM_CELL_SIZE]; make_cell_of_type(cell, 0x77);

        // 1st cell from peer P1 at t=1000 — only one distinct peer → no fire.
        uint8_t p1[6] = {1,1,1,1,1,1};
        cm_ring_push(&ring, cell, p1, 1000);
        cm_effect_t effects[CM_RULES_MAX];
        size_t n = cm_rules_evaluate(&rules, &ring, cell, 1000, effects);
        CHECK(n == 0, "quorum: 1 peer in window does not fire");

        // 2nd cell from peer P2 at t=1200 — now 2 distinct → fires.
        uint8_t p2[6] = {2,2,2,2,2,2};
        cm_ring_push(&ring, cell, p2, 1200);
        n = cm_rules_evaluate(&rules, &ring, cell, 1200, effects);
        CHECK(n == 1, "quorum: 2 distinct peers in window fires");
        CHECK(effects[0].kind == CM_EFFECT_BLINK, "quorum-fired effect is blink");
    }

    // ── Test 9: quorum respects window — out-of-window doesn't count ────
    {
        cm_rules_t rules;  cm_rules_init(&rules);
        cm_ring_t  ring;   cm_ring_init(&ring);

        cm_rule_t r = {0};
        r.trigger_kind          = CM_TRIGGER_QUORUM;
        memset(r.trigger_type_hash, 0x88, 32);
        r.quorum_n              = 2;
        r.quorum_window_ms      = 100;
        r.quorum_distinct_peers = true;
        r.effect.kind           = CM_EFFECT_BLINK;
        r.effect.as.blink.duration_ms = 100;
        cm_rules_install(&rules, &r);

        uint8_t cell[CM_CELL_SIZE]; make_cell_of_type(cell, 0x88);
        uint8_t p1[6] = {1,1,1,1,1,1};
        uint8_t p2[6] = {2,2,2,2,2,2};

        // P1 at t=1000, P2 at t=1500 — 500 ms apart, window is 100 ms.
        cm_ring_push(&ring, cell, p1, 1000);
        cm_ring_push(&ring, cell, p2, 1500);

        cm_effect_t effects[CM_RULES_MAX];
        // Evaluate at t=1500 — only the just-pushed P2 cell is in window.
        size_t n = cm_rules_evaluate(&rules, &ring, cell, 1500, effects);
        CHECK(n == 0, "quorum: out-of-window peer is not counted");
    }

    // ── Test 10: quorum with distinct_peers=false counts duplicates ────
    {
        cm_rules_t rules;  cm_rules_init(&rules);
        cm_ring_t  ring;   cm_ring_init(&ring);

        cm_rule_t r = {0};
        r.trigger_kind          = CM_TRIGGER_QUORUM;
        memset(r.trigger_type_hash, 0x99, 32);
        r.quorum_n              = 3;
        r.quorum_window_ms      = 1000;
        r.quorum_distinct_peers = false; // count duplicates from same peer
        r.effect.kind           = CM_EFFECT_EMIT;
        memset(r.effect.as.emit.type_hash, 0xEE, 32);
        cm_rules_install(&rules, &r);

        uint8_t cell[CM_CELL_SIZE]; make_cell_of_type(cell, 0x99);
        uint8_t p1[6] = {1,1,1,1,1,1};
        cm_ring_push(&ring, cell, p1, 1000);
        cm_ring_push(&ring, cell, p1, 1010);  // same peer, second push
        cm_ring_push(&ring, cell, p1, 1020);

        cm_effect_t effects[CM_RULES_MAX];
        size_t n = cm_rules_evaluate(&rules, &ring, cell, 1020, effects);
        CHECK(n == 1, "quorum: 3 duplicates from one peer satisfies n=3 in non-distinct mode");
    }

    // ── Test 11: quorum with NULL ring is graceful no-op ───────────────
    {
        cm_rules_t rules;  cm_rules_init(&rules);
        cm_rule_t r = {0};
        r.trigger_kind = CM_TRIGGER_QUORUM;
        memset(r.trigger_type_hash, 0xAA, 32);
        r.quorum_n = 1;
        r.quorum_window_ms = 100;
        r.effect.kind = CM_EFFECT_BLINK;
        r.effect.as.blink.duration_ms = 100;
        cm_rules_install(&rules, &r);

        uint8_t cell[CM_CELL_SIZE]; make_cell_of_type(cell, 0xAA);
        cm_effect_t effects[CM_RULES_MAX];
        // NULL ring → quorum doesn't fire (graceful skip).
        size_t n = cm_rules_evaluate(&rules, NULL, cell, 0, effects);
        CHECK(n == 0, "quorum with NULL ring does not fire");
    }

    // ── Test 12: ON_TYPE + QUORUM rules coexist on the same evaluator ──
    {
        cm_rules_t rules;  cm_rules_init(&rules);
        cm_ring_t  ring;   cm_ring_init(&ring);

        cm_rule_t r_type = {0};
        r_type.trigger_kind = CM_TRIGGER_ON_TYPE;
        memset(r_type.trigger_type_hash, 0xCC, 32);
        r_type.effect.kind = CM_EFFECT_BLINK;
        r_type.effect.as.blink.duration_ms = 100;
        cm_rules_install(&rules, &r_type);

        cm_rule_t r_quorum = {0};
        r_quorum.trigger_kind = CM_TRIGGER_QUORUM;
        memcpy(r_quorum.trigger_type_hash, r_type.trigger_type_hash, 32);
        r_quorum.quorum_n = 2;
        r_quorum.quorum_window_ms = 500;
        r_quorum.quorum_distinct_peers = true;
        r_quorum.effect.kind = CM_EFFECT_EMIT;
        memset(r_quorum.effect.as.emit.type_hash, 0xEE, 32);
        cm_rules_install(&rules, &r_quorum);

        uint8_t cell[CM_CELL_SIZE]; make_cell_of_type(cell, 0xCC);
        uint8_t p1[6] = {1,1,1,1,1,1};
        uint8_t p2[6] = {2,2,2,2,2,2};

        // First peer: only ON_TYPE fires (quorum not yet met).
        cm_ring_push(&ring, cell, p1, 1000);
        cm_effect_t effects[CM_RULES_MAX];
        size_t n = cm_rules_evaluate(&rules, &ring, cell, 1000, effects);
        CHECK(n == 1,                          "1st peer: only ON_TYPE fires");
        CHECK(effects[0].kind == CM_EFFECT_BLINK, "1st peer: effect is BLINK");

        // Second distinct peer: both rules fire.
        cm_ring_push(&ring, cell, p2, 1200);
        n = cm_rules_evaluate(&rules, &ring, cell, 1200, effects);
        CHECK(n == 2,                          "2nd peer: both rules fire");
        CHECK(effects[0].kind == CM_EFFECT_BLINK, "2nd peer: first effect BLINK");
        CHECK(effects[1].kind == CM_EFFECT_EMIT,  "2nd peer: second effect EMIT");
    }

    // ── Test 13: rule encode/decode round-trip — ON_TYPE + BLINK ──────
    {
        cm_rule_t in = {0};
        in.trigger_kind = CM_TRIGGER_ON_TYPE;
        memset(in.trigger_type_hash, 0x42, 32);
        in.effect.kind = CM_EFFECT_BLINK;
        in.effect.as.blink.duration_ms = 750;

        uint8_t buf[CM_RULE_ENCODED_SIZE];
        CHECK(cm_rule_encode(&in, buf) == 0,         "encode on_type+blink returns 0");
        CHECK(buf[0] == CM_RULE_SCHEMA_VERSION,      "schema version stamped");

        cm_rule_t out;
        CHECK(cm_rule_decode(buf, &out) == 0,        "decode returns 0");
        CHECK(out.trigger_kind == CM_TRIGGER_ON_TYPE,"trigger_kind round-trips");
        CHECK(memcmp(out.trigger_type_hash, in.trigger_type_hash, 32) == 0, "type_hash round-trips");
        CHECK(out.effect.kind == CM_EFFECT_BLINK,    "effect.kind round-trips");
        CHECK(out.effect.as.blink.duration_ms == 750,"blink duration round-trips");
        CHECK(out.occupied == false,                 "decoded rule has occupied=false");
    }

    // ── Test 14: rule encode/decode round-trip — QUORUM + EMIT ────────
    {
        cm_rule_t in = {0};
        in.trigger_kind = CM_TRIGGER_QUORUM;
        memset(in.trigger_type_hash, 0xAB, 32);
        in.quorum_n = 3;
        in.quorum_window_ms = 1234;
        in.quorum_distinct_peers = true;
        in.effect.kind = CM_EFFECT_EMIT;
        memset(in.effect.as.emit.type_hash, 0xCD, 32);
        in.effect.as.emit.payload_len = 4;
        in.effect.as.emit.payload[0] = 'Q';
        in.effect.as.emit.payload[1] = 'O';
        in.effect.as.emit.payload[2] = 'R';
        in.effect.as.emit.payload[3] = 'M';

        uint8_t buf[CM_RULE_ENCODED_SIZE];
        cm_rule_encode(&in, buf);
        cm_rule_t out;
        CHECK(cm_rule_decode(buf, &out) == 0,                              "decode quorum+emit returns 0");
        CHECK(out.trigger_kind == CM_TRIGGER_QUORUM,                       "quorum trigger round-trips");
        CHECK(out.quorum_n == 3,                                           "quorum_n round-trips");
        CHECK(out.quorum_window_ms == 1234,                                "quorum_window_ms round-trips");
        CHECK(out.quorum_distinct_peers == true,                           "quorum_distinct_peers round-trips");
        CHECK(out.effect.kind == CM_EFFECT_EMIT,                           "emit effect round-trips");
        CHECK(memcmp(out.effect.as.emit.type_hash, in.effect.as.emit.type_hash, 32) == 0, "emit type_hash round-trips");
        CHECK(out.effect.as.emit.payload_len == 4,                         "emit payload_len round-trips");
        CHECK(memcmp(out.effect.as.emit.payload, in.effect.as.emit.payload, 4) == 0, "emit payload round-trips");
    }

    // ── Test 15: decode rejects unknown schema version ─────────────────
    {
        uint8_t buf[CM_RULE_ENCODED_SIZE] = {0};
        buf[0] = 0x99; // unknown version
        cm_rule_t out;
        CHECK(cm_rule_decode(buf, &out) == -1, "decode rejects unknown schema version");
    }

    // ── Test 16: decode rejects unknown trigger_kind ──────────────────
    {
        uint8_t buf[CM_RULE_ENCODED_SIZE] = {0};
        buf[0] = CM_RULE_SCHEMA_VERSION;
        buf[1] = 0xFF; // unknown trigger
        buf[38] = CM_EFFECT_BLINK;
        cm_rule_t out;
        CHECK(cm_rule_decode(buf, &out) == -1, "decode rejects unknown trigger_kind");
    }

    // ── Test 17: cm_rule_equals — same rule equals itself ─────────────
    {
        cm_rule_t r = {0};
        r.trigger_kind = CM_TRIGGER_ON_TYPE;
        memset(r.trigger_type_hash, 0xAA, 32);
        r.effect.kind = CM_EFFECT_BLINK;
        r.effect.as.blink.duration_ms = 100;
        CHECK(cm_rule_equals(&r, &r) == true,  "same rule equals itself");

        cm_rule_t r2 = r;
        r2.occupied = true;   // should be ignored by equals
        CHECK(cm_rule_equals(&r, &r2) == true, "occupied flag ignored by equals");

        r2.effect.as.blink.duration_ms = 200;  // different duration
        CHECK(cm_rule_equals(&r, &r2) == false, "different blink duration is unequal");
    }

    if (fails == 0) {
        printf("\nAll tests passed.\n");
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", fails);
        return 1;
    }
}
