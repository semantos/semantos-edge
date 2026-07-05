// test_cell_forward.c — host smoke tests for the forward cell + step semantics.
//
// Run through the Zig C-ABI harness:
//   ../cell-mesh-zig/run-c-abi-tests.sh

#include "cell_forward.h"
#include "cell_wire.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); fails++; } \
    else         { printf("ok:   %s\n", msg); } \
} while (0)

static void fill_mac(uint8_t mac[6], uint8_t pattern) {
    for (int i = 0; i < 6; i++) mac[i] = pattern + (uint8_t)i;
}

int main(void) {
    int fails = 0;

    // ── Test 1: encode/decode round-trip ──────────────────────────────
    {
        cm_forward_t in = {0};
        memset(in.flow_id, 0xF1, 16);
        in.hop_index = 0;
        in.total_hops = 3;
        in.segments_remaining = 2;
        fill_mac(in.segments[0], 0xA0);
        fill_mac(in.segments[1], 0xB0);
        in.inner_payload_len = 12;
        for (size_t i = 0; i < 12; i++) in.inner_payload[i] = (uint8_t)(i * 7 + 1);

        uint8_t buf[CM_PAYLOAD_SIZE] = {0};
        size_t used = 0;
        CHECK(cm_forward_encode(&in, buf, &used) == 0, "encode rc=0");
        CHECK(used == CM_FORWARD_HEADER_BYTES + 12,    "encoded bytes = header + payload");

        cm_forward_t out;
        CHECK(cm_forward_decode(buf, used, &out) == 0, "decode rc=0");
        CHECK(memcmp(out.flow_id, in.flow_id, 16) == 0, "flow_id round-trips");
        CHECK(out.hop_index == 0,                       "hop_index round-trips");
        CHECK(out.total_hops == 3,                      "total_hops round-trips");
        CHECK(out.segments_remaining == 2,              "segments_remaining round-trips");
        CHECK(memcmp(out.segments[0], in.segments[0], 6) == 0, "segments[0] round-trips");
        CHECK(memcmp(out.segments[1], in.segments[1], 6) == 0, "segments[1] round-trips");
        CHECK(out.inner_payload_len == 12,              "inner_payload_len round-trips");
        CHECK(memcmp(out.inner_payload, in.inner_payload, 12) == 0, "inner_payload round-trips");
    }

    // ── Test 2: step pops segments[0]; out_next_mac is the NEW head ──
    // After popping the current hop's marker (the 0x10 entry), segments
    // shift left so [0]=0x20 — that's the next downstream hop, which is
    // what `out_next_mac` should return.
    {
        cm_forward_t f = {0};
        memset(f.flow_id, 0xAA, 16);
        f.hop_index = 0;
        f.segments_remaining = 3;
        fill_mac(f.segments[0], 0x10);
        fill_mac(f.segments[1], 0x20);
        fill_mac(f.segments[2], 0x30);

        uint8_t expected_next[6]; fill_mac(expected_next, 0x20);  // post-pop head
        uint8_t next_mac[6];
        cm_forward_step_rc_t rc = cm_forward_step(&f, next_mac);
        CHECK(rc == CM_FWD_NEXT,                        "step returns NEXT");
        CHECK(memcmp(next_mac, expected_next, 6) == 0,  "next_mac is NEW segments[0] (next downstream hop)");
        CHECK(f.segments_remaining == 2,                "segments_remaining decremented");
        CHECK(f.hop_index == 1,                         "hop_index incremented");

        uint8_t after_shift_0[6]; fill_mac(after_shift_0, 0x20);
        uint8_t after_shift_1[6]; fill_mac(after_shift_1, 0x30);
        CHECK(memcmp(f.segments[0], after_shift_0, 6) == 0, "segments shifted: [1]→[0]");
        CHECK(memcmp(f.segments[1], after_shift_1, 6) == 0, "segments shifted: [2]→[1]");

        // Last two slots zeroed (since segments_remaining went 3→2).
        uint8_t zero[6] = {0};
        CHECK(memcmp(f.segments[3], zero, 6) == 0, "segments[3] zeroed");
    }

    // ── Test 3: step returns DELIVERED when no segments remain ───────
    {
        cm_forward_t f = {0};
        f.segments_remaining = 0;
        uint8_t next_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        cm_forward_step_rc_t rc = cm_forward_step(&f, next_mac);
        CHECK(rc == CM_FWD_DELIVERED,           "step returns DELIVERED");

        uint8_t zero[6] = {0};
        CHECK(memcmp(next_mac, zero, 6) == 0,   "next_mac zeroed on DELIVERED");
        CHECK(f.hop_index == 0,                 "hop_index unchanged on DELIVERED");
    }

    // ── Test 4: 3-segment chain step-step-step (last pop → DELIVERED) ─
    // segments=[AA,BB,CC]. Each step pops one entry; the THIRD step
    // empties the list and returns DELIVERED. After pop-1, next is BB;
    // after pop-2, next is CC; after pop-3, segments empty → DELIVERED.
    {
        cm_forward_t f = {0};
        f.segments_remaining = 3;
        fill_mac(f.segments[0], 0xAA);
        fill_mac(f.segments[1], 0xBB);
        fill_mac(f.segments[2], 0xCC);

        uint8_t macs[2][6];
        cm_forward_step_rc_t rc;

        rc = cm_forward_step(&f, macs[0]);  CHECK(rc == CM_FWD_NEXT, "step 1 → NEXT");
        rc = cm_forward_step(&f, macs[1]);  CHECK(rc == CM_FWD_NEXT, "step 2 → NEXT");
        rc = cm_forward_step(&f, NULL);     CHECK(rc == CM_FWD_DELIVERED, "step 3 → DELIVERED (consumed last segment)");

        // After step 1 (pop AA), new head is BB.
        // After step 2 (pop BB), new head is CC.
        uint8_t m0[6]; fill_mac(m0, 0xBB);
        uint8_t m1[6]; fill_mac(m1, 0xCC);
        CHECK(memcmp(macs[0], m0, 6) == 0, "after step 1, next_mac == BB-pattern");
        CHECK(memcmp(macs[1], m1, 6) == 0, "after step 2, next_mac == CC-pattern");

        CHECK(f.hop_index == 3, "hop_index advanced to 3");
        CHECK(f.segments_remaining == 0, "segments_remaining is 0 at destination");
    }

    // ── Test 5: max inner_payload (720 bytes) round-trips ─────────────
    {
        cm_forward_t in = {0};
        in.segments_remaining = 1;
        fill_mac(in.segments[0], 0xEE);
        in.inner_payload_len = CM_FORWARD_MAX_INNER_BYTES;
        for (size_t i = 0; i < CM_FORWARD_MAX_INNER_BYTES; i++) {
            in.inner_payload[i] = (uint8_t)((i * 31u + 13u) & 0xff);
        }

        uint8_t buf[CM_PAYLOAD_SIZE] = {0};
        size_t used;
        CHECK(cm_forward_encode(&in, buf, &used) == 0, "encode 720-byte payload");
        CHECK(used == CM_FORWARD_HEADER_BYTES + CM_FORWARD_MAX_INNER_BYTES, "used = 768");

        cm_forward_t out;
        CHECK(cm_forward_decode(buf, used, &out) == 0, "decode 720-byte payload");
        CHECK(out.inner_payload_len == CM_FORWARD_MAX_INNER_BYTES, "inner_payload_len round-trips");
        CHECK(memcmp(out.inner_payload, in.inner_payload, CM_FORWARD_MAX_INNER_BYTES) == 0, "720-byte content round-trips");
    }

    // ── Test 6: encode rejects oversize inner_payload_len ─────────────
    {
        cm_forward_t in = {0};
        in.inner_payload_len = CM_FORWARD_MAX_INNER_BYTES + 1;
        uint8_t buf[CM_PAYLOAD_SIZE];
        size_t used;
        CHECK(cm_forward_encode(&in, buf, &used) == -1, "encode rejects oversize inner_payload_len");
    }

    // ── Test 7: decode rejects oversize segments_remaining ────────────
    {
        uint8_t buf[CM_PAYLOAD_SIZE] = {0};
        buf[18] = CM_FORWARD_MAX_HOPS + 1;  // segments_remaining = 5
        cm_forward_t out;
        CHECK(cm_forward_decode(buf, 48, &out) == -1, "decode rejects segments_remaining > MAX_HOPS");
    }

    // ── Test 8: decode rejects in_used < header ───────────────────────
    {
        uint8_t buf[CM_PAYLOAD_SIZE] = {0};
        cm_forward_t out;
        CHECK(cm_forward_decode(buf, 47, &out) == -1, "decode rejects in_used < 48");
    }

    // ── Test 9: step → re-encode → decode → step (next-hop simulation) ──
    // 2 segments → 1 NEXT then DELIVERED at hop 2.
    {
        cm_forward_t source = {0};
        memset(source.flow_id, 0x77, 16);
        source.total_hops = 2;
        source.segments_remaining = 2;
        fill_mac(source.segments[0], 0xA1);  // hop1
        fill_mac(source.segments[1], 0xA2);  // hop2 (destination)
        const char *msg = "hello-srv6";
        memcpy(source.inner_payload, msg, strlen(msg));
        source.inner_payload_len = (uint32_t)strlen(msg);

        // Hop 1 perspective: step → NEXT, next_mac = A2 (the new head).
        uint8_t mac_to_hop2[6];
        cm_forward_step_rc_t rc1 = cm_forward_step(&source, mac_to_hop2);
        CHECK(rc1 == CM_FWD_NEXT, "hop1 step → NEXT");
        uint8_t expected_next[6]; fill_mac(expected_next, 0xA2);
        CHECK(memcmp(mac_to_hop2, expected_next, 6) == 0, "hop1's next_mac == A2 (new head)");

        // Hop 1 re-encodes and broadcasts. Hop 2 receives.
        uint8_t buf1[CM_PAYLOAD_SIZE] = {0}; size_t used1;
        cm_forward_encode(&source, buf1, &used1);

        cm_forward_t at_hop2;
        cm_forward_decode(buf1, used1, &at_hop2);
        CHECK(at_hop2.hop_index == 1,                          "hop2 sees hop_index=1");
        CHECK(at_hop2.segments_remaining == 1,                 "hop2 sees segments_remaining=1");
        CHECK(memcmp(at_hop2.flow_id, source.flow_id, 16) == 0,"flow_id preserved across hop");
        CHECK(memcmp(at_hop2.inner_payload, msg, strlen(msg)) == 0, "inner_payload preserved across hop");

        // Hop 2 perspective: step → DELIVERED (consumes the last segment).
        cm_forward_step_rc_t rc2 = cm_forward_step(&at_hop2, NULL);
        CHECK(rc2 == CM_FWD_DELIVERED, "hop2 step → DELIVERED");
        CHECK(at_hop2.hop_index == 2, "hop_index advanced to 2");
    }

    // ── Test 10: hop_verb round-trips (EVAL_RULES=1) ─────────────────────
    {
        cm_forward_t in = {0};
        in.hop_verb = CM_HOP_VERB_EVAL_RULES;
        in.segments_remaining = 1;
        fill_mac(in.segments[0], 0xCC);
        in.inner_payload_len = 4;
        in.inner_payload[0] = 'T'; in.inner_payload[1] = 'E';
        in.inner_payload[2] = 'S'; in.inner_payload[3] = 'T';

        uint8_t buf[CM_PAYLOAD_SIZE] = {0};
        size_t used;
        CHECK(cm_forward_encode(&in, buf, &used) == 0, "encode with EVAL_RULES verb");
        CHECK(buf[19] == (uint8_t)CM_HOP_VERB_EVAL_RULES,
              "wire byte 19 == CM_HOP_VERB_EVAL_RULES");

        cm_forward_t out = {0};
        CHECK(cm_forward_decode(buf, used, &out) == 0, "decode with EVAL_RULES verb");
        CHECK(out.hop_verb == CM_HOP_VERB_EVAL_RULES, "hop_verb round-trips EVAL_RULES");
    }

    // ── Test 11: hop_verb INSTALL_RULE preserved through step+re-encode ─
    {
        cm_forward_t in = {0};
        in.hop_verb = CM_HOP_VERB_INSTALL_RULE;
        in.segments_remaining = 2;
        fill_mac(in.segments[0], 0x11);
        fill_mac(in.segments[1], 0x22);
        in.inner_payload_len = 8;
        for (size_t i = 0; i < 8; i++) in.inner_payload[i] = (uint8_t)i;

        // Step (relay pops segments[0])
        uint8_t next[6];
        CHECK(cm_forward_step(&in, next) == CM_FWD_NEXT, "step before INSTALL_RULE re-encode");
        CHECK(in.hop_verb == CM_HOP_VERB_INSTALL_RULE, "hop_verb unchanged after step");

        // Re-encode + decode (simulating the relay re-broadcasting)
        uint8_t buf[CM_PAYLOAD_SIZE] = {0};
        size_t used;
        cm_forward_encode(&in, buf, &used);
        cm_forward_t at_next;
        CHECK(cm_forward_decode(buf, used, &at_next) == 0, "decode relayed INSTALL_RULE cell");
        CHECK(at_next.hop_verb == CM_HOP_VERB_INSTALL_RULE,
              "hop_verb INSTALL_RULE survives step + re-encode + decode");
    }

    // ── Test 12: hop_verb NONE (0) is backward-compat with old reserved=0 ──
    {
        // Simulate an old cell that has reserved=0 at offset 19.
        uint8_t buf[CM_PAYLOAD_SIZE] = {0};
        buf[18] = 1;    // segments_remaining = 1
        buf[19] = 0;    // old reserved byte, now hop_verb field
        fill_mac((uint8_t *)(buf + 24), 0xAB); // segments[0]
        // inner_payload_len = 0 (already zero)

        cm_forward_t out;
        CHECK(cm_forward_decode(buf, CM_FORWARD_HEADER_BYTES, &out) == 0, "decode old zero-reserved cell");
        CHECK(out.hop_verb == CM_HOP_VERB_NONE, "reserved=0 decoded as CM_HOP_VERB_NONE");
    }

    if (fails == 0) {
        printf("\nAll tests passed.\n");
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", fails);
        return 1;
    }
}
