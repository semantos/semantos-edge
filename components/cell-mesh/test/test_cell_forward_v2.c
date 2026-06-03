// test_cell_forward_v2.c — host test for forward.v2 encode/decode + burst step.
//
// Compile and run (no hardware, no IDF):
//   gcc -std=c11 -I../include \
//       ../src/cell_forward_v2.c ../src/cell_forward.c \
//       ../src/cell_wire.c ../src/cell_channel.c \
//       test_cell_forward_v2.c -o test_fwdv2_run && ./test_fwdv2_run

#include "cell_forward_v2.h"
#include "cell_wire.h"
#include "cell_channel.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

// ── Helpers ───────────────────────────────────────────────────────────────────

static int tests_run    = 0;
static int tests_passed = 0;

#define CHECK(expr) do { \
    tests_run++; \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s:%d — %s\n", __FILE__, __LINE__, #expr); \
    } else { \
        tests_passed++; \
    } \
} while (0)

static void fill_flow_id(uint8_t id[16], uint8_t byte) {
    memset(id, byte, 16);
}

static void fill_mac(uint8_t mac[6], uint8_t byte) {
    memset(mac, byte, 6);
}

// Build a minimal cm_channel_commitment_t for test purposes.
static cm_channel_commitment_t make_commitment(uint8_t chan_byte, uint32_t seq) {
    cm_channel_commitment_t c;
    memset(&c, 0, sizeof(c));
    memset(c.channel_id, chan_byte, 16);
    c.seq          = seq;
    c.device_share = 10;
    c.user_share   = 5;
    c.expiry_ms    = 0xFFFFFFFFFFFFFFFFULL;
    memset(c.cert_hash, chan_byte ^ 0xFF, 32);
    return c;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

static void test_budget(void) {
    printf("  test_budget\n");
    CHECK(CM_FORWARD_V2_MAX_INNER_BYTES == 744u);
    CHECK(CM_ROUTING_CONT_USED_BYTES    == 320u);
    // Forward.v2 gives 744B inner — 296 more than forward.v1's 448B
    CHECK(CM_FORWARD_V2_MAX_INNER_BYTES - 448u == 296u);
    CHECK(CM_FORWARD_V2_HEADER_BYTES == 24u);
}

static void test_cell_a_encode_decode(void) {
    printf("  test_cell_a_encode_decode\n");

    cm_forward_v2_t orig;
    memset(&orig, 0, sizeof(orig));
    fill_flow_id(orig.flow_id, 0xAB);
    orig.hop_index         = 1;
    orig.total_hops        = 3;
    orig.hop_verb          = CM_HOP_VERB_EVAL_RULES;
    orig.flags             = CM_FWD_V2_FLAG_ROUTING_CONT;
    orig.inner_payload_len = 100;
    memset(orig.inner_payload, 0xBE, 100);

    uint8_t buf[CM_PAYLOAD_SIZE];
    memset(buf, 0, sizeof(buf));
    size_t used = 0;
    CHECK(cm_forward_v2_encode(&orig, buf, &used) == 0);
    CHECK(used == CM_FORWARD_V2_HEADER_BYTES + 100u);

    cm_forward_v2_t decoded;
    CHECK(cm_forward_v2_decode(buf, used, &decoded) == 0);
    CHECK(memcmp(decoded.flow_id, orig.flow_id, 16) == 0);
    CHECK(decoded.hop_index         == 1);
    CHECK(decoded.total_hops        == 3);
    CHECK(decoded.hop_verb          == CM_HOP_VERB_EVAL_RULES);
    CHECK(decoded.flags & CM_FWD_V2_FLAG_ROUTING_CONT);
    CHECK(decoded.inner_payload_len == 100u);
    CHECK(memcmp(decoded.inner_payload, orig.inner_payload, 100) == 0);
}

static void test_cell_a_max_payload(void) {
    printf("  test_cell_a_max_payload\n");

    cm_forward_v2_t orig;
    memset(&orig, 0, sizeof(orig));
    fill_flow_id(orig.flow_id, 0x01);
    orig.inner_payload_len = CM_FORWARD_V2_MAX_INNER_BYTES;
    memset(orig.inner_payload, 0xCC, CM_FORWARD_V2_MAX_INNER_BYTES);

    uint8_t buf[CM_PAYLOAD_SIZE];
    size_t used = 0;
    CHECK(cm_forward_v2_encode(&orig, buf, &used) == 0);
    CHECK(used == CM_PAYLOAD_SIZE);  // exactly fills the 768-byte payload

    cm_forward_v2_t dec;
    CHECK(cm_forward_v2_decode(buf, used, &dec) == 0);
    CHECK(dec.inner_payload_len == CM_FORWARD_V2_MAX_INNER_BYTES);
    CHECK(memcmp(dec.inner_payload, orig.inner_payload, CM_FORWARD_V2_MAX_INNER_BYTES) == 0);
}

static void test_cell_a_overflow_rejected(void) {
    printf("  test_cell_a_overflow_rejected\n");

    cm_forward_v2_t orig;
    memset(&orig, 0, sizeof(orig));
    orig.inner_payload_len = CM_FORWARD_V2_MAX_INNER_BYTES + 1;  // too large

    uint8_t buf[CM_PAYLOAD_SIZE];
    size_t used = 0;
    CHECK(cm_forward_v2_encode(&orig, buf, &used) == -1);
}

static void test_cell_b_encode_decode(void) {
    printf("  test_cell_b_encode_decode\n");

    cm_routing_cont_t orig;
    memset(&orig, 0, sizeof(orig));
    fill_flow_id(orig.flow_id, 0xCD);
    orig.hop_index          = 0;
    orig.segments_remaining = 2;

    fill_mac(orig.segments[0], 0x11);
    fill_mac(orig.segments[1], 0x22);
    // slots 2 and 3 remain zero

    orig.hop_commitments[0] = make_commitment(0xAA, 1);
    orig.hop_commitments[1] = make_commitment(0xBB, 2);

    uint8_t buf[CM_PAYLOAD_SIZE];
    memset(buf, 0, sizeof(buf));
    size_t used = 0;
    CHECK(cm_routing_cont_encode(&orig, buf, &used) == 0);
    CHECK(used == CM_ROUTING_CONT_USED_BYTES);  // always 320

    cm_routing_cont_t dec;
    CHECK(cm_routing_cont_decode(buf, used, &dec) == 0);
    CHECK(memcmp(dec.flow_id, orig.flow_id, 16) == 0);
    CHECK(dec.hop_index          == 0);
    CHECK(dec.segments_remaining == 2);
    CHECK(memcmp(dec.segments[0], orig.segments[0], 6) == 0);
    CHECK(memcmp(dec.segments[1], orig.segments[1], 6) == 0);

    // Commitment round-trip (check a few key fields)
    CHECK(memcmp(dec.hop_commitments[0].channel_id,
                 orig.hop_commitments[0].channel_id, 16) == 0);
    CHECK(dec.hop_commitments[0].seq          == 1);
    CHECK(dec.hop_commitments[0].device_share == 10);
    CHECK(memcmp(dec.hop_commitments[1].channel_id,
                 orig.hop_commitments[1].channel_id, 16) == 0);
    CHECK(dec.hop_commitments[1].seq          == 2);
}

static void test_flow_id_correlation(void) {
    printf("  test_flow_id_correlation\n");

    // Both cells must share the same flow_id — verify encode preserves it.
    uint8_t fid[16] = { 0xDE,0xAD,0xBE,0xEF, 0,0,0,0, 0,0,0,0, 0x01,0x02,0x03,0x04 };

    cm_forward_v2_t pa;
    memset(&pa, 0, sizeof(pa));
    memcpy(pa.flow_id, fid, 16);
    pa.inner_payload_len = 0;

    cm_routing_cont_t pb;
    memset(&pb, 0, sizeof(pb));
    memcpy(pb.flow_id, fid, 16);

    uint8_t bufa[CM_PAYLOAD_SIZE], bufb[CM_PAYLOAD_SIZE];
    size_t ua, ub;
    CHECK(cm_forward_v2_encode(&pa, bufa, &ua) == 0);
    CHECK(cm_routing_cont_encode(&pb, bufb, &ub) == 0);

    // Verify the flow_id is at offset 0 in both encoded payloads
    CHECK(memcmp(bufa, fid, 16) == 0);
    CHECK(memcmp(bufb, fid, 16) == 0);
}

static void test_step_delivers(void) {
    printf("  test_step_delivers\n");

    cm_forward_v2_t pa;
    memset(&pa, 0, sizeof(pa));
    pa.hop_index          = 1;
    pa.inner_payload_len  = 42;
    memset(pa.inner_payload, 0xFF, 42);

    cm_routing_cont_t pb;
    memset(&pb, 0, sizeof(pb));
    pb.hop_index          = 1;
    pb.segments_remaining = 0;  // destination

    uint8_t next_mac[6];
    memset(next_mac, 0, 6);

    cm_forward_step_rc_t rc = cm_forward_v2_step(&pa, &pb, next_mac);
    CHECK(rc == CM_FWD_DELIVERED);
    // hop_index unchanged on delivery
    CHECK(pa.hop_index == 1);
    CHECK(pb.hop_index == 1);
}

static void test_step_next(void) {
    printf("  test_step_next\n");

    cm_forward_v2_t pa;
    memset(&pa, 0, sizeof(pa));
    fill_flow_id(pa.flow_id, 0x01);
    pa.hop_index   = 0;
    pa.total_hops  = 3;

    cm_routing_cont_t pb;
    memset(&pb, 0, sizeof(pb));
    memcpy(pb.flow_id, pa.flow_id, 16);
    pb.hop_index          = 0;
    pb.segments_remaining = 2;
    fill_mac(pb.segments[0], 0xAA);
    fill_mac(pb.segments[1], 0xBB);

    uint8_t next_mac[6];
    cm_forward_step_rc_t rc = cm_forward_v2_step(&pa, &pb, next_mac);

    CHECK(rc == CM_FWD_NEXT);
    // next_mac == segments[0] AFTER shift (v1-compatible: points to next relay)
    uint8_t expected_mac[6];
    fill_mac(expected_mac, 0xBB);  // 0xBB is now at segments[0] after consuming 0xAA
    CHECK(memcmp(next_mac, expected_mac, 6) == 0);
    // segments shifted: segments[0] now 0xBB, segments[1] zeroed
    uint8_t bb[6]; fill_mac(bb, 0xBB);
    CHECK(memcmp(pb.segments[0], bb, 6) == 0);
    uint8_t zeros[6] = {0};
    CHECK(memcmp(pb.segments[1], zeros, 6) == 0);
    CHECK(pb.segments_remaining == 1);
    CHECK(pa.hop_index == 1);
    CHECK(pb.hop_index == 1);
}

static void test_step_multi_hop(void) {
    printf("  test_step_multi_hop\n");

    cm_forward_v2_t pa;
    memset(&pa, 0, sizeof(pa));
    pa.hop_index   = 0;
    pa.total_hops  = 3;
    pa.inner_payload_len = 8;
    memcpy(pa.inner_payload, "PAYLOAD!", 8);

    cm_routing_cont_t pb;
    memset(&pb, 0, sizeof(pb));
    pb.hop_index          = 0;
    pb.segments_remaining = 2;
    fill_mac(pb.segments[0], 0x01);
    fill_mac(pb.segments[1], 0x02);

    uint8_t mac[6];

    // hop 0: remaining=2 → shift, remaining=1, next_mac = segments[0] after shift = 0x02
    CHECK(cm_forward_v2_step(&pa, &pb, mac) == CM_FWD_NEXT);
    CHECK(pa.hop_index == 1 && pb.hop_index == 1);
    CHECK(pb.segments_remaining == 1);
    uint8_t m2[6]; fill_mac(m2, 0x02);          // next relay (segments[0] post-shift)
    CHECK(memcmp(mac, m2, 6) == 0);

    // hop 1: remaining=1 → shift, remaining=0 → DELIVERED (v1-compatible, no re-emit needed)
    uint8_t zeros[6] = {0};
    CHECK(cm_forward_v2_step(&pa, &pb, mac) == CM_FWD_DELIVERED);
    CHECK(pa.hop_index == 2 && pb.hop_index == 2);
    CHECK(pb.segments_remaining == 0);
    CHECK(memcmp(mac, zeros, 6) == 0);           // next_mac zeroed on DELIVERED
    CHECK(memcmp(pa.inner_payload, "PAYLOAD!", 8) == 0);
}

static void test_step_mismatched_hop_index_rejected(void) {
    printf("  test_step_mismatched_hop_index_rejected\n");

    cm_forward_v2_t pa;
    cm_routing_cont_t pb;
    memset(&pa, 0, sizeof(pa)); memset(&pb, 0, sizeof(pb));
    pa.hop_index = 1;
    pb.hop_index = 2;  // mismatch
    pb.segments_remaining = 1;
    fill_mac(pb.segments[0], 0xAA);

    uint8_t mac[6];
    CHECK(cm_forward_v2_step(&pa, &pb, mac) == CM_FWD_ERR_BAD);
}

static void test_encode_decode_roundtrip_full(void) {
    printf("  test_encode_decode_roundtrip_full\n");

    // Build a 3-hop burst and round-trip both cells through encode/decode.
    cm_forward_v2_t pa;
    memset(&pa, 0, sizeof(pa));
    fill_flow_id(pa.flow_id, 0xEE);
    pa.hop_index   = 0;
    pa.total_hops  = 3;
    pa.hop_verb    = CM_HOP_VERB_EVAL_RULES;
    pa.flags       = CM_FWD_V2_FLAG_ROUTING_CONT;
    pa.inner_payload_len = 16;
    memset(pa.inner_payload, 0x42, 16);

    cm_routing_cont_t pb;
    memset(&pb, 0, sizeof(pb));
    memcpy(pb.flow_id, pa.flow_id, 16);
    pb.hop_index          = 0;
    pb.segments_remaining = 2;
    fill_mac(pb.segments[0], 0x11);
    fill_mac(pb.segments[1], 0x22);
    pb.hop_commitments[0] = make_commitment(0xAA, 100);
    pb.hop_commitments[1] = make_commitment(0xBB, 200);

    uint8_t bufa[CM_PAYLOAD_SIZE], bufb[CM_PAYLOAD_SIZE];
    size_t ua = 0, ub = 0;
    CHECK(cm_forward_v2_encode(&pa, bufa, &ua) == 0);
    CHECK(cm_routing_cont_encode(&pb, bufb, &ub) == 0);
    CHECK(ua == CM_FORWARD_V2_HEADER_BYTES + 16u);
    CHECK(ub == CM_ROUTING_CONT_USED_BYTES);

    cm_forward_v2_t dec_a;
    cm_routing_cont_t dec_b;
    CHECK(cm_forward_v2_decode(bufa, ua, &dec_a) == 0);
    CHECK(cm_routing_cont_decode(bufb, ub, &dec_b) == 0);

    // Cell A fields
    CHECK(memcmp(dec_a.flow_id, pa.flow_id, 16) == 0);
    CHECK(dec_a.hop_index   == 0);
    CHECK(dec_a.total_hops  == 3);
    CHECK(dec_a.hop_verb    == CM_HOP_VERB_EVAL_RULES);
    CHECK(dec_a.inner_payload_len == 16u);
    CHECK(memcmp(dec_a.inner_payload, pa.inner_payload, 16) == 0);

    // Cell B fields
    CHECK(memcmp(dec_b.flow_id, pb.flow_id, 16) == 0);
    CHECK(dec_b.segments_remaining == 2);
    uint8_t m1[6]; fill_mac(m1, 0x11);
    uint8_t m2[6]; fill_mac(m2, 0x22);
    CHECK(memcmp(dec_b.segments[0], m1, 6) == 0);
    CHECK(memcmp(dec_b.segments[1], m2, 6) == 0);
    CHECK(dec_b.hop_commitments[0].seq == 100u);
    CHECK(dec_b.hop_commitments[1].seq == 200u);

    // Now step the decoded pair and verify routing advances
    // New semantics: next_mac = segments[0] AFTER shift (next relay, not consumed one)
    uint8_t mac[6];
    CHECK(cm_forward_v2_step(&dec_a, &dec_b, mac) == CM_FWD_NEXT);
    CHECK(memcmp(mac, m2, 6) == 0);          // m2=0x22 is now at segments[0] after consuming m1
    CHECK(dec_a.hop_index == 1 && dec_b.hop_index == 1);
    CHECK(dec_b.segments_remaining == 1);
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(void) {
    printf("=== test_cell_forward_v2 ===\n");

    test_budget();
    test_cell_a_encode_decode();
    test_cell_a_max_payload();
    test_cell_a_overflow_rejected();
    test_cell_b_encode_decode();
    test_flow_id_correlation();
    test_step_delivers();
    test_step_next();
    test_step_multi_hop();
    test_step_mismatched_hop_index_rejected();
    test_encode_decode_roundtrip_full();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
