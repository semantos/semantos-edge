// test_cell_forward_v1.c — host smoke tests for forward.v1 (channel-gated).
//
// Run through the Zig C-ABI harness:
//   ../cell-mesh-zig/run-c-abi-tests.sh

#include "cell_forward_v1.h"
#include "cell_channel.h"
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

// Build a minimal commitment for testing: channel_id filled with `id_fill`,
// seq = `seq`, device_share = `ds`, user_share = `us`, expiry far future.
static void make_commitment(cm_channel_commitment_t *out,
                            uint8_t id_fill, uint32_t seq,
                            uint32_t ds, uint32_t us) {
    memset(out->channel_id, id_fill, 16);
    out->seq          = seq;
    out->device_share = ds;
    out->user_share   = us;
    out->expiry_ms    = UINT64_MAX;  // far future
}

int main(void) {
    int fails = 0;

    // ── Test 1: header constants sanity ─────────────────────────────
    // Header = 48 (v0 base) + 4*68 (commitments w/ cert_hash[32]) = 320.
    CHECK(CM_FORWARD_V1_HEADER_BYTES == 320u, "v1 header = 320 bytes");
    CHECK(CM_FORWARD_V1_COMMIT_ARRAY_BYTES == 272u, "commitment array = 272 bytes");
    CHECK(CM_FORWARD_V1_MAX_INNER_BYTES == 448u, "max inner payload = 448 bytes");
    CHECK(CM_FORWARD_V1_COMMIT_SLOT_BYTES == CM_CHANNEL_COMMITMENT_PAYLOAD_BYTES,
          "slot bytes == cm_channel_commitment wire size");

    // ── Test 2: encode/decode round-trip ────────────────────────────
    {
        cm_forward_v1_t in = {0};
        memset(in.flow_id, 0xF1, 16);
        in.hop_index = 0; in.total_hops = 2; in.segments_remaining = 2;
        fill_mac(in.segments[0], 0xB0);
        fill_mac(in.segments[1], 0xC0);
        in.hop_verb = CM_HOP_VERB_NONE;
        make_commitment(&in.hop_commitments[0], 0xAA, 1, 10, 90);
        make_commitment(&in.hop_commitments[1], 0xBB, 1, 10, 90);
        in.inner_payload_len = 6;
        memcpy(in.inner_payload, "hello!", 6);

        uint8_t buf[CM_PAYLOAD_SIZE] = {0};
        size_t used = 0;
        CHECK(cm_forward_v1_encode(&in, buf, &used) == 0, "encode rc=0");
        CHECK(used == CM_FORWARD_V1_HEADER_BYTES + 6, "used = header + 6");

        cm_forward_v1_t out;
        CHECK(cm_forward_v1_decode(buf, used, &out) == 0, "decode rc=0");
        CHECK(memcmp(out.flow_id, in.flow_id, 16) == 0, "flow_id round-trips");
        CHECK(out.hop_index == 0, "hop_index round-trips");
        CHECK(out.segments_remaining == 2, "segments_remaining round-trips");
        CHECK(out.hop_verb == CM_HOP_VERB_NONE, "hop_verb round-trips");
        CHECK(memcmp(out.segments[0], in.segments[0], 6) == 0, "segments[0] round-trips");
        CHECK(memcmp(out.segments[1], in.segments[1], 6) == 0, "segments[1] round-trips");
        CHECK(out.hop_commitments[0].seq == 1, "hop_commitments[0].seq round-trips");
        CHECK(out.hop_commitments[0].device_share == 10, "hop_commitments[0].device_share round-trips");
        CHECK(memcmp(out.hop_commitments[0].channel_id, in.hop_commitments[0].channel_id, 16) == 0,
              "hop_commitments[0].channel_id round-trips");
        CHECK(out.hop_commitments[1].seq == 1, "hop_commitments[1].seq round-trips");
        CHECK(out.inner_payload_len == 6, "inner_payload_len round-trips");
        CHECK(memcmp(out.inner_payload, "hello!", 6) == 0, "inner_payload round-trips");
    }

    // ── Test 3: step identical to v0 (2 segs → NEXT then DELIVERED) ──
    {
        cm_forward_v1_t f = {0};
        f.segments_remaining = 2;
        fill_mac(f.segments[0], 0xB0);
        fill_mac(f.segments[1], 0xC0);

        uint8_t next[6];
        cm_forward_step_rc_t rc = cm_forward_v1_step(&f, next);
        uint8_t expected_c[6]; fill_mac(expected_c, 0xC0);
        CHECK(rc == CM_FWD_NEXT, "step 1 → NEXT");
        CHECK(memcmp(next, expected_c, 6) == 0, "next_mac == 0xC0 after step");
        CHECK(f.hop_index == 1, "hop_index incremented to 1");
        CHECK(f.segments_remaining == 1, "segments_remaining decremented to 1");

        rc = cm_forward_v1_step(&f, NULL);
        CHECK(rc == CM_FWD_DELIVERED, "step 2 → DELIVERED");
        CHECK(f.hop_index == 2, "hop_index incremented to 2");
    }

    // ── Test 4: channel check — happy path (valid commitment) ────────
    // Simulate a relay receiving a v1 cell and applying its commitment.
    {
        cm_channel_t chan; cm_channel_init(&chan);
        // Open the channel so it's in the right state.
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0x01, 16);
        memset(op.peer_pubkey, 0x02, 33);
        op.total_capacity = 1000;
        op.initial_locktime_ms = 9999999999ULL;
        CHECK(cm_channel_apply_open(&chan, &op) == CM_CHAN_OK, "channel opened");

        // Build a forward.v1 cell with a valid commitment for hop 0.
        cm_forward_v1_t fwd = {0};
        fwd.segments_remaining = 2;
        fill_mac(fwd.segments[0], 0xB0);  // this relay's MAC
        make_commitment(&fwd.hop_commitments[0], 0x01, 1, 10, 90);

        // hop_index is 0 before step → check hop_commitments[0].
        cm_channel_rc_t crc = cm_channel_apply_commitment(
            &chan, &fwd.hop_commitments[fwd.hop_index], (uint64_t)-1 / 2);
        CHECK(crc == CM_CHAN_OK, "channel accepts valid hop-0 commitment");
        CHECK(chan.current_seq == 1, "channel seq updated to 1");
        CHECK(chan.device_share == 10, "channel device_share updated to 10");
    }

    // ── Test 5: channel check — stale-seq replay rejected ────────────
    {
        cm_channel_t chan; cm_channel_init(&chan);
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0xCC, 16);
        memset(op.peer_pubkey, 0xDD, 33);
        op.total_capacity = 500;
        op.initial_locktime_ms = 9999999999ULL;
        cm_channel_apply_open(&chan, &op);

        cm_channel_commitment_t cm1 = {0};
        memset(cm1.channel_id, 0xCC, 16);
        cm1.seq = 5; cm1.device_share = 50; cm1.user_share = 50; cm1.expiry_ms = UINT64_MAX;
        CHECK(cm_channel_apply_commitment(&chan, &cm1, 1000) == CM_CHAN_OK, "seq=5 accepted");

        // Same seq → stale
        CHECK(cm_channel_apply_commitment(&chan, &cm1, 1000) == CM_CHAN_ERR_STALE_SEQ,
              "replay (seq=5 again) rejected");

        // Lower seq → also stale
        cm_channel_commitment_t cm0 = cm1; cm0.seq = 3;
        CHECK(cm_channel_apply_commitment(&chan, &cm0, 1000) == CM_CHAN_ERR_STALE_SEQ,
              "lower seq=3 rejected");
    }

    // ── Test 6: channel check — monotone device_share enforced ───────
    {
        cm_channel_t chan; cm_channel_init(&chan);
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0xEE, 16);
        memset(op.peer_pubkey, 0xFF, 33);
        op.total_capacity = 1000;
        op.initial_locktime_ms = 9999999999ULL;
        cm_channel_apply_open(&chan, &op);

        cm_channel_commitment_t cm1 = {0};
        memset(cm1.channel_id, 0xEE, 16);
        cm1.seq = 1; cm1.device_share = 100; cm1.user_share = 100; cm1.expiry_ms = UINT64_MAX;
        cm_channel_apply_commitment(&chan, &cm1, 1000);

        // Lower device_share → non-monotone
        cm_channel_commitment_t cm2 = cm1;
        cm2.seq = 2; cm2.device_share = 50; cm2.user_share = 150;
        CHECK(cm_channel_apply_commitment(&chan, &cm2, 1000) == CM_CHAN_ERR_NON_MONO,
              "decreasing device_share rejected");
    }

    // ── Test 7: full 2-hop simulation with channel checks ────────────
    // Source builds a cell with [B,C] segments + commitments for B(hop0) and C(hop1).
    // B: applies hop0 commitment, steps, relays.
    // C: applies hop1 commitment, steps → DELIVERED.
    {
        // Set up two channels: one for B, one for C (both with same peer = source).
        cm_channel_t chan_b, chan_c;
        cm_channel_init(&chan_b); cm_channel_init(&chan_c);

        cm_channel_open_t op_b = {0}, op_c = {0};
        memset(op_b.channel_id, 0xB0, 16); memset(op_b.peer_pubkey, 0x42, 33);
        op_b.total_capacity = 10000; op_b.initial_locktime_ms = 9999999999ULL;
        memset(op_c.channel_id, 0xC0, 16); memset(op_c.peer_pubkey, 0x42, 33);
        op_c.total_capacity = 10000; op_c.initial_locktime_ms = 9999999999ULL;
        cm_channel_apply_open(&chan_b, &op_b);
        cm_channel_apply_open(&chan_c, &op_c);

        // Source builds forward.v1 with commitments for both hops.
        cm_forward_v1_t source = {0};
        memset(source.flow_id, 0x77, 16);
        source.total_hops = 2; source.segments_remaining = 2;
        fill_mac(source.segments[0], 0xB0);
        fill_mac(source.segments[1], 0xC0);
        source.hop_verb = CM_HOP_VERB_NONE;
        // hop 0 = B pays 25 sats
        memset(source.hop_commitments[0].channel_id, 0xB0, 16);
        source.hop_commitments[0].seq = 1;
        source.hop_commitments[0].device_share = 25;
        source.hop_commitments[0].user_share = 75;
        source.hop_commitments[0].expiry_ms = UINT64_MAX;
        // hop 1 = C pays 50 sats
        memset(source.hop_commitments[1].channel_id, 0xC0, 16);
        source.hop_commitments[1].seq = 1;
        source.hop_commitments[1].device_share = 50;
        source.hop_commitments[1].user_share = 50;
        source.hop_commitments[1].expiry_ms = UINT64_MAX;
        const char *msg = "payload-test";
        source.inner_payload_len = (uint32_t)strlen(msg);
        memcpy(source.inner_payload, msg, source.inner_payload_len);

        // ── Hop B perspective ────────────────────────────────────────
        // B applies hop_commitments[0] (its own commitment), then steps.
        cm_channel_rc_t b_rc = cm_channel_apply_commitment(
            &chan_b, &source.hop_commitments[source.hop_index], 1000);
        CHECK(b_rc == CM_CHAN_OK, "B: channel accepts hop-0 commitment");
        CHECK(chan_b.device_share == 25, "B: device_share = 25");

        uint8_t next_for_c[6];
        cm_forward_step_rc_t b_step = cm_forward_v1_step(&source, next_for_c);
        CHECK(b_step == CM_FWD_NEXT, "B: step → NEXT");
        uint8_t expected_c[6]; fill_mac(expected_c, 0xC0);
        CHECK(memcmp(next_for_c, expected_c, 6) == 0, "B: next_mac == 0xC0");
        CHECK(source.hop_index == 1, "B: hop_index advanced to 1");

        // B re-encodes + C receives.
        uint8_t buf[CM_PAYLOAD_SIZE] = {0}; size_t used;
        cm_forward_v1_encode(&source, buf, &used);
        cm_forward_v1_t at_c; cm_forward_v1_decode(buf, used, &at_c);

        CHECK(at_c.hop_index == 1, "C sees hop_index=1");
        CHECK(at_c.segments_remaining == 1, "C sees segments_remaining=1");
        // C's commitment is at hop_commitments[1] (= hop_index at this point).
        CHECK(memcmp(at_c.hop_commitments[1].channel_id, "\xC0\xC0\xC0\xC0\xC0\xC0\xC0\xC0"
                     "\xC0\xC0\xC0\xC0\xC0\xC0\xC0\xC0", 16) == 0,
              "C: hop_commitments[1].channel_id = 0xC0...");

        // ── Hop C perspective ────────────────────────────────────────
        cm_channel_rc_t c_rc = cm_channel_apply_commitment(
            &chan_c, &at_c.hop_commitments[at_c.hop_index], 1000);
        CHECK(c_rc == CM_CHAN_OK, "C: channel accepts hop-1 commitment");
        CHECK(chan_c.device_share == 50, "C: device_share = 50");

        cm_forward_step_rc_t c_step = cm_forward_v1_step(&at_c, NULL);
        CHECK(c_step == CM_FWD_DELIVERED, "C: step → DELIVERED");
        CHECK(at_c.hop_index == 2, "C: hop_index advanced to 2");
        CHECK(memcmp(at_c.inner_payload, msg, strlen(msg)) == 0, "C: inner_payload intact");
    }

    // ── Test 8: decode rejects in_used < v1 header ────────────────────
    {
        uint8_t buf[CM_PAYLOAD_SIZE] = {0};
        cm_forward_v1_t out;
        CHECK(cm_forward_v1_decode(buf, CM_FORWARD_V1_HEADER_BYTES - 1, &out) == -1,
              "decode rejects in_used < 320");
    }

    // ── Test 9: encode rejects oversize inner_payload_len ─────────────
    {
        cm_forward_v1_t in = {0};
        in.inner_payload_len = CM_FORWARD_V1_MAX_INNER_BYTES + 1;
        uint8_t buf[CM_PAYLOAD_SIZE]; size_t used;
        CHECK(cm_forward_v1_encode(&in, buf, &used) == -1,
              "encode rejects inner_payload_len > 448");
    }

    // ── Test 10: commitment channel_id mismatch rejected ──────────────
    {
        cm_channel_t chan; cm_channel_init(&chan);
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0xAA, 16); memset(op.peer_pubkey, 0x01, 33);
        op.total_capacity = 500; op.initial_locktime_ms = 9999999999ULL;
        cm_channel_apply_open(&chan, &op);

        cm_channel_commitment_t cm1 = {0};
        memset(cm1.channel_id, 0xBB, 16);  // WRONG channel_id
        cm1.seq = 1; cm1.device_share = 10; cm1.user_share = 10; cm1.expiry_ms = UINT64_MAX;
        CHECK(cm_channel_apply_commitment(&chan, &cm1, 1000) == CM_CHAN_ERR_BAD_ID,
              "wrong channel_id rejected");
    }

    if (fails == 0) { printf("\nAll tests passed.\n"); return 0; }
    else            { printf("\n%d test(s) failed.\n", fails); return 1; }
}
