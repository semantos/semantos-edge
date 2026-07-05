/**
 * test_cell_channel_onchain.c — host tests for the BSV on-chain channel binding.
 *
 * Tests the cm_channel_validate_utxo_ref hook that validates the channel_id
 * convention: channel_id == first 16 bytes of the funding txid (display order).
 * Also tests the full accumulation flow with a txid-derived channel_id and
 * verifies settlement threshold detection at the bridge level.
 *
 * Run through the Zig C-ABI harness:
 *   ../cell-mesh-zig/run-c-abi-tests.sh
 */

#include "cell_channel.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

// ── Helpers ────────────────────────────────────────────────────────────

static int  s_pass = 0;
static int  s_fail = 0;

#define CHECK(cond, label) do {                                      \
    if (cond) { printf("  PASS %s\n", label); s_pass++; }           \
    else       { printf("  FAIL %s  (line %d)\n", label, __LINE__); s_fail++; } \
} while (0)

// Fake txid: 32-byte test vector (display order).
static const uint8_t TEST_TXID[32] = {
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
};

// channel_id = first 16 bytes of TEST_TXID
static const uint8_t TEST_CHANNEL_ID[16] = {
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
};

static const uint8_t ZERO_CHANNEL_ID[16] = { 0 };

// Dummy wallet pubkey (33 bytes, starts with 0x02 = compressed even).
static const uint8_t WALLET_PK[33] = {
    0x02,
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
};

// ── T1: validate_utxo_ref basics ───────────────────────────────────────

static void test_validate_utxo_ref(void) {
    printf("\n[T1] cm_channel_validate_utxo_ref\n");

    // Correct channel_id from TEST_TXID
    CHECK(cm_channel_validate_utxo_ref(TEST_CHANNEL_ID, TEST_TXID),
          "correct channel_id matches txid");

    // Wrong channel_id (all zeros) should not match
    CHECK(!cm_channel_validate_utxo_ref(ZERO_CHANNEL_ID, TEST_TXID),
          "zero channel_id does not match txid");

    // NULL inputs return false
    CHECK(!cm_channel_validate_utxo_ref(NULL, TEST_TXID),
          "NULL channel_id → false");
    CHECK(!cm_channel_validate_utxo_ref(TEST_CHANNEL_ID, NULL),
          "NULL txid → false");

    // Partial match: change byte 15 — should fail
    uint8_t partial[16];
    memcpy(partial, TEST_CHANNEL_ID, 16);
    partial[15] ^= 0x01;
    CHECK(!cm_channel_validate_utxo_ref(partial, TEST_TXID),
          "partial-match channel_id fails");

    // Only first 16 bytes matter — bytes 16-31 of txid are irrelevant
    uint8_t txid2[32];
    memcpy(txid2, TEST_TXID, 32);
    txid2[16] ^= 0xff;  // change byte 16 only
    CHECK(cm_channel_validate_utxo_ref(TEST_CHANNEL_ID, txid2),
          "txid bytes 16-31 don't affect channel_id match");
}

// ── T2: open channel with txid-derived channel_id ─────────────────────

static void test_channel_open_with_txid_id(void) {
    printf("\n[T2] channel open with txid-derived channel_id\n");

    cm_channel_t ch;
    cm_channel_open_t op;
    memset(&op, 0, sizeof(op));
    memcpy(op.channel_id,  TEST_CHANNEL_ID, 16);
    memcpy(op.peer_pubkey, WALLET_PK, 33);
    op.total_capacity      = 10000;
    op.initial_locktime_ms = (uint64_t)9999999999999ULL;

    cm_channel_init(&ch);
    cm_channel_rc_t rc = cm_channel_apply_open(&ch, &op);
    CHECK(rc == CM_CHAN_OK, "open with txid-derived channel_id: CM_CHAN_OK");
    CHECK(ch.state == CM_CHAN_OPEN, "state == OPEN after open");
    CHECK(memcmp(ch.channel_id, TEST_CHANNEL_ID, 16) == 0, "channel_id stored correctly");
    // Validate the utxo ref matches
    CHECK(cm_channel_validate_utxo_ref(ch.channel_id, TEST_TXID),
          "stored channel_id validates against funding txid");
}

// ── T3: 5-hop accumulation with real channel_id ──────────────────────

static void test_five_hop_accumulation(void) {
    printf("\n[T3] 5-hop commitment accumulation\n");

    cm_channel_t ch;
    cm_channel_open_t op;
    memset(&op, 0, sizeof(op));
    memcpy(op.channel_id,  TEST_CHANNEL_ID, 16);
    memcpy(op.peer_pubkey, WALLET_PK, 33);
    op.total_capacity      = 10000;
    op.initial_locktime_ms = (uint64_t)9999999999999ULL;

    cm_channel_init(&ch);
    cm_channel_apply_open(&ch, &op);

    const uint64_t FAR_FUTURE_MS = 9999999999999ULL;
    // Simulate 5 hops: each adds device_share=10, seq monotonically increases.
    for (int hop = 1; hop <= 5; hop++) {
        cm_channel_commitment_t cm;
        memcpy(cm.channel_id, TEST_CHANNEL_ID, 16);
        cm.seq          = (uint32_t)hop;
        cm.device_share = (uint32_t)(hop * 10);
        cm.user_share   = (uint32_t)(10000 - hop * 10);
        cm.expiry_ms    = FAR_FUTURE_MS;

        cm_channel_rc_t rc = cm_channel_apply_commitment(&ch, &cm, 0 /* now=0, expiry far future */);
        CHECK(rc == CM_CHAN_OK, hop == 1 ? "hop 1: CM_CHAN_OK"
                              : hop == 2 ? "hop 2: CM_CHAN_OK"
                              : hop == 3 ? "hop 3: CM_CHAN_OK"
                              : hop == 4 ? "hop 4: CM_CHAN_OK"
                              :            "hop 5: CM_CHAN_OK");
    }
    CHECK(ch.device_share == 50, "device_share == 50 after 5 hops");
    CHECK(ch.current_seq  ==  5, "current_seq == 5 after 5 hops");
    CHECK(ch.commitments_received == 5, "5 commitments received");

    // Bridge-side threshold: device_share >= 50 triggers settlement.
    // (Mirrored here as a pure integer check — bridge's accumulateHop does this.)
    const uint32_t SETTLE_THRESHOLD = 50;
    CHECK(ch.device_share >= SETTLE_THRESHOLD, "settlement threshold crossed at hop 5");
}

// ── T4: replay protection with txid-derived channel_id ───────────────

static void test_replay_protection(void) {
    printf("\n[T4] replay protection (stale seq) with real channel_id\n");

    cm_channel_t ch;
    cm_channel_open_t op;
    memset(&op, 0, sizeof(op));
    memcpy(op.channel_id,  TEST_CHANNEL_ID, 16);
    memcpy(op.peer_pubkey, WALLET_PK, 33);
    op.total_capacity      = 10000;
    op.initial_locktime_ms = (uint64_t)9999999999999ULL;

    cm_channel_init(&ch);
    cm_channel_apply_open(&ch, &op);

    cm_channel_commitment_t cm;
    memcpy(cm.channel_id, TEST_CHANNEL_ID, 16);
    cm.seq          = 1;
    cm.device_share = 10;
    cm.user_share   = 9990;
    cm.expiry_ms    = (uint64_t)9999999999999ULL;

    cm_channel_apply_commitment(&ch, &cm, 0);
    CHECK(ch.current_seq == 1, "seq=1 accepted");

    // Re-send the same commitment — stale seq must be rejected.
    cm_channel_rc_t rc = cm_channel_apply_commitment(&ch, &cm, 0);
    CHECK(rc == CM_CHAN_ERR_STALE_SEQ, "duplicate commitment → CM_CHAN_ERR_STALE_SEQ");
    CHECK(ch.current_seq == 1, "seq unchanged after stale replay");
}

// ── T5: wrong channel_id rejected ────────────────────────────────────

static void test_wrong_channel_id_rejected(void) {
    printf("\n[T5] commitment with wrong channel_id rejected\n");

    cm_channel_t ch;
    cm_channel_open_t op;
    memset(&op, 0, sizeof(op));
    memcpy(op.channel_id,  TEST_CHANNEL_ID, 16);
    memcpy(op.peer_pubkey, WALLET_PK, 33);
    op.total_capacity      = 10000;
    op.initial_locktime_ms = (uint64_t)9999999999999ULL;

    cm_channel_init(&ch);
    cm_channel_apply_open(&ch, &op);

    cm_channel_commitment_t cm;
    memset(cm.channel_id, 0xff, 16);  // wrong channel_id
    cm.seq          = 1;
    cm.device_share = 10;
    cm.user_share   = 9990;
    cm.expiry_ms    = (uint64_t)9999999999999ULL;

    cm_channel_rc_t rc = cm_channel_apply_commitment(&ch, &cm, 0);
    CHECK(rc == CM_CHAN_ERR_BAD_ID, "wrong channel_id → CM_CHAN_ERR_BAD_ID");
}

// ── T6: close at final seq ────────────────────────────────────────────

static void test_channel_close(void) {
    printf("\n[T6] channel close at final seq\n");

    cm_channel_t ch;
    cm_channel_open_t op;
    memset(&op, 0, sizeof(op));
    memcpy(op.channel_id,  TEST_CHANNEL_ID, 16);
    memcpy(op.peer_pubkey, WALLET_PK, 33);
    op.total_capacity      = 10000;
    op.initial_locktime_ms = (uint64_t)9999999999999ULL;

    cm_channel_init(&ch);
    cm_channel_apply_open(&ch, &op);

    cm_channel_commitment_t cm;
    memcpy(cm.channel_id, TEST_CHANNEL_ID, 16);
    cm.seq = 3; cm.device_share = 30; cm.user_share = 9970;
    cm.expiry_ms = (uint64_t)9999999999999ULL;
    cm_channel_apply_commitment(&ch, &cm, 0);

    cm_channel_close_t cl;
    memcpy(cl.channel_id, TEST_CHANNEL_ID, 16);
    cl.final_seq          = 3;
    cl.final_device_share = 30;

    cm_channel_rc_t rc = cm_channel_apply_close(&ch, &cl);
    CHECK(rc == CM_CHAN_OK, "close at seq=3 device_share=30: CM_CHAN_OK");
    CHECK(ch.state == CM_CHAN_CLOSED, "state == CLOSED after close");
}

// ── main ───────────────────────────────────────────────────────────────

int main(void) {
    printf("=== test_cell_channel_onchain ===\n");
    test_validate_utxo_ref();
    test_channel_open_with_txid_id();
    test_five_hop_accumulation();
    test_replay_protection();
    test_wrong_channel_id_rejected();
    test_channel_close();
    printf("\n=== %d passed, %d failed ===\n", s_pass, s_fail);
    return s_fail ? 1 : 0;
}
