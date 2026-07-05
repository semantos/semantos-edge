// test_cell_channel.c — host smoke tests for the payment-channel state machine.
//
// Run through the Zig C-ABI harness:
//   ../cell-mesh-zig/run-c-abi-tests.sh

#include "cell_channel.h"
#include "cell_wire.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); fails++; } \
    else         { printf("ok:   %s\n", msg); } \
} while (0)

static void fill_pubkey(uint8_t pk[33], uint8_t pattern) {
    pk[0] = 0x02; // compressed-even prefix; arbitrary for tests
    for (int i = 1; i < 33; i++) pk[i] = pattern;
}

int main(void) {
    int fails = 0;

    // ── Test 1: encode/decode round-trip — channel_open ─────────────────
    {
        cm_channel_open_t in = {0};
        memset(in.channel_id, 0x11, 16);
        fill_pubkey(in.peer_pubkey, 0xAB);
        in.initial_locktime_ms = 0x0123456789ABCDEFULL;
        in.total_capacity = 1000;

        uint8_t buf[CM_CHANNEL_OPEN_PAYLOAD_BYTES];
        CHECK(cm_channel_open_encode(&in, buf) == 0, "open encode rc=0");
        cm_channel_open_t out;
        CHECK(cm_channel_open_decode(buf, &out) == 0, "open decode rc=0");
        CHECK(memcmp(out.channel_id,  in.channel_id,  16) == 0, "open channel_id round-trips");
        CHECK(memcmp(out.peer_pubkey, in.peer_pubkey, 33) == 0, "open peer_pubkey round-trips");
        CHECK(out.initial_locktime_ms == in.initial_locktime_ms, "open locktime_ms round-trips");
        CHECK(out.total_capacity == in.total_capacity,           "open capacity round-trips");
    }

    // ── Test 2: encode/decode round-trip — channel_commitment ──────────
    {
        cm_channel_commitment_t in = {0};
        memset(in.channel_id, 0x22, 16);
        in.seq          = 5;
        in.device_share = 250;
        in.user_share   = 750;
        in.expiry_ms    = 0x55667788AABBCCDDULL;

        uint8_t buf[CM_CHANNEL_COMMITMENT_PAYLOAD_BYTES];
        cm_channel_commitment_encode(&in, buf);
        cm_channel_commitment_t out;
        cm_channel_commitment_decode(buf, &out);
        CHECK(memcmp(out.channel_id, in.channel_id, 16) == 0, "commitment channel_id round-trips");
        CHECK(out.seq          == 5,                          "commitment seq round-trips");
        CHECK(out.device_share == 250,                        "commitment device_share round-trips");
        CHECK(out.user_share   == 750,                        "commitment user_share round-trips");
        CHECK(out.expiry_ms    == in.expiry_ms,               "commitment expiry_ms round-trips");
    }

    // ── Test 3: encode/decode round-trip — channel_close ───────────────
    {
        cm_channel_close_t in = {0};
        memset(in.channel_id, 0x33, 16);
        in.final_seq          = 42;
        in.final_device_share = 999;
        uint8_t buf[CM_CHANNEL_CLOSE_PAYLOAD_BYTES];
        cm_channel_close_encode(&in, buf);
        cm_channel_close_t out;
        cm_channel_close_decode(buf, &out);
        CHECK(memcmp(out.channel_id, in.channel_id, 16) == 0, "close channel_id round-trips");
        CHECK(out.final_seq          == 42,                   "close final_seq round-trips");
        CHECK(out.final_device_share == 999,                  "close final_device_share round-trips");
    }

    // ── Test 4: happy-path lifecycle CLOSED -> OPEN -> ACTIVE -> CLOSED ─
    {
        cm_channel_t c; cm_channel_init(&c);
        CHECK(c.state == CM_CHAN_CLOSED, "init state is CLOSED");

        cm_channel_open_t op = {0};
        memset(op.channel_id, 0x42, 16);
        fill_pubkey(op.peer_pubkey, 0xBE);
        op.total_capacity = 1000;
        op.initial_locktime_ms = 5000;
        CHECK(cm_channel_apply_open(&c, &op) == CM_CHAN_OK, "apply_open succeeds");
        CHECK(c.state == CM_CHAN_OPEN, "state is OPEN");

        cm_channel_commitment_t cm1 = {0};
        memcpy(cm1.channel_id, op.channel_id, 16);
        cm1.seq          = 1;
        cm1.device_share = 100;
        cm1.user_share   = 900;
        cm1.expiry_ms    = 10000;
        CHECK(cm_channel_apply_commitment(&c, &cm1, 1000) == CM_CHAN_OK, "first commitment succeeds");
        CHECK(c.state == CM_CHAN_ACTIVE, "state is ACTIVE after commitment");
        CHECK(c.current_seq == 1,         "current_seq = 1");
        CHECK(c.device_share == 100,      "device_share = 100");

        // Update — seq increases, device_share increases, user decreases.
        cm_channel_commitment_t cm2 = cm1;
        cm2.seq          = 2;
        cm2.device_share = 250;
        cm2.user_share   = 750;
        cm2.expiry_ms    = 12000;
        CHECK(cm_channel_apply_commitment(&c, &cm2, 1500) == CM_CHAN_OK, "monotonic commitment succeeds");
        CHECK(c.current_seq == 2 && c.device_share == 250,                "state advances");

        // Close referencing the latest commitment.
        cm_channel_close_t cl = {0};
        memcpy(cl.channel_id, op.channel_id, 16);
        cl.final_seq          = 2;
        cl.final_device_share = 250;
        CHECK(cm_channel_apply_close(&c, &cl) == CM_CHAN_OK, "apply_close succeeds");
        CHECK(c.state == CM_CHAN_CLOSED, "state is CLOSED after close");
    }

    // ── Test 5: stale seq rejected — LINEARITY ────────────────────────
    {
        cm_channel_t c; cm_channel_init(&c);
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0xAA, 16);
        op.total_capacity = 1000;
        cm_channel_apply_open(&c, &op);

        cm_channel_commitment_t cm1 = {0};
        memcpy(cm1.channel_id, op.channel_id, 16);
        cm1.seq = 5; cm1.device_share = 100; cm1.user_share = 900; cm1.expiry_ms = 10000;
        cm_channel_apply_commitment(&c, &cm1, 1000);

        // Replay with same seq — must reject.
        CHECK(cm_channel_apply_commitment(&c, &cm1, 1500) == CM_CHAN_ERR_STALE_SEQ, "same-seq replay rejected");

        // Older seq — must reject.
        cm_channel_commitment_t cm_old = cm1;
        cm_old.seq = 3;
        CHECK(cm_channel_apply_commitment(&c, &cm_old, 1500) == CM_CHAN_ERR_STALE_SEQ, "older seq rejected");
        CHECK(c.commitments_rejected == 2, "two rejections counted");
    }

    // ── Test 6: device_share decrease rejected — LINEARITY ────────────
    {
        cm_channel_t c; cm_channel_init(&c);
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0xBB, 16);
        op.total_capacity = 1000;
        cm_channel_apply_open(&c, &op);

        cm_channel_commitment_t cm1 = {0};
        memcpy(cm1.channel_id, op.channel_id, 16);
        cm1.seq = 1; cm1.device_share = 500; cm1.user_share = 500; cm1.expiry_ms = 10000;
        cm_channel_apply_commitment(&c, &cm1, 1000);

        // Attempt to decrease device_share.
        cm_channel_commitment_t cm2 = cm1;
        cm2.seq = 2;
        cm2.device_share = 400;  // DOWN
        cm2.user_share   = 600;
        CHECK(cm_channel_apply_commitment(&c, &cm2, 1500) == CM_CHAN_ERR_NON_MONO, "device_share decrease rejected");
        CHECK(c.current_seq == 1, "state unchanged after rejection");
    }

    // ── Test 7: overflow rejected ────────────────────────────────────
    {
        cm_channel_t c; cm_channel_init(&c);
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0xCC, 16);
        op.total_capacity = 100;
        cm_channel_apply_open(&c, &op);

        cm_channel_commitment_t cm1 = {0};
        memcpy(cm1.channel_id, op.channel_id, 16);
        cm1.seq = 1; cm1.device_share = 60; cm1.user_share = 50; cm1.expiry_ms = 10000;
        CHECK(cm_channel_apply_commitment(&c, &cm1, 1000) == CM_CHAN_ERR_OVERFLOW, "60+50>100 rejected");
    }

    // ── Test 8: expiry rejected ─────────────────────────────────────
    {
        cm_channel_t c; cm_channel_init(&c);
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0xDD, 16);
        op.total_capacity = 1000;
        cm_channel_apply_open(&c, &op);

        cm_channel_commitment_t cm1 = {0};
        memcpy(cm1.channel_id, op.channel_id, 16);
        cm1.seq = 1; cm1.device_share = 100; cm1.user_share = 900;
        cm1.expiry_ms = 500;        // already in the past at now=1000
        CHECK(cm_channel_apply_commitment(&c, &cm1, 1000) == CM_CHAN_ERR_EXPIRED, "stale-on-arrival rejected");
    }

    // ── Test 9: wrong channel_id rejected ────────────────────────────
    {
        cm_channel_t c; cm_channel_init(&c);
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0xEE, 16);
        op.total_capacity = 1000;
        cm_channel_apply_open(&c, &op);

        cm_channel_commitment_t cm1 = {0};
        memset(cm1.channel_id, 0xEF, 16);  // wrong id
        cm1.seq = 1; cm1.device_share = 100; cm1.user_share = 900; cm1.expiry_ms = 10000;
        CHECK(cm_channel_apply_commitment(&c, &cm1, 1000) == CM_CHAN_ERR_BAD_ID, "wrong channel_id rejected");
    }

    // ── Test 10: open while already open is rejected ─────────────────
    {
        cm_channel_t c; cm_channel_init(&c);
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0x01, 16);
        op.total_capacity = 1000;
        CHECK(cm_channel_apply_open(&c, &op) == CM_CHAN_OK,           "first open ok");
        CHECK(cm_channel_apply_open(&c, &op) == CM_CHAN_ERR_BAD_STATE, "second open rejected (BAD_STATE)");
    }

    // ── Test 11: close requires final_seq matches current_seq ────────
    {
        cm_channel_t c; cm_channel_init(&c);
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0x02, 16);
        op.total_capacity = 1000;
        cm_channel_apply_open(&c, &op);

        cm_channel_commitment_t cm1 = {0};
        memcpy(cm1.channel_id, op.channel_id, 16);
        cm1.seq = 7; cm1.device_share = 200; cm1.user_share = 800; cm1.expiry_ms = 10000;
        cm_channel_apply_commitment(&c, &cm1, 1000);

        // Close with mismatched final_seq.
        cm_channel_close_t cl = {0};
        memcpy(cl.channel_id, op.channel_id, 16);
        cl.final_seq          = 6;       // != current_seq (7)
        cl.final_device_share = 200;
        CHECK(cm_channel_apply_close(&c, &cl) == CM_CHAN_ERR_SEQ_MATCH, "mismatched final_seq rejected");
        CHECK(c.state == CM_CHAN_ACTIVE, "state unchanged after bad close");

        // Correct close.
        cl.final_seq = 7;
        CHECK(cm_channel_apply_close(&c, &cl) == CM_CHAN_OK, "matched close succeeds");
        CHECK(c.state == CM_CHAN_CLOSED, "state is CLOSED");
    }

    // ── Test 12: expiry tick — ACTIVE -> EXPIRED ─────────────────────
    {
        cm_channel_t c; cm_channel_init(&c);
        cm_channel_open_t op = {0};
        memset(op.channel_id, 0x03, 16);
        op.total_capacity = 1000;
        cm_channel_apply_open(&c, &op);

        cm_channel_commitment_t cm1 = {0};
        memcpy(cm1.channel_id, op.channel_id, 16);
        cm1.seq = 1; cm1.device_share = 100; cm1.user_share = 900; cm1.expiry_ms = 2000;
        cm_channel_apply_commitment(&c, &cm1, 1000);
        CHECK(c.state == CM_CHAN_ACTIVE, "active before expiry");

        cm_channel_tick_expiry(&c, 1500);
        CHECK(c.state == CM_CHAN_ACTIVE, "tick before expiry leaves state alone");

        cm_channel_tick_expiry(&c, 2500);
        CHECK(c.state == CM_CHAN_EXPIRED, "tick after expiry transitions to EXPIRED");

        // Close still works from EXPIRED.
        cm_channel_close_t cl = {0};
        memcpy(cl.channel_id, op.channel_id, 16);
        cl.final_seq = 1;
        cl.final_device_share = 100;
        CHECK(cm_channel_apply_close(&c, &cl) == CM_CHAN_OK,  "close from EXPIRED succeeds");
        CHECK(c.state == CM_CHAN_CLOSED,                       "state is CLOSED");
    }

    if (fails == 0) {
        printf("\nAll tests passed.\n");
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", fails);
        return 1;
    }
}
