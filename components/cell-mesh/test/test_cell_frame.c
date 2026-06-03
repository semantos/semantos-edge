// test_cell_frame.c — host-side smoke tests for cell_frame split/reassemble.
//
// Compile:
//   cc -I ../include test_cell_frame.c ../src/cell_frame.c ../src/cell_wire.c -o test_cell_frame

#include "cell_frame.h"
#include "cell_wire.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); fails++; } \
    else         { printf("ok:   %s\n", msg); } \
} while (0)

static void make_test_cell(uint8_t cell[CM_CELL_SIZE], uint8_t pattern) {
    cm_cell_init(cell);
    memset(cm_type_hash_mut(cell), pattern, 32);
    cm_set_timestamp_ms(cell, 1700000000000ULL + pattern);
    // Fill payload with a deterministic pattern so we can verify bit-exact reassembly.
    uint8_t *payload = cm_payload_mut(cell);
    for (size_t i = 0; i < CM_PAYLOAD_SIZE; i++) {
        payload[i] = (uint8_t)((i * 31u + pattern) & 0xff);
    }
}

static void make_test_sig(uint8_t sig[CM_FRAME_SIG_SIZE], uint8_t pattern) {
    for (size_t i = 0; i < CM_FRAME_SIG_SIZE; i++) {
        sig[i] = (uint8_t)((i * 17u + pattern) ^ 0xA5);
    }
}

int main(void) {
    int fails = 0;

    // ── Test 1: split produces 5 frames totalling 1088 bytes of payload ──
    {
        uint8_t cell[CM_CELL_SIZE];  make_test_cell(cell, 0x11);
        uint8_t sig[CM_FRAME_SIG_SIZE]; make_test_sig(sig, 0x11);

        cm_frame_t frames[CM_FRAMES_PER_CELL];
        size_t n = cm_frame_split(cell, sig, 0xDEAD0001u, frames);
        CHECK(n == CM_FRAMES_PER_CELL, "split produces 5 frames");

        size_t total_payload = 0;
        for (size_t i = 0; i < n; i++) {
            CHECK(frames[i].len >= CM_FRAME_HEADER_SIZE, "frame length covers header");
            total_payload += (frames[i].len - CM_FRAME_HEADER_SIZE);
        }
        CHECK(total_payload == CM_FRAME_SIGNED_CELL, "total payload across frames == 1088");
    }

    // ── Test 2: split frame headers are well-formed ─────────────────────
    {
        uint8_t cell[CM_CELL_SIZE];  make_test_cell(cell, 0x22);
        uint8_t sig[CM_FRAME_SIG_SIZE]; make_test_sig(sig, 0x22);
        cm_frame_t frames[CM_FRAMES_PER_CELL];
        cm_frame_split(cell, sig, 0xCAFE0002u, frames);

        for (size_t i = 0; i < CM_FRAMES_PER_CELL; i++) {
            uint8_t *b = frames[i].bytes;
            CHECK(cm_read_u16(b + 0) == CM_FRAME_MAGIC, "magic 0x5C5C present in each frame");
            CHECK((b[2] & CM_FRAME_FLAG_SIGNED) != 0,   "signed flag set");
            CHECK(b[3] == (uint8_t)i,                   "frame_seq matches position");
            CHECK(b[4] == CM_FRAMES_PER_CELL,           "frame_count == 5");
            CHECK(cm_read_u32(b + 6) == 0xCAFE0002u,    "cell_id carried in header");
            CHECK(cm_read_u16(b + 10) == (uint16_t)(i * CM_FRAME_MAX_PAYLOAD),
                                                        "cell_offset matches frame position");
        }
    }

    // ── Test 3: in-order reassembly round-trips bit-exact ───────────────
    {
        uint8_t in_cell[CM_CELL_SIZE]; make_test_cell(in_cell, 0x33);
        uint8_t in_sig[CM_FRAME_SIG_SIZE]; make_test_sig(in_sig, 0x33);
        cm_frame_t frames[CM_FRAMES_PER_CELL];
        cm_frame_split(in_cell, in_sig, 0xBEEF0003u, frames);

        cm_reasm_t r; cm_reasm_init(&r);
        uint8_t sender[6] = {0x01,0x02,0x03,0x04,0x05,0x06};

        uint8_t out_cell[CM_CELL_SIZE] = {0};
        uint8_t out_sig[CM_FRAME_SIG_SIZE] = {0};

        cm_reasm_result_t result = CM_REASM_INCOMPLETE;
        for (size_t i = 0; i < CM_FRAMES_PER_CELL; i++) {
            result = cm_reasm_push(&r, frames[i].bytes, frames[i].len,
                                   sender, 1000 + i, out_cell, out_sig);
            if (i < CM_FRAMES_PER_CELL - 1) {
                CHECK(result == CM_REASM_INCOMPLETE, "intermediate frames are INCOMPLETE");
            }
        }
        CHECK(result == CM_REASM_COMPLETE, "last frame returns COMPLETE");
        CHECK(memcmp(in_cell, out_cell, CM_CELL_SIZE) == 0, "reassembled cell bit-exact");
        CHECK(memcmp(in_sig,  out_sig,  CM_FRAME_SIG_SIZE) == 0, "reassembled sig bit-exact");
        CHECK(r.total_reassembled == 1, "telemetry: 1 reassembled");
        CHECK(r.total_pushed == 5,      "telemetry: 5 pushed");
    }

    // ── Test 4: out-of-order reassembly works ──────────────────────────
    {
        uint8_t in_cell[CM_CELL_SIZE]; make_test_cell(in_cell, 0x44);
        uint8_t in_sig[CM_FRAME_SIG_SIZE]; make_test_sig(in_sig, 0x44);
        cm_frame_t frames[CM_FRAMES_PER_CELL];
        cm_frame_split(in_cell, in_sig, 0xF00D0004u, frames);

        cm_reasm_t r; cm_reasm_init(&r);
        uint8_t sender[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
        uint8_t out_cell[CM_CELL_SIZE] = {0};
        uint8_t out_sig[CM_FRAME_SIG_SIZE] = {0};

        // Permute: 2, 0, 4, 1, 3
        const size_t order[] = {2, 0, 4, 1, 3};
        cm_reasm_result_t result = CM_REASM_INCOMPLETE;
        for (size_t k = 0; k < 5; k++) {
            size_t i = order[k];
            result = cm_reasm_push(&r, frames[i].bytes, frames[i].len,
                                   sender, 2000 + k, out_cell, out_sig);
        }
        CHECK(result == CM_REASM_COMPLETE, "out-of-order completes");
        CHECK(memcmp(in_cell, out_cell, CM_CELL_SIZE) == 0, "out-of-order cell bit-exact");
        CHECK(memcmp(in_sig,  out_sig,  CM_FRAME_SIG_SIZE) == 0, "out-of-order sig bit-exact");
    }

    // ── Test 5: duplicate frames are idempotent ────────────────────────
    {
        uint8_t in_cell[CM_CELL_SIZE]; make_test_cell(in_cell, 0x55);
        uint8_t in_sig[CM_FRAME_SIG_SIZE]; make_test_sig(in_sig, 0x55);
        cm_frame_t frames[CM_FRAMES_PER_CELL];
        cm_frame_split(in_cell, in_sig, 0x12345555u, frames);

        cm_reasm_t r; cm_reasm_init(&r);
        uint8_t sender[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        uint8_t out_cell[CM_CELL_SIZE], out_sig[CM_FRAME_SIG_SIZE];

        // Push frame 0 three times, then 1..4 normally.
        cm_reasm_push(&r, frames[0].bytes, frames[0].len, sender, 100, NULL, NULL);
        cm_reasm_push(&r, frames[0].bytes, frames[0].len, sender, 101, NULL, NULL);
        cm_reasm_push(&r, frames[0].bytes, frames[0].len, sender, 102, NULL, NULL);
        cm_reasm_push(&r, frames[1].bytes, frames[1].len, sender, 103, NULL, NULL);
        cm_reasm_push(&r, frames[2].bytes, frames[2].len, sender, 104, NULL, NULL);
        cm_reasm_push(&r, frames[3].bytes, frames[3].len, sender, 105, NULL, NULL);
        cm_reasm_result_t result = cm_reasm_push(&r, frames[4].bytes, frames[4].len,
                                                  sender, 106, out_cell, out_sig);
        CHECK(result == CM_REASM_COMPLETE,                       "duplicate frames don't break reassembly");
        CHECK(memcmp(in_cell, out_cell, CM_CELL_SIZE) == 0,      "dup-tolerant cell bit-exact");
    }

    // ── Test 6: two senders interleaved reassemble independently ───────
    {
        uint8_t cell_a[CM_CELL_SIZE], cell_b[CM_CELL_SIZE];
        uint8_t sig_a[CM_FRAME_SIG_SIZE], sig_b[CM_FRAME_SIG_SIZE];
        make_test_cell(cell_a, 0xA0); make_test_sig(sig_a, 0xA0);
        make_test_cell(cell_b, 0xB0); make_test_sig(sig_b, 0xB0);

        cm_frame_t fa[CM_FRAMES_PER_CELL], fb[CM_FRAMES_PER_CELL];
        cm_frame_split(cell_a, sig_a, 0xAAAA0001u, fa);
        cm_frame_split(cell_b, sig_b, 0xBBBB0001u, fb);

        cm_reasm_t r; cm_reasm_init(&r);
        uint8_t sender_a[6] = {1,1,1,1,1,1};
        uint8_t sender_b[6] = {2,2,2,2,2,2};
        uint8_t out_cell[CM_CELL_SIZE], out_sig[CM_FRAME_SIG_SIZE];

        // Interleave their frames.
        cm_reasm_result_t r_a = CM_REASM_INCOMPLETE, r_b = CM_REASM_INCOMPLETE;
        uint8_t a_out[CM_CELL_SIZE] = {0}, b_out[CM_CELL_SIZE] = {0};
        uint8_t a_sig[CM_FRAME_SIG_SIZE] = {0}, b_sig[CM_FRAME_SIG_SIZE] = {0};
        for (size_t i = 0; i < 5; i++) {
            cm_reasm_result_t got_a = cm_reasm_push(&r, fa[i].bytes, fa[i].len, sender_a, 100 + i, out_cell, out_sig);
            if (got_a == CM_REASM_COMPLETE) { r_a = got_a; memcpy(a_out, out_cell, CM_CELL_SIZE); memcpy(a_sig, out_sig, CM_FRAME_SIG_SIZE); }
            cm_reasm_result_t got_b = cm_reasm_push(&r, fb[i].bytes, fb[i].len, sender_b, 200 + i, out_cell, out_sig);
            if (got_b == CM_REASM_COMPLETE) { r_b = got_b; memcpy(b_out, out_cell, CM_CELL_SIZE); memcpy(b_sig, out_sig, CM_FRAME_SIG_SIZE); }
        }
        CHECK(r_a == CM_REASM_COMPLETE && r_b == CM_REASM_COMPLETE, "both senders complete independently");
        CHECK(memcmp(cell_a, a_out, CM_CELL_SIZE) == 0, "sender A cell bit-exact");
        CHECK(memcmp(cell_b, b_out, CM_CELL_SIZE) == 0, "sender B cell bit-exact");
        CHECK(memcmp(sig_a,  a_sig, CM_FRAME_SIG_SIZE) == 0, "sender A sig bit-exact");
        CHECK(memcmp(sig_b,  b_sig, CM_FRAME_SIG_SIZE) == 0, "sender B sig bit-exact");
    }

    // ── Test 7: bad magic is rejected ──────────────────────────────────
    {
        cm_reasm_t r; cm_reasm_init(&r);
        uint8_t junk[CM_FRAME_TOTAL_SIZE];
        memset(junk, 0xFF, sizeof(junk));
        uint8_t sender[6] = {0};
        cm_reasm_result_t result = cm_reasm_push(&r, junk, sizeof(junk), sender, 1000, NULL, NULL);
        CHECK(result == CM_REASM_BAD_FRAME, "frame with bad magic rejected");
        CHECK(r.total_bad_frame == 1, "telemetry: 1 bad frame");
    }

    // ── Test 8: short frame (< header size) is rejected ─────────────────
    {
        cm_reasm_t r; cm_reasm_init(&r);
        uint8_t tiny[4] = {0};
        uint8_t sender[6] = {0};
        cm_reasm_result_t result = cm_reasm_push(&r, tiny, sizeof(tiny), sender, 1000, NULL, NULL);
        CHECK(result == CM_REASM_BAD_FRAME, "short frame rejected");
    }

    // ── Test 9: TTL eviction frees up slots ────────────────────────────
    {
        cm_reasm_t r; cm_reasm_init(&r);
        uint8_t in_cell[CM_CELL_SIZE]; make_test_cell(in_cell, 0x99);
        uint8_t in_sig[CM_FRAME_SIG_SIZE]; make_test_sig(in_sig, 0x99);
        cm_frame_t frames[CM_FRAMES_PER_CELL];
        cm_frame_split(in_cell, in_sig, 0x99990001u, frames);

        // Push just frame 0 from a sender at t=0 (incomplete; stays in table).
        uint8_t sender_old[6] = {0x77,0x77,0x77,0x77,0x77,0x77};
        cm_reasm_push(&r, frames[0].bytes, frames[0].len, sender_old, 0, NULL, NULL);
        CHECK(r.total_dropped == 0, "no eviction yet");

        // Now push a full cell from another sender at t > TTL — old partial
        // gets evicted (TTL pressure on the second push).
        uint8_t sender_new[6] = {0x88,0x88,0x88,0x88,0x88,0x88};
        uint8_t out_cell[CM_CELL_SIZE], out_sig[CM_FRAME_SIG_SIZE];
        cm_reasm_result_t result = CM_REASM_INCOMPLETE;
        for (size_t i = 0; i < CM_FRAMES_PER_CELL; i++) {
            result = cm_reasm_push(&r, frames[i].bytes, frames[i].len,
                                   sender_new, CM_REASM_TTL_MS + 100 + i,
                                   out_cell, out_sig);
        }
        CHECK(result == CM_REASM_COMPLETE,    "new sender completes after TTL evicts old");
        CHECK(r.total_dropped >= 1,            "TTL eviction recorded in telemetry");
    }

    if (fails == 0) {
        printf("\nAll tests passed.\n");
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", fails);
        return 1;
    }
}
