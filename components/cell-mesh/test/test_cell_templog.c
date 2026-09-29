// test_cell_templog.c — the temperature-logger core seen from firmware.
//
// The Zig tests prove the logic. This proves the C view of it: that the
// structs in cell_templog.h have the layout the Zig side exports, and that a
// batch built through the C ABI decodes the way docs/TEMP-LOGGER.md says.
//
// Run through the Zig C-ABI harness:
//   ../cell-mesh-zig/run-c-abi-tests.sh

#include "cell_templog.h"
#include "cell_wire.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); fails++; } \
    else         { printf("ok:   %s\n", msg); } \
} while (0)

int main(void) {
    int fails = 0;

    // ── Layouts ──────────────────────────────────────────────────────
    CHECK(sizeof(cm_tlog_record_t) == 16, "record struct is 16 bytes");
    CHECK(offsetof(cm_tlog_record_t, centi_c) == 12, "record.centi_c at 12");
    CHECK(offsetof(cm_tlog_record_t, flags) == 14, "record.flags at 14");
    CHECK(sizeof(cm_tlog_batch_header_t) == CM_TLOG_BATCH_HEADER_SIZE, "batch header struct matches its wire size");
    CHECK(offsetof(cm_tlog_batch_header_t, log_id) == 36, "batch header log_id at 36");
    CHECK(offsetof(cm_tlog_log_t, acked_through) == 12, "log.acked_through at 12");
    CHECK(offsetof(cm_tlog_sched_t, backoff_ms) == 8, "sched.backoff_ms at 8");
    CHECK(CM_TLOG_BATCH_MAX_SAMPLES == 91, "91 samples per batch");

    // ── DS18B20 ──────────────────────────────────────────────────────
    {
        uint8_t sp[9] = { 0x91, 0x01, 0x4B, 0x46, 0x7F, 0xFF, 0x0C, 0x10, 0 };
        sp[8] = cm_crc8_maxim(sp, 8);
        int16_t c = 0;
        CHECK(cm_ds18b20_decode(sp, &c) == CM_DS_OK && c == 2506, "25.0625 C decodes to 2506 centi");
        sp[1] ^= 0x01;
        CHECK(cm_ds18b20_decode(sp, &c) == CM_DS_ERR_CRC, "a flipped bit fails the CRC");
    }

    // ── Log + a batch built from it ──────────────────────────────────
    {
        cm_tlog_log_t log;
        cm_tlog_init(&log, 16384);
        CHECK(log.capacity == 16384, "the firmware's 256 KB ring is usable as-is");
        uint32_t first = 0;
        for (int i = 0; i < 3; i++) {
            uint32_t seq = cm_tlog_append(&log);
            if (i == 0) first = seq;
        }
        CHECK(first == 1 && cm_tlog_pending(&log) == 3, "three appends are pending");

        uint8_t payload[CM_PAYLOAD_SIZE];
        cm_tlog_batch_header_t h;
        memset(&h, 0, sizeof h);
        h.first_seq = cm_tlog_pending_first(&log);
        h.boot_id = 2;
        h.boot_now = 2;
        h.uptime_now_s = 300;
        h.sample_interval_s = 60;
        h.policy_min_centi = -200;
        h.policy_max_centi = 2800;
        h.log_id = 0xCAFEF00Du;
        cm_tlog_batch_begin(payload, &h);

        for (uint32_t s = 1; s <= 3; s++) {
            cm_tlog_record_t r = { .seq = s, .boot_id = 2, .uptime_s = s * 60,
                                   .centi_c = (int16_t)(1800 + s), .flags = 0 };
            uint8_t flash[CM_TLOG_RECORD_SIZE];
            cm_tlog_record_encode(&r, flash);
            cm_tlog_record_t back;
            CHECK(cm_tlog_record_decode(flash, &back) && back.centi_c == r.centi_c, "record survives flash");
            CHECK(cm_tlog_batch_add(payload, &back), "record joins the batch");
        }
        CHECK(cm_tlog_batch_used_bytes(payload) == 40 + 3 * 8, "used bytes = header + 3 samples");

        cm_tlog_batch_header_t got;
        CHECK(cm_tlog_batch_decode_header(payload, sizeof payload, &got), "header decodes");
        CHECK(got.count == 3 && got.first_seq == 1 && got.log_id == 0xCAFEF00Du, "header fields survive");
        cm_tlog_record_t r2;
        CHECK(cm_tlog_batch_sample(payload, sizeof payload, 2, &r2) && r2.seq == 3 && r2.centi_c == 1803,
              "sample 2 is seq 3 at 18.03 C");

        CHECK(cm_tlog_apply_ack(&log, 3) == 3 && cm_tlog_pending(&log) == 0, "an ack clears the window");
    }

    // ── Ack ──────────────────────────────────────────────────────────
    {
        uint8_t payload[CM_PAYLOAD_SIZE];
        const uint8_t mac[6] = { 0x58, 0xE6, 0xC5, 0x1A, 0x8B, 0x28 };
        cm_tlog_ack_encode(payload, mac, 42, 1790000000u);
        uint8_t m[6];
        uint32_t acked = 0, host = 0;
        CHECK(cm_tlog_ack_decode(payload, CM_TLOG_ACK_SIZE, m, &acked, &host), "ack decodes");
        CHECK(memcmp(m, mac, 6) == 0 && acked == 42 && host == 1790000000u, "ack fields survive");
    }

    // ── Schedule ─────────────────────────────────────────────────────
    {
        cm_tlog_sched_t s;
        cm_tlog_sched_init(&s);
        CHECK(cm_tlog_sched_should_send(&s, 0, 1), "a pending sample goes at once");
        cm_tlog_sched_on_sent(&s, 0, 60000);
        CHECK(!cm_tlog_sched_should_send(&s, 1999, 1), "and then waits for an ack");
    }

    // ── Policy scripts ───────────────────────────────────────────────
    {
        uint8_t lock[16], unlock[8];
        size_t nl = cm_tlog_policy_lock(-200, 2800, lock, sizeof lock);
        size_t nu = cm_tlog_policy_unlock(2506, unlock, sizeof unlock);
        const uint8_t want_lock[] = { 0x02, 0xc8, 0x80, 0x02, 0xf1, 0x0a, 0xa5 };
        const uint8_t want_unlock[] = { 0x02, 0xca, 0x09 };
        CHECK(nl == sizeof want_lock && memcmp(lock, want_lock, nl) == 0, "policy lock bytes");
        CHECK(nu == sizeof want_unlock && memcmp(unlock, want_unlock, nu) == 0, "policy unlock bytes");
    }

    if (fails) {
        fprintf(stderr, "%d check(s) failed\n", fails);
        return 1;
    }
    printf("all templog C-ABI checks passed\n");
    return 0;
}
