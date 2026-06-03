// test_cell_meter.c — host smoke tests for the device-side draining meter.
//
// Compile:
//   cc -I ../include test_cell_meter.c ../src/cell_meter.c -o test_cell_meter
//   ./test_cell_meter

#include "cell_meter.h"

#include <stdio.h>
#include <stdint.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); fails++; } \
    else         { printf("ok:   %s\n", msg); } \
} while (0)

int main(void) {
    int fails = 0;

    // ── Test 1: accrual is exact regardless of tick frequency ───────────
    {
        // 1 sat/sec == 1000 msat/sec (a 10 W bulb @ 360 sats/Wh).
        cm_meter_t m;
        cm_meter_init(&m, 1000);
        cm_meter_start(&m, 0);

        // One coarse 10s jump.
        cm_meter_tick(&m, 10000);
        CHECK(cm_meter_consumed_sats(&m) == 10, "10s @1sat/s coarse → 10 sats");

        // Fine-grained ticking over the next 10s must land on the same total.
        cm_meter_t f;
        cm_meter_init(&f, 1000);
        cm_meter_start(&f, 0);
        for (uint64_t t = 100; t <= 10000; t += 100) cm_meter_tick(&f, t);
        CHECK(cm_meter_consumed_sats(&f) == 10, "10s @1sat/s in 100ms steps → 10 sats");
        CHECK(cm_meter_consumed_msat(&f) == 10000, "fine ticks accrue exact msats");
    }

    // ── Test 2: sub-sat-per-second rate accrues smoothly ────────────────
    {
        // 100 msat/sec = 0.1 sat/sec.
        cm_meter_t m;
        cm_meter_init(&m, 100);
        cm_meter_start(&m, 0);
        cm_meter_tick(&m, 5000);   // 5s → 500 msat → 0 whole sats
        CHECK(cm_meter_consumed_msat(&m) == 500, "5s @0.1sat/s → 500 msat");
        CHECK(cm_meter_consumed_sats(&m) == 0,   "  ... floors to 0 whole sats");
        cm_meter_tick(&m, 10000);  // +5s → 1000 msat → 1 whole sat
        CHECK(cm_meter_consumed_sats(&m) == 1,   "10s @0.1sat/s → 1 sat");
    }

    // ── Test 3: stopped time is never billed ────────────────────────────
    {
        cm_meter_t m;
        cm_meter_init(&m, 1000);
        cm_meter_start(&m, 0);
        cm_meter_tick(&m, 3000);          // 3s on → 3 sats
        cm_meter_stop(&m, 3000);
        cm_meter_tick(&m, 100000);        // 97s OFF — must not accrue
        CHECK(cm_meter_consumed_sats(&m) == 3, "off-time not billed");
        cm_meter_start(&m, 100000);       // resume
        cm_meter_tick(&m, 102000);        // +2s on → 5 sats total
        CHECK(cm_meter_consumed_sats(&m) == 5, "resume continues accrual");
    }

    // ── Test 4: non-monotonic clock never accrues negative ──────────────
    {
        cm_meter_t m;
        cm_meter_init(&m, 1000);
        cm_meter_start(&m, 5000);
        cm_meter_tick(&m, 4000);          // clock went backwards
        CHECK(cm_meter_consumed_sats(&m) == 0, "backwards clock → no accrual");
        cm_meter_tick(&m, 6000);          // forward 1s from the corrected base
        CHECK(cm_meter_consumed_sats(&m) == 1, "recovers after clock correction");
    }

    // ── Test 5: the authorization gate (the actuator cut-off) ───────────
    {
        // Prepaid drain: consumer pays ahead in 5-sat commitments; the meter
        // drains at 1 sat/s; a 1-sat tolerance floats one tick of service.
        cm_meter_t m;
        cm_meter_init(&m, 1000);
        cm_meter_start(&m, 0);
        const uint32_t TOL = 1;

        uint32_t paid = 5;  // first commitment: device_share = 5
        cm_meter_tick(&m, 4000);  // 4 sats consumed, paid 5 → authorized
        CHECK(cm_meter_authorized(&m, paid, TOL), "consumed<paid → authorized (lit)");

        cm_meter_tick(&m, 6000);  // 6 consumed, paid 5, tol 1 → exactly at edge
        CHECK(cm_meter_authorized(&m, paid, TOL), "consumed==paid+tol → still authorized");

        cm_meter_tick(&m, 7000);  // 7 consumed, paid 5 + tol 1 = 6 → exceeded
        CHECK(!cm_meter_authorized(&m, paid, TOL), "consumed>paid+tol → CUT OFF (exhausted)");

        // Consumer sends a fresh commitment raising device_share → re-lit.
        paid = 10;
        CHECK(cm_meter_authorized(&m, paid, TOL), "fresh commitment re-authorizes (re-lit)");

        // Consumer goes away (vault exhausted): no more commitments. The
        // meter drains past the last paid amount and stays cut off.
        cm_meter_tick(&m, 12000); // 12 consumed, paid 10 + tol 1 = 11 → exceeded
        CHECK(!cm_meter_authorized(&m, paid, TOL), "no fresh commitment → drains to cut-off");
    }

    // ── Test 6: device_share monotonic with consumption is the steady state ─
    {
        // Mirror the on-device loop: pay 1 sat/s exactly, meter 1 sat/s.
        cm_meter_t m;
        cm_meter_init(&m, 1000);
        cm_meter_start(&m, 0);
        bool ever_cut = false;
        for (uint32_t s = 1; s <= 30; s++) {
            cm_meter_tick(&m, (uint64_t)s * 1000);
            uint32_t paid = s; // commitment keeps pace, device_share == seconds
            if (!cm_meter_authorized(&m, paid, 1)) ever_cut = true;
        }
        CHECK(!ever_cut, "paying in lock-step with consumption never cuts off");
    }

    if (fails == 0) { printf("\nALL PASS\n"); return 0; }
    fprintf(stderr, "\n%d FAILED\n", fails);
    return 1;
}
