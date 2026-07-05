// cell_meter.h — device-side draining meter for the Metered Flow Protocol.
//
// The device is the trusted meter: it measures + verifies, but does not hold
// spending keys. While service is being delivered — the lightbulb is lit,
// bandwidth is flowing — the meter accrues *consumed value* at a pro-rata
// rate. The consumer keeps the channel paid ahead of consumption by sending
// fresh commitment cells that raise the channel's `device_share` (see
// cell_channel.h). The actuator may keep delivering service only while the
// paid `device_share` covers what's been consumed.
//
// This is the device half of the prepaid-drain model: when the consumer
// stops paying (the Tier-0 vault is exhausted, or the wallet went away),
// no fresh commitments arrive, consumption catches up to the last paid
// amount, the authorization gate closes, and the device cuts the actuator
// off. Symmetric to the host-side MfpFlowAdapter exhausting at its cap
// (core/protocol-types/src/mfp/flow-adapter.ts).
//
// Fixed-point, integer-only — no float, MCU-friendly. Value is metered in
// milli-sats internally so a sub-sat-per-second rate (e.g. a 10 W bulb at
// ~1 sat/sec) accrues smoothly across millisecond ticks.
//
// Zig-backed C ABI, no IDF dependency — host-testable.

#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // Pro-rata value rate, milli-sats per second. cost = rate * elapsed.
    uint32_t rate_msat_per_sec;
    // Accrued consumed value, milli-sats. Monotonic non-decreasing.
    uint64_t accrued_msat;
    // Timestamp of the last accrual (host monotonic clock, ms).
    uint64_t last_tick_ms;
    // Metering only accrues while running (i.e. while the actuator is on).
    bool     running;
} cm_meter_t;

// Initialise a stopped meter with the given pro-rata rate.
void cm_meter_init(cm_meter_t *m, uint32_t rate_msat_per_sec);

// Begin (or resume) metering at now_ms. Accrual starts from this instant;
// time spent stopped is never billed. Idempotent if already running.
void cm_meter_start(cm_meter_t *m, uint64_t now_ms);

// Accrue elapsed wall-time since the last tick at the configured rate.
// No-op while stopped. Safe to call as often as the main loop spins;
// accrual is exact to the millisecond regardless of tick frequency.
void cm_meter_tick(cm_meter_t *m, uint64_t now_ms);

// Accrue up to now_ms, then pause. Time after this is not billed until
// the next start(). No-op if already stopped.
void cm_meter_stop(cm_meter_t *m, uint64_t now_ms);

// Total consumed value in whole sats (floor of accrued milli-sats).
uint32_t cm_meter_consumed_sats(const cm_meter_t *m);

// Accrued value in milli-sats (for fine-grained logging/telemetry).
uint64_t cm_meter_consumed_msat(const cm_meter_t *m);

// The actuator-authorization gate. Service may continue iff the consumer
// has paid for what's been consumed, within a small tolerance band:
//
//     consumed_sats <= paid_device_share + tolerance_sats
//
// `paid_device_share` is the channel's current commitment device_share
// (cm_channel_t.device_share). `tolerance_sats` gives the consumer a grace
// margin to deliver the next commitment before cut-off (it bounds how much
// unpaid service the device will float). Returns true while authorized.
bool cm_meter_authorized(const cm_meter_t *m,
                         uint32_t paid_device_share,
                         uint32_t tolerance_sats);

#ifdef __cplusplus
}
#endif
