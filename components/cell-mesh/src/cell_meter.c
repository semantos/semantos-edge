// cell_meter.c — device-side draining meter. Pure C, integer-only.

#include "cell_meter.h"

#include <string.h>

void cm_meter_init(cm_meter_t *m, uint32_t rate_msat_per_sec) {
    if (!m) return;
    memset(m, 0, sizeof(*m));
    m->rate_msat_per_sec = rate_msat_per_sec;
}

void cm_meter_start(cm_meter_t *m, uint64_t now_ms) {
    if (!m || m->running) return;
    m->running      = true;
    m->last_tick_ms = now_ms;
}

void cm_meter_tick(cm_meter_t *m, uint64_t now_ms) {
    if (!m || !m->running) return;
    // Guard against a non-monotonic clock: hold the high-water mark so a
    // transient backwards blip is never billed (and recovers once the
    // clock climbs back past it). Errs toward under-billing the consumer.
    if (now_ms <= m->last_tick_ms) return;
    uint64_t elapsed_ms = now_ms - m->last_tick_ms;
    // cost(msat) = rate(msat/s) * elapsed(ms) / 1000. Compute in 64-bit to
    // avoid overflow; the /1000 keeps the millisecond resolution.
    m->accrued_msat += ((uint64_t)m->rate_msat_per_sec * elapsed_ms) / 1000ULL;
    m->last_tick_ms = now_ms;
}

void cm_meter_stop(cm_meter_t *m, uint64_t now_ms) {
    if (!m || !m->running) return;
    cm_meter_tick(m, now_ms);
    m->running = false;
}

uint32_t cm_meter_consumed_sats(const cm_meter_t *m) {
    if (!m) return 0;
    uint64_t sats = m->accrued_msat / 1000ULL;
    return sats > 0xFFFFFFFFULL ? 0xFFFFFFFFu : (uint32_t)sats;
}

uint64_t cm_meter_consumed_msat(const cm_meter_t *m) {
    return m ? m->accrued_msat : 0;
}

bool cm_meter_authorized(const cm_meter_t *m,
                         uint32_t paid_device_share,
                         uint32_t tolerance_sats) {
    if (!m) return false;
    uint64_t consumed = (uint64_t)cm_meter_consumed_sats(m);
    uint64_t allowed  = (uint64_t)paid_device_share + (uint64_t)tolerance_sats;
    return consumed <= allowed;
}
