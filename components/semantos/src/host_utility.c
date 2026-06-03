// host_utility.c — the five non-crypto host imports: log, blocktime,
// sequence, call_by_name, fetch_cell.
//
// These are deliberately dumb on the ESP32:
//
//   blocktime  — the unix epoch as reported by settimeofday(), or 0 if
//                the system clock has not been set
//   sequence   — a monotonic counter that increments on every call; good
//                enough for ordering within a boot
//   log        — ESP_LOG pipe
//   call_by_name — host function dispatch (unknown names return 0xFFFFFFFF)
//   fetch_cell — octave-memory retrieval stub (returns 0 = failure until
//                you wire in real higher-octave storage)

#include "semantos_internal.h"

#include "esp_log.h"
#include "esp_timer.h"
#include <sys/time.h>
#include <string.h>

void semantos_host_log(const char *msg, uint32_t msg_len) {
    // ESP_LOGI expects a NUL-terminated format string; msg from WASM is a
    // non-terminated slice, so we bounce it through a scratch buffer.
    char buf[192];
    uint32_t n = msg_len < sizeof(buf) - 1 ? msg_len : sizeof(buf) - 1;
    memcpy(buf, msg, n);
    buf[n] = '\0';
    ESP_LOGI(SEMANTOS_TAG, "wasm: %s", buf);
}

uint32_t semantos_host_get_blocktime(void) {
    // Treat "blocktime" as the current unix epoch. If the clock hasn't
    // been set (no NTP, no RTC), return the micros-since-boot as a
    // monotonic fallback so scripts that depend on time still advance.
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0 && tv.tv_sec > 1600000000 /* Sept 2020 */) {
        return (uint32_t)tv.tv_sec;
    }
    return (uint32_t)(esp_timer_get_time() / 1000000);
}

uint32_t semantos_host_get_sequence(void) {
    static uint32_t seq = 0;
    return ++seq;
}

// ── call_by_name ────────────────────────────────────────────────────────
//
// The kernel uses this to reach named host functions from inside a script
// (Phase 25.5 opcodes). For the hack-kit we ship an empty dispatch table;
// meetup folks can add their own names here (e.g. "gpio.toggle",
// "led.blink", "sensor.read") and have scripts call them.
//
// Returning 0xFFFFFFFF tells the kernel the name is unknown.

uint32_t semantos_host_call_by_name(const char *name, uint32_t name_len) {
#if CONFIG_SEMANTOS_LOG_HOST_CALLS
    char buf[64];
    uint32_t n = name_len < sizeof(buf) - 1 ? name_len : sizeof(buf) - 1;
    memcpy(buf, name, n);
    buf[n] = '\0';
    ESP_LOGI(SEMANTOS_TAG, "call_by_name: '%s'", buf);
#endif
    (void)name;
    (void)name_len;
    return 0xFFFFFFFFu; // unknown
}

// ── fetch_cell ──────────────────────────────────────────────────────────
//
// The cell-engine's octave memory model lets scripts reference cells that
// live outside the 1KB WASM-side working set by asking the host to slice
// a chunk from a higher octave. For a meetup hack-kit we don't ship a
// real multi-octave store — this is where you'd plug your SPIFFS /
// SD-card / LittleFS-backed cell provider.
//
// Returns 1 on success (exactly 1024 bytes written to out_ptr), 0 on
// failure. Keep returning 0 and the kernel gracefully refuses operations
// that need higher-octave data.

uint32_t semantos_host_fetch_cell(uint8_t octave, uint32_t slot, uint32_t offset, uint8_t *out_ptr) {
#if CONFIG_SEMANTOS_LOG_HOST_CALLS
    ESP_LOGI(SEMANTOS_TAG,
             "fetch_cell octave=%u slot=%u offset=%u (not implemented)",
             (unsigned)octave, (unsigned)slot, (unsigned)offset);
#endif
    (void)octave;
    (void)slot;
    (void)offset;
    (void)out_ptr;
    return 0;
}
