// temp_logger — a store-and-forward temperature logger on the cell engine.
//
// One firmware, two roles (menuconfig → Temp logger → Role):
//
//   node     A DS18B20 in a box. Each reading is checked against the heat
//            policy by the cell engine, written to the flash log, and sent
//            over ESP-NOW whenever a gateway answers. Nothing is dropped for
//            being unsent: the log keeps it until the host acknowledges it.
//
//   gateway  On the laptop's USB. Prints each batch as a `TL` line for
//            tools/templog-bridge, and relays the bridge's `AK` lines back to
//            the node as ack cells.
//
// Formats and rules: docs/TEMP-LOGGER.md. The logic is the core's
// (cell_templog.h); this file is the ESP-IDF around it.

#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"

#include "cell_domains.h"
#include "cell_frame.h"
#include "cell_radio.h"
#include "cell_templog.h"
#include "cell_wire.h"

#if CONFIG_TL_ROLE_NODE
#include <math.h>
#include "ds18b20.h"
#include "semantos.h"
#include "tlog_store.h"
#include "wasm_export.h"   // wasm_runtime_init_thread_env
#endif

static const char *TAG = "temp_logger";

#define LED_GPIO          CONFIG_TL_LED_GPIO
#define POLICY_MIN        ((int16_t)CONFIG_TL_POLICY_MIN_CENTI)
#define POLICY_MAX        ((int16_t)CONFIG_TL_POLICY_MAX_CENTI)
#define SAMPLE_MS         ((uint64_t)CONFIG_TL_SAMPLE_INTERVAL_S * 1000ULL)
#define MAX_BACKOFF_MS    ((uint32_t)CONFIG_TL_MAX_BACKOFF_S * 1000u)
#define TICK_MS           100
#define GATEWAY_FALLBACK  3   // unanswered unicasts before going back to broadcast

static uint8_t s_my_mac[6];
static char    s_my_mac_str[18];
static uint8_t s_batch_type_hash[32];
static uint8_t s_ack_type_hash[32];

static cm_reasm_t    s_reasm;
static QueueHandle_t s_rx_queue;

typedef struct {
    uint8_t mac[6];
    uint8_t cell[CM_CELL_SIZE];
} rx_item_t;

static inline uint64_t now_ms(void) { return (uint64_t)(esp_timer_get_time() / 1000); }
static inline uint32_t uptime_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

static void format_mac(char buf[18], const uint8_t mac[6]) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// ── LED (XIAO: GPIO15, active low) ───────────────────────────────────

static void led_init(void) {
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << LED_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);
    gpio_set_level(LED_GPIO, 1);
}

static inline void led_set(bool on) { gpio_set_level(LED_GPIO, on ? 0 : 1); }

// ── Cells ─────────────────────────────────────────────────────────────

// Unsigned telemetry, as mesh_demo sends it: the domain flag is a label here,
// not a boundary, because no signature covers the header.
static void build_cell(uint8_t cell[CM_CELL_SIZE], const uint8_t type_hash[32],
                       const uint8_t payload[CM_PAYLOAD_SIZE], size_t used) {
    cm_cell_init(cell);
    cm_set_flags(cell, CM_DOMAIN_MESH_TELEMETRY);
    cm_set_linearity(cell, CM_LINEARITY_AFFINE);
    memcpy(cm_type_hash_mut(cell), type_hash, 32);
    memcpy(cm_owner_id_mut(cell), s_my_mac, 6);
    memset(cm_owner_id_mut(cell) + 6, 0, 10);
    cm_set_timestamp_ms(cell, (uint64_t)esp_log_timestamp());
    memcpy(cm_payload_mut(cell), payload, CM_PAYLOAD_SIZE);
    cm_set_payload_total(cell, (uint32_t)used);
    mbedtls_sha256(cm_payload(cell), CM_PAYLOAD_SIZE, cm_domain_payload_root_mut(cell), 0);
}

// Runs in the Wi-Fi task: reassemble, keep only the cell type this role
// consumes, and hand it to the main loop. No logging, no waiting.
static void on_radio_recv(const uint8_t sender_mac[6], const uint8_t *frame, size_t len, void *ud) {
    (void)ud;
    if (memcmp(sender_mac, s_my_mac, 6) == 0) return;
    static uint8_t cell[CM_CELL_SIZE];
    static uint8_t sig[CM_FRAME_SIG_SIZE];
    if (cm_reasm_push(&s_reasm, frame, len, sender_mac, now_ms(), cell, sig) != CM_REASM_COMPLETE) return;
#if CONFIG_TL_ROLE_GATEWAY
    const uint8_t *want = s_batch_type_hash;
#else
    const uint8_t *want = s_ack_type_hash;
#endif
    if (memcmp(cm_type_hash(cell), want, 32) != 0) return;
    static rx_item_t item;
    memcpy(item.mac, sender_mac, 6);
    memcpy(item.cell, cell, CM_CELL_SIZE);
    (void)xQueueSend(s_rx_queue, &item, 0);   // full queue: drop; the sender retries
}

// ═════════════════════════════════════════════════════════════════════
#if CONFIG_TL_ROLE_NODE
// ═════════════════════════════════════════════════════════════════════

// Temperatures print as degrees with two decimals; -32768 means no reading.
static const char *fmt_centi(char buf[12], int16_t c) {
    if (c == CM_TLOG_TEMP_INVALID) return "none";
    int v = c < 0 ? -c : c;
    snprintf(buf, 12, "%s%d.%02d", c < 0 ? "-" : "", v / 100, v % 100);
    return buf;
}

#if CONFIG_TL_MOCK_PROBE
#define PROBE_NOTE " (SIMULATED PROBE)"
#else
#define PROBE_NOTE ""
#endif

static tlog_store_t    s_store;
static cm_tlog_sched_t s_sched;
static semantos_t     *s_engine;
static uint8_t         s_lock[16];
static size_t          s_lock_len;
#if !CONFIG_TL_MOCK_PROBE
static bool            s_probe_ok;
#endif

static uint8_t  s_gateway_mac[6];
static bool     s_gateway_known;
static uint32_t s_unanswered;

// What the LED shows: the latest reading, and whether any reading since boot
// left the band (latched, like a tripped dye strip).
static uint8_t s_last_flags;
static bool    s_tripped;

// ── The probe (or a stand-in for bench runs) ─────────────────────────

#if CONFIG_TL_MOCK_PROBE
static int probe_read(int16_t *out) {
    // A slow day/night sine around 16 °C, and every 3 hours a 40-minute
    // excursion to about 35 °C, so the whole path shows up in a short run.
    double t = (double)uptime_s();
    double c = 16.0 + 3.0 * sin(t / 3600.0);
    double phase = fmod(t, 3.0 * 3600.0);
    if (phase > 3600.0 && phase < 3600.0 + 40.0 * 60.0) c += 19.0 * sin(M_PI * (phase - 3600.0) / 2400.0);
    *out = (int16_t)lround(c * 100.0);
    return CM_DS_OK;
}
#else
static int probe_read(int16_t *out) {
    if (!s_probe_ok) {
        s_probe_ok = ds18b20_init(CONFIG_TL_PROBE_GPIO) == ESP_OK;   // it may have been plugged in since
        if (!s_probe_ok) return CM_DS_ERR_NO_DEVICE;
    }
    int rc = ds18b20_read(CONFIG_TL_PROBE_GPIO, out);
    if (rc == CM_DS_ERR_NO_DEVICE) s_probe_ok = false;
    return rc;
}
#endif

// ── The heat policy, in the cell engine ──────────────────────────────
//
// The engine runs <reading> <min> <max+1> OP_WITHIN and accepts only a
// reading inside the band. The same comparison is done natively, and a
// disagreement counts as an engine fault. Either way a fault is a reject:
// a heat check that cannot answer does not get to say "fine".
static uint8_t policy_flags(int16_t centi) {
    bool native_ok = centi >= POLICY_MIN && centi <= POLICY_MAX;
    if (!s_engine || s_lock_len == 0) return CM_TLOG_SF_POLICY_REJECT | CM_TLOG_SF_VM_ERROR;

    uint8_t unlock[8];
    size_t unlock_len = cm_tlog_policy_unlock(centi, unlock, sizeof unlock);
    semantos_kernel_reset(s_engine);
    int rc = semantos_kernel_load_script(s_engine, s_lock, (uint32_t)s_lock_len);
    if (rc == SEMANTOS_OK) rc = semantos_kernel_load_unlock(s_engine, unlock, (uint32_t)unlock_len);
    if (rc == SEMANTOS_OK) rc = semantos_kernel_execute(s_engine);
    bool vm_ok = rc == SEMANTOS_OK;

    if (vm_ok != native_ok) {
        ESP_LOGW(TAG, "policy: engine says %s, native says %s (rc=%d err=%u) — counted as a fault",
                 vm_ok ? "in band" : "out", native_ok ? "in band" : "out",
                 rc, (unsigned)semantos_kernel_get_error(s_engine));
        return CM_TLOG_SF_POLICY_REJECT | CM_TLOG_SF_VM_ERROR;
    }
    return vm_ok ? 0 : CM_TLOG_SF_POLICY_REJECT;
}

static void take_sample(void) {
    int16_t centi = CM_TLOG_TEMP_INVALID;
    uint8_t flags;
    int rc = probe_read(&centi);
    if (rc == CM_DS_OK) {
        flags = policy_flags(centi);
    } else {
        flags = CM_TLOG_SF_SENSOR_ERROR | (rc == CM_DS_POR ? CM_TLOG_SF_POR_SUSPECT : 0);
        centi = CM_TLOG_TEMP_INVALID;
    }

    cm_tlog_record_t rec = { .boot_id = s_store.boot_id, .uptime_s = uptime_s(),
                             .centi_c = centi, .flags = flags };
    uint32_t seq = tlog_store_append(&s_store, &rec);

    s_last_flags = flags;
    if (flags & CM_TLOG_SF_POLICY_REJECT) s_tripped = true;
    char t[12];
    ESP_LOGI(TAG, "SAMPLE seq=%u c=%s flags=0x%02x pending=%u%s",
             (unsigned)seq, fmt_centi(t, centi), flags, (unsigned)cm_tlog_pending(&s_store.log),
             (flags & CM_TLOG_SF_POLICY_REJECT) ? "  *** OUT OF BAND ***" : "");
}

// ── Store and forward ────────────────────────────────────────────────

static void send_batch(uint64_t t_ms) {
    static uint8_t payload[CM_PAYLOAD_SIZE];
    static uint8_t cell[CM_CELL_SIZE];
    uint8_t sig[CM_FRAME_SIG_SIZE] = {0};   // unsigned: devices do not hold keys

    uint32_t first = cm_tlog_pending_first(&s_store.log);
    uint32_t end = s_store.log.next_seq;
    cm_tlog_record_t rec;
    bool have_first = tlog_store_read(&s_store, first, &rec);

    cm_tlog_batch_header_t h = {0};
    h.first_seq = first;
    h.boot_id = have_first ? rec.boot_id : s_store.boot_id;
    h.boot_now = s_store.boot_id;
    h.uptime_now_s = uptime_s();
    h.boot_epoch_s = tlog_store_epoch_for(&s_store, h.boot_id);
    h.lost_through = cm_tlog_lost_through(&s_store.log);
    h.sample_interval_s = CONFIG_TL_SAMPLE_INTERVAL_S;
    h.policy_min_centi = POLICY_MIN;
    h.policy_max_centi = POLICY_MAX;
    h.log_id = s_store.log_id;
    cm_tlog_batch_begin(payload, &h);

    for (uint32_t seq = first; seq < end; seq++) {
        bool ok = seq == first ? have_first : tlog_store_read(&s_store, seq, &rec);
        // A batch stops when it is full or the next record is from another
        // boot; an unreadable record travels as a marked placeholder.
        if (!(ok ? cm_tlog_batch_add(payload, &rec) : cm_tlog_batch_add_lost(payload, seq))) break;
    }
    uint16_t n = cm_tlog_batch_count(payload);
    if (n == 0) return;

    build_cell(cell, s_batch_type_hash, payload, cm_tlog_batch_used_bytes(payload));
    uint32_t cell_id = esp_random();
    bool unicast = s_gateway_known;
    esp_err_t err = unicast ? cm_radio_send_cell_to(s_gateway_mac, cell, sig, cell_id)
                            : cm_radio_send_cell(cell, sig, cell_id);
    cm_tlog_sched_on_sent(&s_sched, t_ms, MAX_BACKOFF_MS);
    if (++s_unanswered >= GATEWAY_FALLBACK && s_gateway_known) {
        s_gateway_known = false;   // the gateway may have moved; ask everyone again
        ESP_LOGW(TAG, "no ack for %u sends — back to broadcast", (unsigned)s_unanswered);
    }
    ESP_LOGI(TAG, "TX batch seqs %u..%u (%u) lost_through=%u %s rc=%d",
             (unsigned)first, (unsigned)(first + n - 1), (unsigned)n, (unsigned)h.lost_through,
             unicast ? "unicast" : "broadcast", (int)err);
}

static void handle_ack(const rx_item_t *it, uint64_t t_ms) {
    uint8_t mac[6];
    uint32_t acked = 0, host_unix = 0;
    if (!cm_tlog_ack_decode(cm_payload(it->cell), cm_payload_total(it->cell), mac, &acked, &host_unix)) return;
    if (memcmp(mac, s_my_mac, 6) != 0) return;   // another node's

    uint32_t before = s_store.log.acked_through;
    tlog_store_set_acked(&s_store, acked);
    memcpy(s_gateway_mac, it->mac, 6);
    s_gateway_known = true;
    s_unanswered = 0;
    cm_tlog_sched_on_ack(&s_sched, t_ms);

    // The host's clock places this boot: anything logged before the node
    // next reboots can then be timed, even if it only reaches the host later.
    uint32_t up = uptime_s();
    if (host_unix > up) tlog_store_note_epoch(&s_store, s_store.boot_id, host_unix - up);

    ESP_LOGI(TAG, "RX ack through %u (was %u), %u pending",
             (unsigned)s_store.log.acked_through, (unsigned)before, (unsigned)cm_tlog_pending(&s_store.log));
}

// ── LED: what a person looking at the board should know ──────────────
//   fast blink   the latest reading is out of band
//   double blink the probe is not answering
//   slow blink   a reading left the band since boot (latched)
//   blip         all well
static void led_tick(uint64_t t_ms) {
    uint32_t phase = (uint32_t)(t_ms % 2000);
    bool on;
    if (s_last_flags & CM_TLOG_SF_POLICY_REJECT)      on = (phase % 250) < 125;
    else if (s_last_flags & CM_TLOG_SF_SENSOR_ERROR)  on = phase < 100 || (phase >= 250 && phase < 350);
    else if (s_tripped)                               on = phase < 400;
    else                                              on = (t_ms % 5000) < 60;
    led_set(on);
}

static void run_node(void) {
    // The engine first: WAMR needs a contiguous ~128 KB block, which it
    // only gets before anything else carves up the heap (see mesh_demo).
    if (!wasm_runtime_init_thread_env()) ESP_LOGE(TAG, "wasm_runtime_init_thread_env failed");
    semantos_config_t cfg = SEMANTOS_DEFAULT_CONFIG();
    if (semantos_init(&cfg, &s_engine) != ESP_OK || semantos_kernel_init(s_engine) != SEMANTOS_OK) {
        ESP_LOGE(TAG, "cell engine did not start — every reading will be flagged as unchecked");
        s_engine = NULL;
    }
    ESP_ERROR_CHECK(tlog_store_init(&s_store));
    s_lock_len = cm_tlog_policy_lock(POLICY_MIN, POLICY_MAX, s_lock, sizeof s_lock);
    char lo[12], hi[12];
    ESP_LOGI(TAG, "heat policy: %s..%s C in the cell engine (%u-byte lock script)",
             fmt_centi(lo, POLICY_MIN), fmt_centi(hi, POLICY_MAX), (unsigned)s_lock_len);

    ESP_ERROR_CHECK(cm_radio_init());
    cm_reasm_init(&s_reasm);
    cm_radio_register_recv(on_radio_recv, NULL);
    ESP_ERROR_CHECK(cm_radio_get_mac(s_my_mac));
    format_mac(s_my_mac_str, s_my_mac);

#if !CONFIG_TL_MOCK_PROBE
    s_probe_ok = ds18b20_init(CONFIG_TL_PROBE_GPIO) == ESP_OK;
#endif
    cm_tlog_sched_init(&s_sched);
    ESP_LOGI(TAG, "node up. mac=%s log=%08x boot=%u every %us%s", s_my_mac_str,
             (unsigned)s_store.log_id, (unsigned)s_store.boot_id, (unsigned)CONFIG_TL_SAMPLE_INTERVAL_S,
             PROBE_NOTE);

    static rx_item_t it;
    uint64_t next_sample = now_ms();
    for (;;) {
        uint64_t t = now_ms();
        if (t >= next_sample) {
            take_sample();
            next_sample += SAMPLE_MS;
            if (next_sample <= t) next_sample = t + SAMPLE_MS;   // a stall must not cause a burst
        }
        while (xQueueReceive(s_rx_queue, &it, 0) == pdTRUE) handle_ack(&it, now_ms());
        if (cm_tlog_sched_should_send(&s_sched, now_ms(), cm_tlog_pending(&s_store.log))) send_batch(now_ms());
        led_tick(now_ms());
        vTaskDelay(pdMS_TO_TICKS(TICK_MS));
    }
}

// ═════════════════════════════════════════════════════════════════════
#else  // CONFIG_TL_ROLE_GATEWAY
// ═════════════════════════════════════════════════════════════════════

// Standard CRC-32 (zlib), the same one the serial inject path uses.
static uint32_t crc32_zlib(const uint8_t *d, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= d[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1u)));
    }
    return c ^ 0xFFFFFFFFu;
}

static uint64_t s_led_off_at;

// One whole line per write, through the driver, so a batch arrives at the
// bridge in one piece. The bridge checks the CRC and ignores anything else.
static void print_batch(const rx_item_t *it) {
    static char line[3 + 18 + CM_CELL_SIZE * 2 + 1 + 8 + 2 + 8];   // + slack
    static const char hex[] = "0123456789abcdef";
    char mac[18];
    format_mac(mac, it->mac);
    size_t o = (size_t)snprintf(line, sizeof line, "TL %s ", mac);
    for (size_t i = 0; i < CM_CELL_SIZE; i++) {
        line[o++] = hex[it->cell[i] >> 4];
        line[o++] = hex[it->cell[i] & 0x0f];
    }
    o += (size_t)snprintf(line + o, sizeof line - o, " %08" PRIx32 "\n", crc32_zlib(it->cell, CM_CELL_SIZE));
    usb_serial_jtag_write_bytes(line, o, pdMS_TO_TICKS(500));

    cm_tlog_batch_header_t h;
    if (cm_tlog_batch_decode_header(cm_payload(it->cell), cm_payload_total(it->cell), &h)) {
        ESP_LOGI(TAG, "RX [%s] batch log=%08x seqs %u..%u", mac, (unsigned)h.log_id,
                 (unsigned)h.first_seq, (unsigned)(h.first_seq + h.count - 1));
    }
    led_set(true);
    s_led_off_at = now_ms() + 80;
}

static bool parse_mac12(const char *s, uint8_t out[6]) {
    for (int i = 0; i < 6; i++) {
        char b[3] = { s[2 * i], s[2 * i + 1], 0 };
        char *end = NULL;
        long v = strtol(b, &end, 16);
        if (end != b + 2 || v < 0) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

// "AK <aabbccddeeff> <acked_through> <host_unix_s>"
static void handle_ak_line(const char *line) {
    if (strncmp(line, "AK ", 3) != 0 || strlen(line) < 3 + 12 + 2) return;
    uint8_t mac[6];
    if (!parse_mac12(line + 3, mac) || line[15] != ' ') {
        ESP_LOGW(TAG, "AK: bad mac");
        return;
    }
    char *end = NULL;
    unsigned long acked = strtoul(line + 16, &end, 10);
    unsigned long host = (end && *end == ' ') ? strtoul(end + 1, NULL, 10) : 0;

    static uint8_t payload[CM_PAYLOAD_SIZE];
    static uint8_t cell[CM_CELL_SIZE];
    uint8_t sig[CM_FRAME_SIG_SIZE] = {0};
    cm_tlog_ack_encode(payload, mac, (uint32_t)acked, (uint32_t)host);
    build_cell(cell, s_ack_type_hash, payload, CM_TLOG_ACK_SIZE);
    esp_err_t err = cm_radio_send_cell_to(mac, cell, sig, esp_random());
    char m[18];
    format_mac(m, mac);
    ESP_LOGI(TAG, "TX ack → %s through %lu rc=%d", m, acked, (int)err);
}

static void serial_task(void *arg) {
    (void)arg;
    static char line[96];
    size_t pos = 0;
    uint8_t rx[64];
    for (;;) {
        int n = usb_serial_jtag_read_bytes(rx, sizeof rx, pdMS_TO_TICKS(1000));
        for (int i = 0; i < n; i++) {
            char ch = (char)rx[i];
            if (ch == '\n' || ch == '\r') {
                if (pos > 0) {
                    line[pos] = 0;
                    handle_ak_line(line);
                    pos = 0;
                }
            } else if (pos < sizeof line - 1) {
                line[pos++] = ch;
            } else {
                pos = 0;   // overlong: drop and resync at the next newline
            }
        }
    }
}

static void run_gateway(void) {
    ESP_ERROR_CHECK(cm_radio_init());
    cm_reasm_init(&s_reasm);
    cm_radio_register_recv(on_radio_recv, NULL);
    ESP_ERROR_CHECK(cm_radio_get_mac(s_my_mac));
    format_mac(s_my_mac_str, s_my_mac);

    usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    cfg.rx_buffer_size = 1024;
    cfg.tx_buffer_size = 4096;   // a whole TL line fits
    esp_err_t e = usb_serial_jtag_driver_install(&cfg);
    if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) ESP_LOGE(TAG, "usb_serial_jtag_driver_install: %d", (int)e);
    xTaskCreate(serial_task, "tl_serial", 4096, NULL, 5, NULL);

    ESP_LOGI(TAG, "gateway up. mac=%s — TL lines out, AK lines in", s_my_mac_str);

    static rx_item_t it;
    for (;;) {
        if (xQueueReceive(s_rx_queue, &it, pdMS_TO_TICKS(TICK_MS)) == pdTRUE) print_batch(&it);
        if (s_led_off_at && now_ms() >= s_led_off_at) {
            led_set(false);
            s_led_off_at = 0;
        }
    }
}

#endif

// ── Entry ─────────────────────────────────────────────────────────────
//
// Everything runs on a pthread, not app_main's task: WAMR resolves
// pthread_self() internally and asserts on a thread it does not know
// (same pattern as hello_cell and mesh_demo).
static void *main_thread(void *arg) {
    (void)arg;
    mbedtls_sha256((const unsigned char *)CM_TLOG_BATCH_TYPE_NAME, sizeof(CM_TLOG_BATCH_TYPE_NAME) - 1,
                   s_batch_type_hash, 0);
    mbedtls_sha256((const unsigned char *)CM_TLOG_ACK_TYPE_NAME, sizeof(CM_TLOG_ACK_TYPE_NAME) - 1,
                   s_ack_type_hash, 0);
    s_rx_queue = xQueueCreate(4, sizeof(rx_item_t));
    led_init();
#if CONFIG_TL_ROLE_NODE
    run_node();
#else
    run_gateway();
#endif
    return NULL;
}

void app_main(void) {
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 12 * 1024);   // mesh_demo's size: leaves WAMR its 128 KB block
    int rc = pthread_create(&tid, &attr, main_thread, NULL);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        ESP_LOGE(TAG, "pthread_create: %d", rc);
        return;
    }
    pthread_detach(tid);
}
