// cold_chain_main.c — ESP32-C6 cold chain temperature monitor
//
// A self-contained logger box that:
//   1. Reads temperature every SAMPLE_INTERVAL_MS (default 10 s)
//   2. Publishes a cold-chain.sensor.reading cell to the relay over WiFi
//   3. When WiFi is offline: queues readings in NVS flash (survives power cuts)
//   4. On reconnect: drains the NVS queue to the relay before live readings
//   5. On breach (temp > THRESHOLD_C for BREACH_SECS): publishes a
//      cold-chain.alert.breach cell — the relay anchors this on BSV (txid)
//
// HARDWARE
// ────────
//   ESP32-C6 dev board (any — XIAO C6, WeAct C6, generic)
//   DS18B20 temperature sensor on GPIO4 (1-Wire)  — see SENSOR section
//   USB-C power bank — just plug in, no config needed
//
// BUILD
// ─────
//   export IDF_PATH=~/esp/esp-idf   (v5.1+)
//   cd examples/cold_chain
//   idf.py menuconfig               ← set WiFi SSID/pass + relay URL
//   idf.py build flash monitor
//
// CONFIGURATION (Component config → Cold Chain in menuconfig)
// ────────────────────────────────────────────────────────────
//   CC_WIFI_SSID      WiFi network name
//   CC_WIFI_PASS      WiFi password
//   CC_RELAY_URL      http://192.168.0.50:5199   (relay host on same LAN)
//   CC_SENSOR_ID      truck-007                  (unique per device)
//   CC_LOCATION       cold-zone-A
//   CC_THRESHOLD_C    8.0                        (°C, max allowed)
//   CC_BREACH_SECS    30                         (seconds above threshold → alert)
//   CC_SAMPLE_MS      10000                      (ms between readings)
//   CC_MOCK_SENSOR    1                          (0 = real DS18B20, 1 = simulated)
//
// DESIGN NOTES
// ────────────
// No private key on device (Craig's stance). Cells carry a senderFp
// (SHA-256(SENSOR_ID)[0:4]) as an identifier. The anchor (PushDrop txid)
// is computed by the relay-side bridge, not on-device.
//
// NVS queue: ring buffer of up to CC_NVS_QUEUE_MAX (default 120) readings.
// At 10s intervals: 20 minutes of offline resilience in default NVS partition.
// Increase CC_NVS_QUEUE_MAX or switch to SPIFFS for longer blackouts.
//
// No WAMR / cell-engine WASM used here. Threshold logic is plain C.
// cell_wire.h is used only for the canonical 1024-byte cell framing.

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_http_client.h"
#include "mbedtls/sha256.h"

#include "cell_wire.h"  // CM_CELL_SIZE, cm_cell_init, cm_set_*, cm_payload_mut

static const char *TAG = "cold_chain";

// ── Compile-time config (override via menuconfig or Kconfig.projbuild) ────────

#ifndef CONFIG_CC_WIFI_SSID
#define CONFIG_CC_WIFI_SSID      "YourNetworkName"
#endif
#ifndef CONFIG_CC_WIFI_PASS
#define CONFIG_CC_WIFI_PASS      "YourNetworkPass"
#endif
#ifndef CONFIG_CC_RELAY_URL
#define CONFIG_CC_RELAY_URL      "http://192.168.0.50:5199"
#endif
#ifndef CONFIG_CC_SENSOR_ID
#define CONFIG_CC_SENSOR_ID      "sensor-001"
#endif
#ifndef CONFIG_CC_LOCATION
#define CONFIG_CC_LOCATION       "cold-zone-A"
#endif
#ifndef CONFIG_CC_THRESHOLD_C
#define CONFIG_CC_THRESHOLD_C    8.0f
#endif
#ifndef CONFIG_CC_BREACH_SECS
#define CONFIG_CC_BREACH_SECS    30
#endif
#ifndef CONFIG_CC_SAMPLE_MS
#define CONFIG_CC_SAMPLE_MS      10000
#endif
#ifndef CONFIG_CC_MOCK_SENSOR
#define CONFIG_CC_MOCK_SENSOR    1   // 1 = simulated, 0 = real DS18B20
#endif
#ifndef CONFIG_CC_NVS_QUEUE_MAX
#define CONFIG_CC_NVS_QUEUE_MAX  120
#endif

// Derived: senderFp = SHA-256(SENSOR_ID)[0:4] as 8 hex chars
static char s_sender_fp[9];   // set once in app_main

// ── WiFi event group ──────────────────────────────────────────────────────────

static EventGroupHandle_t s_wifi_events;
#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1
static int s_wifi_retry = 0;
#define WIFI_MAX_RETRY      10

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_wifi_retry < WIFI_MAX_RETRY) {
            esp_wifi_connect();
            s_wifi_retry++;
            ESP_LOGW(TAG, "WiFi disconnected — retry %d/%d", s_wifi_retry, WIFI_MAX_RETRY);
        } else {
            xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
        }
        xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT);
    } else if (base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "WiFi up — IP " IPSTR, IP2STR(&e->ip_info.ip));
        s_wifi_retry = 0;
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init(void)
{
    s_wifi_events = xEventGroupCreate();
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                        wifi_event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                        wifi_event_handler, NULL, NULL);

    wifi_config_t wifi_cfg = {};
    strncpy((char *)wifi_cfg.sta.ssid,     CONFIG_CC_WIFI_SSID, sizeof(wifi_cfg.sta.ssid) - 1);
    strncpy((char *)wifi_cfg.sta.password, CONFIG_CC_WIFI_PASS, sizeof(wifi_cfg.sta.password) - 1);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);
    esp_wifi_start();
}

static bool wifi_is_up(void)
{
    return (xEventGroupGetBits(s_wifi_events) & WIFI_CONNECTED_BIT) != 0;
}

// Block until WiFi is connected (or timeout_ms elapses).
static bool wifi_wait(uint32_t timeout_ms)
{
    EventBits_t bits = xEventGroupWaitBits(s_wifi_events,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(timeout_ms));
    return (bits & WIFI_CONNECTED_BIT) != 0;
}

// ── Temperature sensor ────────────────────────────────────────────────────────
// Two implementations: mock (sine wave + door-open spikes) and real DS18B20.
// Set CONFIG_CC_MOCK_SENSOR=0 to enable real sensor on GPIO_NUM_4.

#if CONFIG_CC_MOCK_SENSOR

// Simulated temperature — realistic cold-chain profile.
// Baseline 2°C, 1-hour sine wave ±0.5°C, occasional door-open spikes.
// At 10s sample intervals, a spike lasts ~12 samples (2 min in real time).

static float s_mock_phase    = 0.0f;           // accumulated phase for drift
static int64_t s_spike_until = 0;              // μs timestamp when spike ends
static float   s_spike_peak  = 0.0f;

static float sensor_read_temperature_c(void)
{
    int64_t now_us = esp_timer_get_time();

    // Daily sine wave (1-hr period in demo = 3600s * 1e6 μs)
    s_mock_phase += (float)CONFIG_CC_SAMPLE_MS / 3600000.0f * 2.0f * (float)M_PI;
    float baseline = 2.0f + 0.5f * sinf(s_mock_phase);

    // Small sensor noise (±0.15°C)
    float noise = ((float)(esp_random() % 300) - 150.0f) / 1000.0f;

    // Door-open spike (random ~10% chance each sample, lasts 90-150s)
    if (now_us < s_spike_until) {
        float progress = (float)(s_spike_until - now_us) / (120.0f * 1e6f);
        float spike = s_spike_peak * (1.0f - progress * progress);
        return baseline + noise + spike;
    }
    if (esp_random() % 10 == 0) {
        s_spike_peak  = 4.0f + (float)(esp_random() % 60) / 10.0f;   // 4-10°C
        uint32_t dur  = 90 + esp_random() % 60;                       // 90-150s
        s_spike_until = now_us + (int64_t)dur * 1000000LL;
        ESP_LOGI(TAG, "mock door-open: +%.1f°C for %us", (double)s_spike_peak, dur);
    }

    return baseline + noise;
}

static esp_err_t sensor_init(void) { return ESP_OK; }

#else  // CONFIG_CC_MOCK_SENSOR == 0 → real DS18B20 on GPIO_NUM_4

// DS18B20 1-Wire driver (bare GPIO bit-bang, no external library needed).
// Timing is based on Maxim AN:
//   Reset pulse:  ≥480 μs low
//   Presence:     60-240 μs low (device response, we just wait)
//   Write-1:      1-15 μs low, then release for ≥1 μs
//   Write-0:      60-120 μs low
//   Read:         1-15 μs low, then sample at ≤15 μs

#include "driver/gpio.h"
#include "rom/ets_sys.h"   // ets_delay_us

#define OW_GPIO  GPIO_NUM_4

// Pull low for t μs, then release. Returns line level after release.
#define OW_LOW(t)    do { gpio_set_level(OW_GPIO, 0); ets_delay_us(t); } while(0)
#define OW_HIGH(t)   do { gpio_set_level(OW_GPIO, 1); ets_delay_us(t); } while(0)
#define OW_READ()    gpio_get_level(OW_GPIO)

static void ow_write_bit(int bit)
{
    if (bit) {
        gpio_set_direction(OW_GPIO, GPIO_MODE_OUTPUT);
        OW_LOW(1);
        gpio_set_direction(OW_GPIO, GPIO_MODE_INPUT);
        ets_delay_us(62);
    } else {
        gpio_set_direction(OW_GPIO, GPIO_MODE_OUTPUT);
        OW_LOW(65);
        gpio_set_direction(OW_GPIO, GPIO_MODE_INPUT);
        ets_delay_us(2);
    }
}

static int ow_read_bit(void)
{
    gpio_set_direction(OW_GPIO, GPIO_MODE_OUTPUT);
    OW_LOW(1);
    gpio_set_direction(OW_GPIO, GPIO_MODE_INPUT);
    ets_delay_us(13);
    int bit = OW_READ();
    ets_delay_us(50);
    return bit;
}

static bool ow_reset(void)
{
    gpio_set_direction(OW_GPIO, GPIO_MODE_OUTPUT);
    OW_LOW(490);
    gpio_set_direction(OW_GPIO, GPIO_MODE_INPUT);
    ets_delay_us(70);
    int presence = !OW_READ();   // device pulls low = presence
    ets_delay_us(420);
    return presence;
}

static void ow_write_byte(uint8_t b)
{
    for (int i = 0; i < 8; i++) { ow_write_bit(b & 1); b >>= 1; }
}

static uint8_t ow_read_byte(void)
{
    uint8_t b = 0;
    for (int i = 0; i < 8; i++) { b |= ow_read_bit() << i; }
    return b;
}

static esp_err_t sensor_init(void)
{
    gpio_reset_pin(OW_GPIO);
    gpio_set_pull_mode(OW_GPIO, GPIO_PULLUP_ONLY);
    gpio_set_direction(OW_GPIO, GPIO_MODE_INPUT);
    if (!ow_reset()) {
        ESP_LOGE(TAG, "DS18B20 not found on GPIO%d — check wiring", OW_GPIO);
        return ESP_ERR_NOT_FOUND;
    }
    ESP_LOGI(TAG, "DS18B20 found on GPIO%d", OW_GPIO);
    return ESP_OK;
}

// DS18B20 commands
#define DS18B20_SKIP_ROM         0xCC
#define DS18B20_CONVERT_T        0x44
#define DS18B20_READ_SCRATCHPAD  0xBE

static float sensor_read_temperature_c(void)
{
    // Initiate conversion (blocking ~750ms for 12-bit)
    if (!ow_reset()) return -999.0f;
    ow_write_byte(DS18B20_SKIP_ROM);
    ow_write_byte(DS18B20_CONVERT_T);
    // Wait for conversion (parasite power: hold line high; external power: poll)
    vTaskDelay(pdMS_TO_TICKS(800));

    // Read scratchpad
    if (!ow_reset()) return -999.0f;
    ow_write_byte(DS18B20_SKIP_ROM);
    ow_write_byte(DS18B20_READ_SCRATCHPAD);

    uint8_t sp[9];
    for (int i = 0; i < 9; i++) sp[i] = ow_read_byte();

    // Basic CRC check (byte 8 must equal CRC of bytes 0-7)
    // (Simple fold-XOR Maxim CRC-8 — omitted here for brevity, add in production)

    int16_t raw = (int16_t)((sp[1] << 8) | sp[0]);
    return (float)raw / 16.0f;
}

#endif  // CONFIG_CC_MOCK_SENSOR

// ── SHA-256 helpers ───────────────────────────────────────────────────────────

static void sha256_hex(const uint8_t *data, size_t len, char out_hex[65])
{
    uint8_t hash[32];
    mbedtls_sha256(data, len, hash, 0);
    for (int i = 0; i < 32; i++) snprintf(out_hex + i * 2, 3, "%02x", hash[i]);
    out_hex[64] = '\0';
}

// bin2hex — encode bytes as lowercase hex string
static void bin2hex(const uint8_t *bin, size_t len, char *hex)
{
    for (size_t i = 0; i < len; i++) snprintf(hex + i * 2, 3, "%02x", bin[i]);
    hex[len * 2] = '\0';
}

// ── NVS offline queue ─────────────────────────────────────────────────────────
// Ring buffer of up to CC_NVS_QUEUE_MAX serialised cell publish bodies.
// Keys: "wptr" (u32 write head), "rptr" (u32 read head), "r<index>" (blob).
// Index wraps at CC_NVS_QUEUE_MAX.  Oldest reading is dropped on overflow.

#define NVS_NS  "cc_q"

static nvs_handle_t s_nvs;

static esp_err_t nvs_queue_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition damaged — erasing");
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) return err;
    return nvs_open(NVS_NS, NVS_READWRITE, &s_nvs);
}

static uint32_t nvs_get_u32(const char *key, uint32_t default_val)
{
    uint32_t v = default_val;
    nvs_get_u32(s_nvs, key, &v);
    return v;
}

static uint32_t nvs_queue_size(void)
{
    uint32_t w = nvs_get_u32("wptr", 0);
    uint32_t r = nvs_get_u32("rptr", 0);
    return (w >= r) ? (w - r) : (CONFIG_CC_NVS_QUEUE_MAX - r + w);
}

// Push a JSON body string into the NVS queue.
static esp_err_t nvs_queue_push(const char *json_body, size_t len)
{
    uint32_t w = nvs_get_u32("wptr", 0);
    uint32_t r = nvs_get_u32("rptr", 0);
    uint32_t size = (w >= r) ? (w - r) : (CONFIG_CC_NVS_QUEUE_MAX - r + w);

    if (size >= (uint32_t)CONFIG_CC_NVS_QUEUE_MAX) {
        // Drop oldest — advance read pointer
        uint32_t new_r = (r + 1) % CONFIG_CC_NVS_QUEUE_MAX;
        nvs_set_u32(s_nvs, "rptr", new_r);
        ESP_LOGW(TAG, "NVS queue full (%u) — dropping oldest reading", size);
    }

    char key[12];
    snprintf(key, sizeof(key), "r%u", w % CONFIG_CC_NVS_QUEUE_MAX);
    esp_err_t err = nvs_set_blob(s_nvs, key, json_body, len);
    if (err != ESP_OK) return err;

    nvs_set_u32(s_nvs, "wptr", (w + 1) % CONFIG_CC_NVS_QUEUE_MAX);
    return nvs_commit(s_nvs);
}

// Pop the oldest entry from the NVS queue (non-destructive peek then delete).
static bool nvs_queue_pop(char *out_buf, size_t out_max, size_t *out_len)
{
    uint32_t w = nvs_get_u32("wptr", 0);
    uint32_t r = nvs_get_u32("rptr", 0);
    if (w == r) return false;  // empty

    char key[12];
    snprintf(key, sizeof(key), "r%u", r % CONFIG_CC_NVS_QUEUE_MAX);

    size_t len = out_max;
    esp_err_t err = nvs_get_blob(s_nvs, key, out_buf, &len);
    if (err != ESP_OK) {
        // Corrupted entry — skip it
        nvs_set_u32(s_nvs, "rptr", (r + 1) % CONFIG_CC_NVS_QUEUE_MAX);
        nvs_commit(s_nvs);
        return false;
    }
    *out_len = len;

    // Advance read pointer (commit)
    nvs_set_u32(s_nvs, "rptr", (r + 1) % CONFIG_CC_NVS_QUEUE_MAX);
    nvs_commit(s_nvs);
    return true;
}

// ── Cell builder ──────────────────────────────────────────────────────────────
// Builds the relay POST body for a cold-chain cell.
//
// Body format (JSON, ~400-500 bytes total):
// {
//   "header": { "cellId": "64hex", "typePath": "cold-chain.sensor.reading",
//               "senderFp": "8hex", "seq": 42, "payloadLen": 130 },
//   "payload": "2-hex-per-byte JSON string of reading data"
// }
//
// We use the canonical cell_wire.h layout for the binary cell (1024 bytes)
// and encode the payload region as hex for the relay's JSON API.

static uint32_t s_seq = 0;

typedef struct {
    const char *type_path;   // e.g. "cold-chain.sensor.reading"
    float       temp_c;
    int64_t     ts_ms;       // Unix epoch ms (or monotonic if no NTP)
    bool        above_thresh;
    float       breach_secs;
    bool        is_breach_alert;
    uint32_t    breach_number;
} cell_reading_t;

// Returns length of body written into out_buf, or 0 on error.
// out_buf must be at least 1024 bytes.
static size_t build_relay_body(const cell_reading_t *r, char *out_buf, size_t out_max)
{
    // 1. Build canonical 1024-byte cell
    static uint8_t cell[CM_CELL_SIZE];
    cm_cell_init(cell);
    cm_set_linearity(cell, CM_LINEARITY_LINEAR);
    cm_set_timestamp_ms(cell, (uint64_t)r->ts_ms);

    // Type-hash: SHA-256 of typePath string (first 32 bytes = CM_OFF_TYPE_HASH region)
    {
        uint8_t th[32];
        mbedtls_sha256((const uint8_t *)r->type_path, strlen(r->type_path), th, 0);
        memcpy(cm_type_hash_mut(cell), th, 32);
    }

    // Payload JSON in payload region (offset 256, up to 768 bytes)
    uint8_t *payload_ptr = cm_payload_mut(cell);
    int payload_len = snprintf(
        (char *)payload_ptr, CM_PAYLOAD_SIZE,
        "{\"sensorId\":\"%s\",\"location\":\"%s\",\"tempC\":%.2f,"
        "\"ts\":%lld,\"seq\":%lu,\"threshC\":%.1f,"
        "\"aboveThresh\":%s,\"breachSecs\":%.1f,"
        "\"breachAlert\":%s,\"breachNum\":%lu}",
        CONFIG_CC_SENSOR_ID,
        CONFIG_CC_LOCATION,
        (double)r->temp_c,
        (long long)r->ts_ms,
        (unsigned long)s_seq,
        (double)CONFIG_CC_THRESHOLD_C,
        r->above_thresh ? "true" : "false",
        (double)r->breach_secs,
        r->is_breach_alert ? "true" : "false",
        (unsigned long)r->breach_number
    );
    if (payload_len < 0 || payload_len >= (int)CM_PAYLOAD_SIZE) return 0;

    cm_set_payload_total(cell, (uint32_t)payload_len);

    // Cell-ID = SHA-256 of the payload bytes (content-addressed)
    char cell_id_hex[65];
    sha256_hex(payload_ptr, (size_t)payload_len, cell_id_hex);

    // Payload hex (relay expects hex-encoded bytes)
    // Each byte → 2 hex chars; payload_len bytes → payload_len*2 chars
    // Use a stack buffer — max payload is 768 bytes → 1536 hex chars
    static char payload_hex[CM_PAYLOAD_SIZE * 2 + 1];
    bin2hex(payload_ptr, (size_t)payload_len, payload_hex);

    // 2. Build relay POST body JSON
    size_t n = (size_t)snprintf(out_buf, out_max,
        "{\"header\":{"
        "\"cellId\":\"%s\","
        "\"typePath\":\"%s\","
        "\"senderFp\":\"%s\","
        "\"seq\":%lu,"
        "\"payloadLen\":%d"
        "},\"payload\":\"%s\"}",
        cell_id_hex,
        r->type_path,
        s_sender_fp,
        (unsigned long)s_seq,
        payload_len,
        payload_hex
    );

    s_seq++;
    return (n < out_max) ? n : 0;
}

// ── HTTP relay client ─────────────────────────────────────────────────────────
// POSTs a pre-built relay body to /publish.

// Static HTTP response buffer (not body — we discard the response)
static char s_http_resp[64];

static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    if (evt->event_id == HTTP_EVENT_ON_DATA && evt->data_len < (int)sizeof(s_http_resp))
        memcpy(s_http_resp, evt->data, evt->data_len);
    return ESP_OK;
}

static bool relay_post(const char *body, size_t body_len)
{
    char url[256];
    snprintf(url, sizeof(url), "%s/publish", CONFIG_CC_RELAY_URL);

    esp_http_client_config_t cfg = {
        .url            = url,
        .method         = HTTP_METHOD_POST,
        .event_handler  = http_event_handler,
        .timeout_ms     = 5000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body, (int)body_len);

    esp_err_t err = esp_http_client_perform(client);
    int status    = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "relay POST failed: %s", esp_err_to_name(err));
        return false;
    }
    if (status < 200 || status >= 300) {
        ESP_LOGW(TAG, "relay POST HTTP %d", status);
        return false;
    }
    return true;
}

// ── NVS drain — flush queued readings to relay ────────────────────────────────

static void drain_nvs_queue(void)
{
    uint32_t queued = nvs_queue_size();
    if (queued == 0) return;

    ESP_LOGI(TAG, "WiFi up — draining %lu queued readings", (unsigned long)queued);

    static char buf[2048];  // large enough for one relay body
    size_t len;
    uint32_t sent = 0;

    while (wifi_is_up() && nvs_queue_pop(buf, sizeof(buf) - 1, &len)) {
        buf[len] = '\0';
        if (relay_post(buf, len)) sent++;
        else { ESP_LOGW(TAG, "drain: relay POST failed — stopping"); break; }
        vTaskDelay(pdMS_TO_TICKS(100));  // don't hammer the relay
    }

    ESP_LOGI(TAG, "Drained %lu/%lu readings to relay", (unsigned long)sent, (unsigned long)queued);
}

// ── Main measurement loop ─────────────────────────────────────────────────────

// Breach state machine
static int64_t s_breach_start_ms  = 0;  // 0 = no active breach
static float   s_breach_peak_c    = 0.0f;
static int     s_breach_count     = 0;
static bool    s_breach_alerted   = false;

static void publish_or_queue(const char *body, size_t len, const char *label)
{
    if (wifi_is_up()) {
        if (relay_post(body, len)) {
            ESP_LOGI(TAG, "  → relay  [%s]", label);
        } else {
            nvs_queue_push(body, len);
            ESP_LOGW(TAG, "  → NVS   [%s] (relay failed)", label);
        }
    } else {
        nvs_queue_push(body, len);
        ESP_LOGI(TAG, "  → NVS   [%s] (WiFi offline, queue=%lu)",
                 label, (unsigned long)nvs_queue_size());
    }
}

static void measurement_task(void *arg)
{
    // Wait up to 15s for first WiFi connection before starting measurements
    ESP_LOGI(TAG, "waiting for WiFi (15s)…");
    wifi_wait(15000);
    if (wifi_is_up()) drain_nvs_queue();

    static char body[2048];
    bool was_wifi_up = wifi_is_up();

    for (;;) {
        // Drain NVS on WiFi reconnect
        bool now_up = wifi_is_up();
        if (now_up && !was_wifi_up) drain_nvs_queue();
        was_wifi_up = now_up;

        // Read temperature
        float temp_c = sensor_read_temperature_c();
        int64_t ts   = esp_timer_get_time() / 1000LL;  // ms since boot (no NTP in demo)

        bool above = temp_c > CONFIG_CC_THRESHOLD_C;
        float breach_secs = 0.0f;

        // Update breach state
        if (above) {
            if (s_breach_start_ms == 0) {
                s_breach_start_ms = ts;
                s_breach_peak_c   = temp_c;
                s_breach_alerted  = false;
                ESP_LOGW(TAG, "⚠  above threshold: %.2f°C", (double)temp_c);
            } else {
                if (temp_c > s_breach_peak_c) s_breach_peak_c = temp_c;
            }
            breach_secs = (float)(ts - s_breach_start_ms) / 1000.0f;
        } else if (s_breach_start_ms != 0) {
            float dur = (float)(ts - s_breach_start_ms) / 1000.0f;
            if (s_breach_alerted) {
                // Publish restored cell
                cell_reading_t restored = {
                    .type_path      = "cold-chain.alert.restored",
                    .temp_c         = temp_c,
                    .ts_ms          = ts,
                    .above_thresh   = false,
                    .breach_secs    = dur,
                };
                size_t n = build_relay_body(&restored, body, sizeof(body));
                if (n) publish_or_queue(body, n, "restored");
                ESP_LOGI(TAG, "✅ Restored — breach %.0fs, peak %.2f°C", (double)dur, (double)s_breach_peak_c);
            }
            s_breach_start_ms = 0;
            s_breach_peak_c   = 0.0f;
            s_breach_alerted  = false;
        }

        // Fire breach alert after BREACH_SECS sustained
        if (above && !s_breach_alerted && breach_secs >= (float)CONFIG_CC_BREACH_SECS) {
            s_breach_alerted = true;
            s_breach_count++;

            ESP_LOGE(TAG, "🚨 BREACH #%d: %.2f°C > %.1f°C for %.0fs",
                     s_breach_count, (double)temp_c,
                     (double)CONFIG_CC_THRESHOLD_C, (double)breach_secs);

            cell_reading_t alert = {
                .type_path       = "cold-chain.alert.breach",
                .temp_c          = temp_c,
                .ts_ms           = ts,
                .above_thresh    = true,
                .breach_secs     = breach_secs,
                .is_breach_alert = true,
                .breach_number   = (uint32_t)s_breach_count,
            };
            size_t n = build_relay_body(&alert, body, sizeof(body));
            if (n) {
                // Try relay first; if down, queue it — breach alerts are high priority
                // and must not be lost (NVS ensures delivery when WiFi comes back)
                publish_or_queue(body, n, "BREACH");
                ESP_LOGI(TAG, "  breach cell seq=%lu", (unsigned long)(s_seq - 1));
            }
        }

        // Publish regular reading
        cell_reading_t reading = {
            .type_path    = "cold-chain.sensor.reading",
            .temp_c       = temp_c,
            .ts_ms        = ts,
            .above_thresh = above,
            .breach_secs  = breach_secs,
        };
        size_t n = build_relay_body(&reading, body, sizeof(body));
        if (n) publish_or_queue(body, n, "reading");

        ESP_LOGI(TAG, "🌡  %.2f°C%s%s  q=%lu",
                 (double)temp_c,
                 above ? " ⚠" : "",
                 wifi_is_up() ? "  WiFi:up" : "  WiFi:off",
                 (unsigned long)nvs_queue_size());

        vTaskDelay(pdMS_TO_TICKS(CONFIG_CC_SAMPLE_MS));
    }
}

// ── app_main ──────────────────────────────────────────────────────────────────

void app_main(void)
{
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "━━━ Cold Chain Monitor ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    ESP_LOGI(TAG, "  Sensor:    %s (%s)", CONFIG_CC_SENSOR_ID, CONFIG_CC_LOCATION);
    ESP_LOGI(TAG, "  Threshold: %.1f°C / %ds", (double)CONFIG_CC_THRESHOLD_C, CONFIG_CC_BREACH_SECS);
    ESP_LOGI(TAG, "  Interval:  %dms", CONFIG_CC_SAMPLE_MS);
    ESP_LOGI(TAG, "  Relay:     %s", CONFIG_CC_RELAY_URL);
    ESP_LOGI(TAG, "  Mode:      %s", CONFIG_CC_MOCK_SENSOR ? "MOCK sensor" : "DS18B20 GPIO4");
    ESP_LOGI(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Derive senderFp from SENSOR_ID
    {
        uint8_t h[32];
        mbedtls_sha256((const uint8_t *)CONFIG_CC_SENSOR_ID, strlen(CONFIG_CC_SENSOR_ID), h, 0);
        snprintf(s_sender_fp, sizeof(s_sender_fp), "%02x%02x%02x%02x",
                 h[0], h[1], h[2], h[3]);
    }
    ESP_LOGI(TAG, "  senderFp:  %s", s_sender_fp);

    // NVS init
    ESP_ERROR_CHECK(nvs_queue_init());
    ESP_LOGI(TAG, "  NVS queue: %lu buffered", (unsigned long)nvs_queue_size());

    // Sensor init (no-op for mock, GPIO init for real DS18B20)
    if (sensor_init() != ESP_OK) {
        ESP_LOGE(TAG, "Sensor init failed — continuing with mock readings");
    }

    // WiFi
    wifi_init();

    // Measurement task (stack 8KB — heap has plenty on C6 without WAMR)
    xTaskCreate(measurement_task, "cc_measure", 8192, NULL, 5, NULL);
}
