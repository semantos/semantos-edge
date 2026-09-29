// cell_templog.h — the temperature logger's pure core, behind the cm_* ABI.
//
// DS18B20 decoding, the flash record and its ring, the store-and-forward
// window, the batch and ack payload codecs, the send schedule, and the heat
// policy's scripts. Implemented in components/cell-mesh-zig/src/cell_templog.zig;
// layouts and rules are in docs/TEMP-LOGGER.md. No I/O: examples/temp_logger
// does the flash, radio and sensor work around it.
//
// Not thread-safe. Caller serializes access.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CM_TLOG_BATCH_TYPE_NAME   "templog.batch.v0"
#define CM_TLOG_ACK_TYPE_NAME     "templog.ack.v0"

#define CM_TLOG_RECORD_SIZE         16u
#define CM_TLOG_RECORDS_PER_SECTOR 256u
#define CM_TLOG_BATCH_HEADER_SIZE   40u
#define CM_TLOG_SAMPLE_SIZE          8u
#define CM_TLOG_BATCH_MAX_SAMPLES   91u
#define CM_TLOG_ACK_SIZE            16u
#define CM_TLOG_SCHED_MIN_BACKOFF_MS 2000u

// centi-°C stored when there is no valid reading.
#define CM_TLOG_TEMP_INVALID ((int16_t)-32768)

// Sample flags.
#define CM_TLOG_SF_POLICY_REJECT 0x01u  // outside the safe band, or the engine could not say
#define CM_TLOG_SF_VM_ERROR      0x02u  // the engine failed to evaluate
#define CM_TLOG_SF_SENSOR_ERROR  0x04u  // no valid reading
#define CM_TLOG_SF_POR_SUSPECT   0x08u  // the probe's 85 °C power-on value, twice
#define CM_TLOG_SF_RECORD_LOST   0x10u  // the flash record could not be read

// cm_ds18b20_decode results.
#define CM_DS_OK            0
#define CM_DS_POR           1   // decoded, but it is the 85 °C power-on value
#define CM_DS_ERR_NULL     -1
#define CM_DS_ERR_NO_DEVICE -2  // line stuck high or low
#define CM_DS_ERR_CRC      -3
#define CM_DS_ERR_RANGE    -4

typedef struct {
    uint32_t seq;
    uint32_t boot_id;
    uint32_t uptime_s;
    int16_t  centi_c;
    uint8_t  flags;
} cm_tlog_record_t;

typedef struct {
    uint32_t capacity;       // records; whole sectors, at least two
    uint32_t next_seq;       // the seq the next append receives, >= 1
    uint32_t oldest_seq;     // oldest record still in flash
    uint32_t acked_through;  // host holds every seq up to this; 0 = nothing
    uint32_t rec_min;        // recovery scratch
    uint32_t rec_max;
} cm_tlog_log_t;

typedef struct {
    uint8_t  version;
    uint8_t  flags;
    uint16_t count;
    uint32_t first_seq;
    uint32_t boot_id;
    uint32_t boot_now;
    uint32_t uptime_now_s;
    uint32_t boot_epoch_s;
    uint32_t lost_through;
    uint32_t sample_interval_s;
    int16_t  policy_min_centi;
    int16_t  policy_max_centi;
    uint32_t log_id;
} cm_tlog_batch_header_t;

typedef struct {
    uint64_t next_due_ms;
    uint32_t backoff_ms;
} cm_tlog_sched_t;

// ── CRC and the probe ────────────────────────────────────────────────
uint8_t cm_crc8_maxim(const uint8_t *data, size_t len);
int     cm_ds18b20_decode(const uint8_t scratchpad[9], int16_t *out_centi);

// ── Flash record ─────────────────────────────────────────────────────
void cm_tlog_record_encode(const cm_tlog_record_t *rec, uint8_t out[CM_TLOG_RECORD_SIZE]);
bool cm_tlog_record_decode(const uint8_t in[CM_TLOG_RECORD_SIZE], cm_tlog_record_t *out);
bool cm_tlog_record_is_erased(const uint8_t in[CM_TLOG_RECORD_SIZE]);

// ── Ring ─────────────────────────────────────────────────────────────
uint32_t cm_tlog_slot_for_seq(uint32_t seq, uint32_t capacity);
bool     cm_tlog_erase_before_write(uint32_t seq, uint32_t capacity);

void     cm_tlog_init(cm_tlog_log_t *log, uint32_t capacity);
// Reserve the next seq (0 if the log is unusable). Erase first when
// cm_tlog_erase_before_write says so, then write the record.
uint32_t cm_tlog_append(cm_tlog_log_t *log);
// Burn next_seq without writing it: its slot was found programmed.
uint32_t cm_tlog_skip_seq(cm_tlog_log_t *log);
uint32_t cm_tlog_pending_first(const cm_tlog_log_t *log);
uint32_t cm_tlog_pending(const cm_tlog_log_t *log);
uint32_t cm_tlog_lost_through(const cm_tlog_log_t *log);
// Sets the pointer, clamped to the newest record. Lower = replay request.
uint32_t cm_tlog_apply_ack(cm_tlog_log_t *log, uint32_t acked_through);

// Recovery: begin, feed every slot that decodes, finish with NVS's values.
void cm_tlog_recover_begin(cm_tlog_log_t *log, uint32_t capacity);
void cm_tlog_recover_feed(cm_tlog_log_t *log, uint32_t slot, const cm_tlog_record_t *rec);
void cm_tlog_recover_finish(cm_tlog_log_t *log, uint32_t persisted_acked, uint32_t seq_floor);

// ── Batch payload (768 bytes) ────────────────────────────────────────
// begin() ignores h->count and h->version; set first_seq and boot_id to the
// first sample you will add.
void     cm_tlog_batch_begin(uint8_t *payload, const cm_tlog_batch_header_t *h);
bool     cm_tlog_batch_add(uint8_t *payload, const cm_tlog_record_t *rec);
bool     cm_tlog_batch_add_lost(uint8_t *payload, uint32_t seq);
uint16_t cm_tlog_batch_count(const uint8_t *payload);
size_t   cm_tlog_batch_used_bytes(const uint8_t *payload);
bool     cm_tlog_batch_decode_header(const uint8_t *payload, size_t len, cm_tlog_batch_header_t *out);
bool     cm_tlog_batch_sample(const uint8_t *payload, size_t len, uint16_t i, cm_tlog_record_t *out);

// ── Ack payload ──────────────────────────────────────────────────────
void cm_tlog_ack_encode(uint8_t *payload, const uint8_t target_mac[6],
                        uint32_t acked_through, uint32_t host_unix_s);
bool cm_tlog_ack_decode(const uint8_t *payload, size_t len, uint8_t out_mac[6],
                        uint32_t *out_acked_through, uint32_t *out_host_unix_s);

// ── Send schedule ────────────────────────────────────────────────────
void cm_tlog_sched_init(cm_tlog_sched_t *s);
bool cm_tlog_sched_should_send(const cm_tlog_sched_t *s, uint64_t now_ms, uint32_t pending);
void cm_tlog_sched_on_sent(cm_tlog_sched_t *s, uint64_t now_ms, uint32_t max_backoff_ms);
void cm_tlog_sched_on_ack(cm_tlog_sched_t *s, uint64_t now_ms);

// ── Script numbers and the heat policy ───────────────────────────────
// Minimal script-number push; bytes written, or 0 if it does not fit.
size_t cm_script_num_push(int32_t value, uint8_t *out, size_t cap);
// <min> <max+1> OP_WITHIN — accepts min <= x <= max. 0 if the band is empty.
size_t cm_tlog_policy_lock(int16_t min_centi, int16_t max_centi, uint8_t *out, size_t cap);
size_t cm_tlog_policy_unlock(int16_t centi, uint8_t *out, size_t cap);

#ifdef __cplusplus
}
#endif
