// tlog_store.c — flash and NVS I/O for the reading log. See tlog_store.h.

#include "tlog_store.h"

#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "nvs_flash.h"

static const char *TAG = "tlog_store";

#define NVS_NS        "templog"
#define KEY_BOOT      "boot"
#define KEY_LOG_ID    "log_id"
#define KEY_ACKED     "acked"
#define KEY_EPOCHS    "epochs"

static uint32_t nvs_u32(nvs_handle_t h, const char *key, uint32_t dflt) {
    uint32_t v = dflt;
    if (nvs_get_u32(h, key, &v) != ESP_OK) v = dflt;
    return v;
}

static void nvs_put_u32(nvs_handle_t h, const char *key, uint32_t v) {
    esp_err_t err = nvs_set_u32(h, key, v);
    if (err == ESP_OK) err = nvs_commit(h);
    if (err != ESP_OK) ESP_LOGW(TAG, "nvs %s: %s", key, esp_err_to_name(err));
}

static uint32_t fresh_log_id(void) {
    uint32_t id = 0;
    while (id == 0) id = esp_random();
    return id;
}

static bool read_slot(const tlog_store_t *st, uint32_t slot, uint8_t buf[CM_TLOG_RECORD_SIZE]) {
    return esp_partition_read(st->part, (size_t)slot * CM_TLOG_RECORD_SIZE,
                              buf, CM_TLOG_RECORD_SIZE) == ESP_OK;
}

esp_err_t tlog_store_init(tlog_store_t *st) {
    memset(st, 0, sizeof *st);

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) return err;
    err = nvs_open(NVS_NS, NVS_READWRITE, &st->nvs);
    if (err != ESP_OK) return err;

    st->part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                        ESP_PARTITION_SUBTYPE_DATA_UNDEFINED, "templog");
    if (!st->part) {
        ESP_LOGE(TAG, "no `templog` partition — flash with this example's partitions.csv");
        return ESP_ERR_NOT_FOUND;
    }

    st->boot_id = nvs_u32(st->nvs, KEY_BOOT, 0) + 1;
    nvs_put_u32(st->nvs, KEY_BOOT, st->boot_id);

    size_t len = sizeof st->epochs;
    if (nvs_get_blob(st->nvs, KEY_EPOCHS, st->epochs, &len) != ESP_OK) memset(st->epochs, 0, sizeof st->epochs);

    // Rebuild the log from flash: every slot that decodes, placed by the core.
    uint32_t capacity = (uint32_t)(st->part->size / CM_TLOG_RECORD_SIZE);
    cm_tlog_recover_begin(&st->log, capacity);
    if (st->log.capacity == 0) {
        ESP_LOGE(TAG, "`templog` is %u bytes; the ring needs at least two 4 KB sectors",
                 (unsigned)st->part->size);
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t buf[CM_TLOG_RECORD_SIZE];
    uint32_t found = 0;
    for (uint32_t slot = 0; slot < st->log.capacity; slot++) {
        cm_tlog_record_t rec;
        if (read_slot(st, slot, buf) && cm_tlog_record_decode(buf, &rec)) {
            cm_tlog_recover_feed(&st->log, slot, &rec);
            found++;
        }
    }

    uint32_t acked = nvs_u32(st->nvs, KEY_ACKED, 0);
    st->log_id = nvs_u32(st->nvs, KEY_LOG_ID, 0);
    if (found == 0) {
        // Nothing on flash: a first boot, or the partition was wiped while NVS
        // survived. Every boot logs within one interval, so there is no third
        // case. A new log starts at seq 1 under a new id, and the host cannot
        // mistake its seqs for an old log's.
        st->log_id = fresh_log_id();
        acked = 0;
        nvs_put_u32(st->nvs, KEY_LOG_ID, st->log_id);
        nvs_put_u32(st->nvs, KEY_ACKED, 0);
    }
    cm_tlog_recover_finish(&st->log, acked, 0);

    // The slot after the newest record should be erased. If power failed
    // while it was being written it is not, and NOR flash cannot be written
    // again without erasing the whole sector: burn the seq instead. It will
    // travel to the host as a lost record. At a sector start the erase that
    // precedes the write takes care of it.
    while (!cm_tlog_erase_before_write(st->log.next_seq, st->log.capacity)) {
        uint32_t slot = cm_tlog_slot_for_seq(st->log.next_seq, st->log.capacity);
        if (!read_slot(st, slot, buf) || cm_tlog_record_is_erased(buf)) break;
        uint32_t burned = cm_tlog_skip_seq(&st->log);
        ESP_LOGW(TAG, "seq %u: slot %u half-written by a power cut, skipped", (unsigned)burned, (unsigned)slot);
    }

    ESP_LOGI(TAG, "log %08x boot %u: %u records, seqs %u..%u, acked through %u, %u pending",
             (unsigned)st->log_id, (unsigned)st->boot_id, (unsigned)found,
             (unsigned)st->log.oldest_seq, (unsigned)(st->log.next_seq - 1),
             (unsigned)st->log.acked_through, (unsigned)cm_tlog_pending(&st->log));
    return ESP_OK;
}

uint32_t tlog_store_append(tlog_store_t *st, const cm_tlog_record_t *in) {
    uint32_t seq = cm_tlog_append(&st->log);
    if (seq == 0) return 0;
    uint32_t slot = cm_tlog_slot_for_seq(seq, st->log.capacity);

    if (cm_tlog_erase_before_write(seq, st->log.capacity)) {
        size_t sector = (size_t)(slot / CM_TLOG_RECORDS_PER_SECTOR) * CM_TLOG_RECORDS_PER_SECTOR * CM_TLOG_RECORD_SIZE;
        esp_err_t err = esp_partition_erase_range(st->part, sector,
                                                  CM_TLOG_RECORDS_PER_SECTOR * CM_TLOG_RECORD_SIZE);
        if (err != ESP_OK) ESP_LOGE(TAG, "erase sector at 0x%x: %s", (unsigned)sector, esp_err_to_name(err));
    }

    cm_tlog_record_t rec = *in;
    rec.seq = seq;
    uint8_t buf[CM_TLOG_RECORD_SIZE];
    cm_tlog_record_encode(&rec, buf);
    esp_err_t err = esp_partition_write(st->part, (size_t)slot * CM_TLOG_RECORD_SIZE, buf, sizeof buf);
    if (err != ESP_OK) ESP_LOGE(TAG, "write seq %u: %s", (unsigned)seq, esp_err_to_name(err));
    return seq;
}

bool tlog_store_read(const tlog_store_t *st, uint32_t seq, cm_tlog_record_t *out) {
    if (seq < st->log.oldest_seq || seq >= st->log.next_seq) return false;
    uint8_t buf[CM_TLOG_RECORD_SIZE];
    if (!read_slot(st, cm_tlog_slot_for_seq(seq, st->log.capacity), buf)) return false;
    return cm_tlog_record_decode(buf, out) && out->seq == seq;
}

void tlog_store_set_acked(tlog_store_t *st, uint32_t acked_through) {
    uint32_t before = st->log.acked_through;
    uint32_t now = cm_tlog_apply_ack(&st->log, acked_through);
    if (now != before) nvs_put_u32(st->nvs, KEY_ACKED, now);
}

uint32_t tlog_store_epoch_for(const tlog_store_t *st, uint32_t boot_id) {
    for (int i = 0; i < TLOG_EPOCHS; i++) {
        if (st->epochs[i].boot_id == boot_id && st->epochs[i].epoch_s != 0) return st->epochs[i].epoch_s;
    }
    return 0;
}

void tlog_store_note_epoch(tlog_store_t *st, uint32_t boot_id, uint32_t epoch_s) {
    if (epoch_s == 0 || tlog_store_epoch_for(st, boot_id) != 0) return;
    // Keep the newest few boots: shift out the oldest.
    memmove(&st->epochs[1], &st->epochs[0], sizeof st->epochs[0] * (TLOG_EPOCHS - 1));
    st->epochs[0].boot_id = boot_id;
    st->epochs[0].epoch_s = epoch_s;
    esp_err_t err = nvs_set_blob(st->nvs, KEY_EPOCHS, st->epochs, sizeof st->epochs);
    if (err == ESP_OK) err = nvs_commit(st->nvs);
    if (err != ESP_OK) ESP_LOGW(TAG, "nvs epochs: %s", esp_err_to_name(err));
}
