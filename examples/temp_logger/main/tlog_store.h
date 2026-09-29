// tlog_store.h — the reading log on flash, and what NVS remembers about it.
//
// The ring's rules (slots, erases, recovery, the delivery window) are the
// core's, in cell_templog.h. This file only reads and writes: the `templog`
// data partition for records, and NVS namespace "templog" for the boot count,
// the log id, the delivery pointer and each boot's start time.

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "cell_templog.h"
#include "esp_err.h"
#include "esp_partition.h"
#include "nvs.h"

#define TLOG_EPOCHS 4

typedef struct {
    const esp_partition_t *part;
    nvs_handle_t nvs;
    cm_tlog_log_t log;
    uint32_t boot_id;   // this boot; counts up across power cycles
    uint32_t log_id;    // random; a new one whenever the old log is gone
    struct { uint32_t boot_id, epoch_s; } epochs[TLOG_EPOCHS];
} tlog_store_t;

// Open NVS and the partition, count this boot, and rebuild the log from what
// flash holds. Call once, before the radio and before the engine.
esp_err_t tlog_store_init(tlog_store_t *st);

// Append a reading. `rec->seq` is ignored and assigned. Returns the seq, or 0
// if the log is unusable. A failed flash write still consumes the seq.
uint32_t tlog_store_append(tlog_store_t *st, const cm_tlog_record_t *rec);

// Read one seq back. False when its record is missing or unreadable.
bool tlog_store_read(const tlog_store_t *st, uint32_t seq, cm_tlog_record_t *out);

// Apply an ack from the host and remember it across reboots.
void tlog_store_set_acked(tlog_store_t *st, uint32_t acked_through);

// When boot `boot_id` started, in Unix seconds; 0 if never learned.
uint32_t tlog_store_epoch_for(const tlog_store_t *st, uint32_t boot_id);
void tlog_store_note_epoch(tlog_store_t *st, uint32_t boot_id, uint32_t epoch_s);
