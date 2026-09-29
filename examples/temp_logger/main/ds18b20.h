// ds18b20.h — one DS18B20 on a bit-banged 1-Wire pin.
//
// Decoding and validation live in the core (cm_ds18b20_decode); this file
// only moves bits. One probe per pin, addressed with SKIP ROM.

#pragma once

#include <stdint.h>
#include "esp_err.h"

// Configure the pin (open drain, pull-up on) and check a probe answers.
esp_err_t ds18b20_init(int gpio);

// Convert and read, retrying transient faults. Returns a CM_DS_* code from
// cell_templog.h: CM_DS_OK with *out_centi set, CM_DS_POR if the probe kept
// reporting its 85 °C power-on value, or the last error seen.
int ds18b20_read(int gpio, int16_t *out_centi);
