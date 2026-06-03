// semantos.h — public API of the Semantos cell-engine ESP-IDF component.
//
// Load the embedded WASM blob, register host imports (crypto + utility) and
// the four adapters (storage / identity / anchor / network), then call
// kernel_* exports. The WASM module is ~29KB; the glue here is small.
//
// Typical lifecycle:
//
//     semantos_t *sem;
//     semantos_config_t cfg = SEMANTOS_DEFAULT_CONFIG();
//     cfg.adapters = /* your adapter function table, or NULL for no-ops */;
//     ESP_ERROR_CHECK(semantos_init(&cfg, &sem));
//
//     int rc = semantos_kernel_init(sem);
//     rc = semantos_kernel_load_script(sem, script, script_len);
//     rc = semantos_kernel_execute(sem);
//
//     semantos_destroy(sem);
//
// The adapter callbacks are what make the kernel "do something" on the
// device. Wire them to NVS, SPIFFS, MQTT, BLE, LoRa, whatever — the kernel
// does not care.

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "semantos_adapters.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct semantos_ctx semantos_t;

typedef struct {
    // Stack size for the WASM module in bytes. Defaults to
    // CONFIG_SEMANTOS_WASM_STACK_SIZE.
    uint32_t wasm_stack_size;

    // Adapter function table. NULL is allowed — the no-op stub table is
    // registered in that case and any kernel I/O call fails with
    // SEMANTOS_ERR_DENIED.
    const semantos_adapter_table_t *adapters;
} semantos_config_t;

#define SEMANTOS_DEFAULT_CONFIG() ((semantos_config_t){ \
    .wasm_stack_size = 0, /* use Kconfig default */ \
    .adapters = NULL, \
})

// Return codes from kernel exports mirror the Zig-side status codes.
// 0 = success; anything else is an error.
#define SEMANTOS_OK              0
#define SEMANTOS_ERR_UNINIT     -1
#define SEMANTOS_ERR_DENIED     -2
#define SEMANTOS_ERR_BADARG     -3
#define SEMANTOS_ERR_BADSTATE   -4
#define SEMANTOS_ERR_INTERNAL   -99

// Boot: load the WASM module, register imports, allocate runtime state.
// Returns ESP_OK on success.
esp_err_t semantos_init(const semantos_config_t *cfg, semantos_t **out);

// Tear down and free all runtime state.
void semantos_destroy(semantos_t *sem);

// ── Kernel exports (thin wrappers around the WASM module exports) ──
// These map one-to-one to the exports declared in
// packages/cell-engine/src/main.zig. Only the ones you are likely to need
// from a meetup hack project are surfaced here; the others can be added by
// following the same pattern.

int semantos_kernel_init(semantos_t *sem);
void semantos_kernel_reset(semantos_t *sem);

int semantos_kernel_load_script(semantos_t *sem,
                                const uint8_t *script,
                                uint32_t script_len);

int semantos_kernel_load_unlock(semantos_t *sem,
                                const uint8_t *unlock,
                                uint32_t unlock_len);

// Load a BIP143 transaction context. Required before kernel_execute()
// for any script that uses OP_CHECKSIG / OP_CHECKSIGVERIFY (the engine
// needs the tx data to compute the sighash preimage). `input_value` is
// the value of the UTXO being spent — hashed into the preimage but
// otherwise not enforced.
int semantos_kernel_load_tx_context(semantos_t *sem,
                                     const uint8_t *tx, uint32_t tx_len,
                                     uint32_t input_index,
                                     uint64_t input_value);

int semantos_kernel_execute(semantos_t *sem);

int semantos_kernel_get_type_class(semantos_t *sem);
uint32_t semantos_kernel_get_opcount(semantos_t *sem);
uint32_t semantos_kernel_get_error(semantos_t *sem);
uint32_t semantos_kernel_stack_depth(semantos_t *sem);
uint32_t semantos_kernel_stack_peek(semantos_t *sem, uint32_t index);

#ifdef __cplusplus
}
#endif
