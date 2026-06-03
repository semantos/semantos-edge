// semantos.c — top-level lifecycle: load the embedded WASM blob, bring up
// the runtime backend, register host imports, and expose thin wrappers
// around the kernel_* exports declared in the cell-engine WASM module.

#include "semantos_internal.h"
#include "sdkconfig.h"

#include "esp_log.h"
#include "esp_err.h"

#include <stdlib.h>
#include <string.h>

_Thread_local semantos_t *semantos_current = NULL;

// The WASM blob is linked into flash via EMBED_FILES in CMakeLists.txt.
// ESP-IDF generates these symbols automatically.
extern const uint8_t wasm_blob_start[] asm("_binary_cell_engine_embedded_wasm_start");
extern const uint8_t wasm_blob_end[]   asm("_binary_cell_engine_embedded_wasm_end");

esp_err_t semantos_init(const semantos_config_t *cfg, semantos_t **out) {
    if (!out) return ESP_ERR_INVALID_ARG;

    semantos_t *sem = calloc(1, sizeof(*sem));
    if (!sem) return ESP_ERR_NO_MEM;

    sem->wasm_stack_size = (cfg && cfg->wasm_stack_size)
        ? cfg->wasm_stack_size
        : CONFIG_SEMANTOS_WASM_STACK_SIZE;

    sem->adapters = (cfg && cfg->adapters)
        ? cfg->adapters
        : &semantos_adapters_noop;

    const size_t wasm_len = (size_t)(wasm_blob_end - wasm_blob_start);
    ESP_LOGI(SEMANTOS_TAG,
             "init: loading cell-engine-embedded.wasm (%u bytes), stack=%u",
             (unsigned)wasm_len, (unsigned)sem->wasm_stack_size);

    esp_err_t err = semantos_runtime_load(sem, wasm_blob_start, wasm_len);
    if (err != ESP_OK) {
        ESP_LOGE(SEMANTOS_TAG, "runtime_load failed: %s", esp_err_to_name(err));
        free(sem);
        return err;
    }

    err = semantos_register_host_imports(sem);
    if (err != ESP_OK) {
        ESP_LOGE(SEMANTOS_TAG, "host import registration failed");
        semantos_runtime_unload(sem);
        free(sem);
        return err;
    }

    *out = sem;
    return ESP_OK;
}

void semantos_destroy(semantos_t *sem) {
    if (!sem) return;
    semantos_runtime_unload(sem);
    free(sem);
}

// ── Small helper: push/pop current-context so host import trampolines
//    can find the active adapter table. ──
static inline void enter(semantos_t *sem) { semantos_current = sem; }
static inline void leave(void)            { semantos_current = NULL; }

// ── Kernel export wrappers ─────────────────────────────────────────────

static int call_i32(semantos_t *sem, const char *name,
                    const uint32_t *argv, size_t argc) {
    enter(sem);
    uint32_t result = 0;
    int rc = semantos_runtime_call(sem, name, argv, argc, &result);
    leave();
    if (rc != 0) return SEMANTOS_ERR_INTERNAL;
    return (int32_t)result;
}

static uint32_t call_u32(semantos_t *sem, const char *name,
                         const uint32_t *argv, size_t argc) {
    enter(sem);
    uint32_t result = 0;
    int rc = semantos_runtime_call(sem, name, argv, argc, &result);
    leave();
    if (rc != 0) return 0;
    return result;
}

static void call_void(semantos_t *sem, const char *name,
                      const uint32_t *argv, size_t argc) {
    enter(sem);
    (void)semantos_runtime_call(sem, name, argv, argc, NULL);
    leave();
}

int semantos_kernel_init(semantos_t *sem) {
    return call_i32(sem, "kernel_init", NULL, 0);
}

void semantos_kernel_reset(semantos_t *sem) {
    call_void(sem, "kernel_reset", NULL, 0);
}

int semantos_kernel_load_script(semantos_t *sem,
                                const uint8_t *script,
                                uint32_t script_len) {
    uint32_t wasm_ptr = semantos_runtime_memcpy_in(sem, script, script_len);
    if (wasm_ptr == 0 && script_len > 0) return SEMANTOS_ERR_INTERNAL;
    uint32_t argv[2] = { wasm_ptr, script_len };
    int rc = call_i32(sem, "kernel_load_script", argv, 2);
    semantos_runtime_memfree(sem, wasm_ptr, script_len);
    return rc;
}

int semantos_kernel_load_unlock(semantos_t *sem,
                                const uint8_t *unlock,
                                uint32_t unlock_len) {
    uint32_t wasm_ptr = semantos_runtime_memcpy_in(sem, unlock, unlock_len);
    if (wasm_ptr == 0 && unlock_len > 0) return SEMANTOS_ERR_INTERNAL;
    uint32_t argv[2] = { wasm_ptr, unlock_len };
    int rc = call_i32(sem, "kernel_load_unlock", argv, 2);
    semantos_runtime_memfree(sem, wasm_ptr, unlock_len);
    return rc;
}

// Load a BIP143 transaction context — required by OP_CHECKSIG /
// OP_CHECKSIGVERIFY before kernel_execute. `tx` is the raw serialized
// BSV transaction (minimal: version + inputs + outputs + locktime).
// `input_value` is BIP143's "value of output being spent" — hashed into
// the sighash preimage; doesn't need to match real chain economics.
int semantos_kernel_load_tx_context(semantos_t *sem,
                                     const uint8_t *tx, uint32_t tx_len,
                                     uint32_t input_index,
                                     uint64_t input_value) {
    uint32_t wasm_ptr = semantos_runtime_memcpy_in(sem, tx, tx_len);
    if (wasm_ptr == 0 && tx_len > 0) return SEMANTOS_ERR_INTERNAL;
    // wasm signature: (i32 ptr, i32 len, i32 input_index, i64 input_value) → i32
    // WAMR's call_wasm marshalls i64 as two consecutive i32 slots (lo, hi).
    uint32_t argv[5] = {
        wasm_ptr, tx_len, input_index,
        (uint32_t)(input_value & 0xffffffffu),
        (uint32_t)((input_value >> 32) & 0xffffffffu),
    };
    int rc = call_i32(sem, "kernel_load_tx_context", argv, 5);
    semantos_runtime_memfree(sem, wasm_ptr, tx_len);
    return rc;
}

int semantos_kernel_execute(semantos_t *sem) {
    return call_i32(sem, "kernel_execute", NULL, 0);
}

int semantos_kernel_get_type_class(semantos_t *sem) {
    return call_i32(sem, "kernel_get_type_class", NULL, 0);
}

uint32_t semantos_kernel_get_opcount(semantos_t *sem) {
    return call_u32(sem, "kernel_get_opcount", NULL, 0);
}

uint32_t semantos_kernel_get_error(semantos_t *sem) {
    return call_u32(sem, "kernel_get_error", NULL, 0);
}

uint32_t semantos_kernel_stack_depth(semantos_t *sem) {
    return call_u32(sem, "kernel_stack_depth", NULL, 0);
}

uint32_t semantos_kernel_stack_peek(semantos_t *sem, uint32_t index) {
    uint32_t argv[1] = { index };
    return call_u32(sem, "kernel_stack_peek", argv, 1);
}

// ── Host import registration plumbing ──
//
// The concrete binding lives in each runtime backend. This function exists
// so the top-level init path doesn't have to #ifdef on runtime choice.

esp_err_t semantos_register_host_imports(semantos_t *sem) {
    (void)sem;
    // Each backend's runtime_load() registers imports inline at module
    // instantiation time, because both wasm3 and WAMR require imports to
    // be bound before instantiate succeeds. This function is a no-op hook
    // left in place so applications can do additional registration later
    // if they want.
    return ESP_OK;
}
