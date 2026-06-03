// runtime_wamr.c — WAMR (WebAssembly Micro Runtime) backend for the
// Semantos cell-engine.
//
// WAMR is the fatter, faster option. It supports both a classic
// interpreter and an AOT mode; for a 29KB module on ESP32 the classic
// interpreter is plenty. WAMR wants more RAM than wasm3, so we recommend
// ESP32-S3 with PSRAM for this backend.
//
// Each host import declared in packages/cell-engine/src/host.zig is
// bound here as a NativeSymbol in the "host" module namespace. The
// signature strings follow WAMR's convention: "(ii*)i" means
// (i32, i32, pointer)->i32, etc.
//
// NOTE: This file is only compiled when CONFIG_SEMANTOS_RUNTIME_WAMR is
// selected. The wamr component (espressif/wamr) must be added to the
// application's idf_component.yml.

#include "semantos_internal.h"
#include "sdkconfig.h"

#if CONFIG_SEMANTOS_RUNTIME_WAMR

#include "wasm_export.h"
#include "esp_heap_caps.h"

#include <stdlib.h>
#include <string.h>

// NOTE on allocator choice (2026-05, ESP32-C6 / IDF 5.3 / WAMR 2.4.0):
// Three paths were tried and each hit a distinct wall:
//   1. Alloc_With_System_Allocator     → crashes in wasm_runtime_free
//   2. Alloc_With_Allocator (heap_caps)→ pthread_self assertion in WAMR PAL
//   3. Alloc_With_Pool                 → instantiate fails "allocate
//                                        linear memory failed" even with
//                                        sufficient pool headroom
// Pool mode is the closest-to-working path (gets past load, fails at
// instantiate). The pool's internal block-size or alignment constraints
// appear to refuse the linear-memory allocation — needs deeper WAMR
// source dive to resolve. See memory `wamr_esp32c6_integration_wall`.

struct semantos_runtime_backend {
    wasm_module_t          module;
    wasm_module_inst_t     instance;
    wasm_exec_env_t        exec_env;
    uint32_t               bump_top;
    // WAMR's wasm_runtime_load mutates its input buffer (resolves imports,
    // patches sections in place) and keeps a reference to it for the
    // lifetime of the module. The hackkit embeds the WASM via EMBED_FILES
    // which lives in flash (XIP, read-only on ESP32-C6 and friends). We
    // copy the bytes into a RAM buffer here, owned by the backend, freed
    // on unload.
    uint8_t               *wasm_ram_copy;
};

static bool wamr_runtime_ready = false;

// ── Host import trampolines ──
//
// WAMR native-symbol signatures:
//   i — i32
//   I — i64
//   f — f32
//   F — f64
//   $ — null-terminated string (host pointer)
//   * — pointer to raw memory (length is next arg, passed as a size_t)
//   ~ — used with * to mark the paired length arg
//
// The Semantos host ABI passes all buffers as (ptr, len) pairs, so we use
// the "*~" pattern to get WAMR to auto-translate.

static void trampoline_host_sha256(wasm_exec_env_t env,
                                   const uint8_t *data, uint32_t data_len,
                                   uint8_t *out) {
    (void)env;
    semantos_host_sha256(data, data_len, out);
}

static void trampoline_host_hash160(wasm_exec_env_t env,
                                    const uint8_t *data, uint32_t data_len,
                                    uint8_t *out) {
    (void)env;
    semantos_host_hash160(data, data_len, out);
}

static void trampoline_host_hash256(wasm_exec_env_t env,
                                    const uint8_t *data, uint32_t data_len,
                                    uint8_t *out) {
    (void)env;
    semantos_host_hash256(data, data_len, out);
}

static uint32_t trampoline_host_checksig(wasm_exec_env_t env,
                                         const uint8_t *pk,  uint32_t pk_len,
                                         const uint8_t *msg, uint32_t msg_len,
                                         const uint8_t *sig, uint32_t sig_len) {
    (void)env;
    return semantos_host_checksig(pk, pk_len, msg, msg_len, sig, sig_len);
}

static uint32_t trampoline_host_checkmultisig(wasm_exec_env_t env,
                                              const uint8_t *pks,  uint32_t pks_count,
                                              const uint8_t *sigs, uint32_t sigs_count,
                                              const uint8_t *msg,  uint32_t msg_len,
                                              uint32_t threshold) {
    (void)env;
    return semantos_host_checkmultisig(pks, pks_count, sigs, sigs_count,
                                       msg, msg_len, threshold);
}

static uint32_t trampoline_host_get_blocktime(wasm_exec_env_t env) {
    (void)env;
    return semantos_host_get_blocktime();
}

static uint32_t trampoline_host_get_sequence(wasm_exec_env_t env) {
    (void)env;
    return semantos_host_get_sequence();
}

static void trampoline_host_log(wasm_exec_env_t env,
                                const char *msg, uint32_t msg_len) {
    (void)env;
    semantos_host_log(msg, msg_len);
}

static uint32_t trampoline_host_call_by_name(wasm_exec_env_t env,
                                             const char *name, uint32_t name_len) {
    (void)env;
    return semantos_host_call_by_name(name, name_len);
}

static uint32_t trampoline_host_fetch_cell(wasm_exec_env_t env,
                                           uint32_t octave, uint32_t slot,
                                           uint32_t offset, uint8_t *out) {
    (void)env;
    return semantos_host_fetch_cell((uint8_t)octave, slot, offset, out);
}

static NativeSymbol g_host_native_symbols[] = {
    { "host_sha256",        trampoline_host_sha256,        "(*~*)",   NULL },
    { "host_hash160",       trampoline_host_hash160,       "(*~*)",   NULL },
    { "host_hash256",       trampoline_host_hash256,       "(*~*)",   NULL },
    { "host_checksig",      trampoline_host_checksig,      "(*~*~*~)i", NULL },
    { "host_checkmultisig", trampoline_host_checkmultisig, "(*~*~*~i)i", NULL },
    { "host_get_blocktime", trampoline_host_get_blocktime, "()i",     NULL },
    { "host_get_sequence",  trampoline_host_get_sequence,  "()i",     NULL },
    { "host_log",           trampoline_host_log,           "(*~)",    NULL },
    { "host_call_by_name",  trampoline_host_call_by_name,  "(*~)i",   NULL },
    { "host_fetch_cell",    trampoline_host_fetch_cell,    "(iii*)i", NULL },
};

// ── Backend interface ──

// WAMR-on-ESP-IDF wants a dedicated memory pool for its internal allocator;
// the system-allocator path is flaky on FreeRTOS heap and crashes inside
// wasm_runtime_free during module load (observed on ESP32-C6 2026-05).
//
// Pool sizing — IMPORTANT MCU DETAIL:
// On ESP-IDF, linear memory does NOT come from the WAMR pool. WAMR routes
// linear-memory allocations through os_mmap → heap_caps_malloc directly
// (see espidf_memmap.c). So the pool only needs to hold WAMR's internal
// structures: parsed AST, exports table, native bindings, the WASM module
// byte copy. ~96KB is plenty for our 36KB cell-engine-embedded blob.
//
// CRITICAL: making the pool TOO BIG starves the heap of contiguous space
// for the linear-memory mmap. With a 256KB pool, the linear-memory mmap
// of 128KB fails despite total free heap > 200KB, because the pool took
// the biggest contiguous chunk first. Sizing it tight is the correct move.
//
// We malloc the pool from the FreeRTOS heap rather than declaring it as a
// static array — putting it in `.bss` would blow the linker's sram_seg
// budget. Heap allocation comes from the larger dynamic region.
//
// Tuned 2026-05-21 in the mesh_demo bring-up: 128 KB pool + 128 KB
// linear memory + a pthread stack starved the heap of a contiguous
// 128 KB block ("allocate linear memory failed"). 80 KB leaves enough
// runway; the 36 KB embedded blob's internal needs sit well under that.
#define WAMR_HEAP_POOL_BYTES (128 * 1024)
static uint8_t *g_wamr_heap_pool = NULL;

esp_err_t semantos_runtime_load(semantos_t *sem, const uint8_t *wasm, size_t wasm_len) {
    if (!wamr_runtime_ready) {
        // Alloc_With_Pool is the only allocator path that avoided the
        // pthread_self() assertion failure on ESP32-C6 (the system and
        // custom-callback paths both trip it during wasm_runtime_full_init).
        if (!g_wamr_heap_pool) {
            g_wamr_heap_pool = heap_caps_malloc(WAMR_HEAP_POOL_BYTES,
                                                MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
            if (!g_wamr_heap_pool) {
                ESP_LOGE(SEMANTOS_TAG, "wamr pool malloc(%d) failed", WAMR_HEAP_POOL_BYTES);
                return ESP_ERR_NO_MEM;
            }
        }
        RuntimeInitArgs init_args = {0};
        init_args.mem_alloc_type = Alloc_With_Pool;
        init_args.mem_alloc_option.pool.heap_buf  = g_wamr_heap_pool;
        init_args.mem_alloc_option.pool.heap_size = WAMR_HEAP_POOL_BYTES;
        if (!wasm_runtime_full_init(&init_args)) {
            ESP_LOGE(SEMANTOS_TAG, "wasm_runtime_full_init failed");
            return ESP_FAIL;
        }
        if (!wasm_runtime_register_natives("host",
                                           g_host_native_symbols,
                                           sizeof(g_host_native_symbols)/sizeof(NativeSymbol))) {
            ESP_LOGE(SEMANTOS_TAG, "register_natives failed");
            wasm_runtime_destroy();
            return ESP_FAIL;
        }
        wamr_runtime_ready = true;
    }

    semantos_runtime_backend_t *bk = calloc(1, sizeof(*bk));
    if (!bk) return ESP_ERR_NO_MEM;

    // Copy the WASM blob from flash (EMBED_FILES is XIP / read-only) into
    // a RAM buffer that WAMR can patch in place.
    bk->wasm_ram_copy = malloc(wasm_len);
    if (!bk->wasm_ram_copy) {
        free(bk);
        return ESP_ERR_NO_MEM;
    }
    memcpy(bk->wasm_ram_copy, wasm, wasm_len);

    char err_buf[96] = {0};
    bk->module = wasm_runtime_load(bk->wasm_ram_copy, wasm_len, err_buf, sizeof(err_buf));
    if (!bk->module) {
        ESP_LOGE(SEMANTOS_TAG, "wasm_runtime_load: %s", err_buf);
        free(bk->wasm_ram_copy);
        free(bk);
        return ESP_FAIL;
    }

    // Heap size = WASM module's internal heap (appended to the linear-
    // memory mmap). semantos.c uses wasm_runtime_module_malloc to copy
    // host-side script + unlock buffers into the WASM linear memory
    // before invoking exports; that requires a non-zero module heap.
    // 4 KB is comfortable for our small (≤256 B) scripted-cell payloads
    // and keeps the linear-memory mmap to 64 KB + 4 KB = ~68 KB, which
    // fits the largest free block after the WAMR pool's slice.
    bk->instance = wasm_runtime_instantiate(
        bk->module,
        sem->wasm_stack_size,  /* stack size */
        4 * 1024,              /* heap size — module_malloc backing */
        err_buf, sizeof(err_buf));
    if (!bk->instance) {
        ESP_LOGE(SEMANTOS_TAG, "wasm_runtime_instantiate: %s", err_buf);
        wasm_runtime_unload(bk->module);
        free(bk->wasm_ram_copy);
        free(bk);
        return ESP_FAIL;
    }

    bk->exec_env = wasm_runtime_create_exec_env(bk->instance, sem->wasm_stack_size);
    if (!bk->exec_env) {
        wasm_runtime_deinstantiate(bk->instance);
        wasm_runtime_unload(bk->module);
        free(bk->wasm_ram_copy);
        free(bk);
        return ESP_FAIL;
    }

    sem->backend = bk;
    return ESP_OK;
}

void semantos_runtime_unload(semantos_t *sem) {
    if (!sem || !sem->backend) return;
    wasm_runtime_destroy_exec_env(sem->backend->exec_env);
    wasm_runtime_deinstantiate(sem->backend->instance);
    wasm_runtime_unload(sem->backend->module);
    free(sem->backend->wasm_ram_copy);
    free(sem->backend);
    sem->backend = NULL;
}

int semantos_runtime_call(semantos_t *sem, const char *export_name,
                          const uint32_t *argv, size_t argc,
                          uint32_t *result_out) {
    wasm_function_inst_t fn = wasm_runtime_lookup_function(sem->backend->instance, export_name);
    if (!fn) {
        ESP_LOGE(SEMANTOS_TAG, "export not found: %s", export_name);
        return -1;
    }

    uint32_t argv_copy[8];
    if (argc > 8) return -1;
    for (size_t i = 0; i < argc; i++) argv_copy[i] = argv[i];

    if (!wasm_runtime_call_wasm(sem->backend->exec_env, fn,
                                (uint32_t)argc, argv_copy)) {
        ESP_LOGE(SEMANTOS_TAG, "call_wasm(%s): %s",
                 export_name, wasm_runtime_get_exception(sem->backend->instance));
        return -1;
    }

    if (result_out) *result_out = argv_copy[0];
    return 0;
}

uint32_t semantos_runtime_memcpy_in(semantos_t *sem, const void *host_src, size_t len) {
    if (len == 0) return 0;
    // WAMR's module_malloc returns a WASM-side offset and gives us a
    // host pointer to write into. Much nicer than a manual bump alloc.
    void *host_dst = NULL;
    uint32_t wasm_offset = wasm_runtime_module_malloc(sem->backend->instance, len, &host_dst);
    if (wasm_offset == 0 || !host_dst) return 0;
    memcpy(host_dst, host_src, len);
    return wasm_offset;
}

void semantos_runtime_memfree(semantos_t *sem, uint32_t wasm_ptr, size_t len) {
    (void)len;
    if (wasm_ptr != 0) {
        wasm_runtime_module_free(sem->backend->instance, wasm_ptr);
    }
}

#endif /* CONFIG_SEMANTOS_RUNTIME_WAMR */
