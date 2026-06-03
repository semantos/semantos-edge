// semantos_internal.h — implementation-private interface shared across
// the host_*, adapters_*, and runtime_* source files in this component.
//
// Not installed as a public header; do not include from application code.

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "esp_log.h"
#include "semantos.h"
#include "semantos_adapters.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SEMANTOS_TAG "semantos"

// Opaque runtime handle — the concrete type is defined inside the runtime
// backend (runtime_wasm3.c / runtime_wamr.c). Each backend owns whatever
// interpreter state it needs.
typedef struct semantos_runtime_backend semantos_runtime_backend_t;

// Context shared between the public API, the host imports, and the runtime
// backend. The runtime backend stashes a pointer to the live semantos_t
// into whatever per-instance slot its API gives us so that host import
// trampolines can recover it.
struct semantos_ctx {
    semantos_runtime_backend_t *backend;
    const semantos_adapter_table_t *adapters;
    uint32_t wasm_stack_size;
};

// Currently-active context — set for the duration of a kernel call so that
// host import trampolines can find the adapter table without chasing it
// through the runtime's per-instance userdata. Single-threaded assumption:
// one kernel call in flight at a time on a given core. If you want
// multi-core execution, give each core its own semantos_t.
extern _Thread_local semantos_t *semantos_current;

// ── Runtime backend interface ──
// Each backend (wasm3, wamr) implements these. Exactly one backend is
// compiled in based on Kconfig.

esp_err_t semantos_runtime_load(semantos_t *sem,
                                const uint8_t *wasm,
                                size_t wasm_len);

void semantos_runtime_unload(semantos_t *sem);

// Invoke a kernel export by name. Results come back through `result_out`
// (may be NULL if the export returns void). `argv`/`argc` carries u32/i32
// arguments; longer argument types should be passed through shared linear
// memory (use semantos_runtime_memcpy_in / _out).
int semantos_runtime_call(semantos_t *sem,
                          const char *export_name,
                          const uint32_t *argv,
                          size_t argc,
                          uint32_t *result_out);

// Copy a buffer from host memory into the WASM module's linear memory.
// Returns the WASM linear-memory offset (pointer in the module's address
// space) on success, or 0 on failure.
uint32_t semantos_runtime_memcpy_in(semantos_t *sem,
                                    const void *host_src,
                                    size_t len);

// Free a linear-memory buffer previously allocated by memcpy_in.
void semantos_runtime_memfree(semantos_t *sem, uint32_t wasm_ptr, size_t len);

// ── Host import registration — called from the runtime backend at load
//    time to wire all 10 "host" namespace imports. ──

esp_err_t semantos_register_host_imports(semantos_t *sem);

// ── The 10 host imports. Each backend wraps these into whatever the
//    runtime's import-binding ABI expects (IM3Function, NativeSymbol, ...). ──

// Crypto (5)
void     semantos_host_sha256(const uint8_t *data, uint32_t data_len, uint8_t *out32);
void     semantos_host_hash160(const uint8_t *data, uint32_t data_len, uint8_t *out20);
void     semantos_host_hash256(const uint8_t *data, uint32_t data_len, uint8_t *out32);
uint32_t semantos_host_checksig(const uint8_t *pk, uint32_t pk_len,
                                const uint8_t *msg, uint32_t msg_len,
                                const uint8_t *sig, uint32_t sig_len);
uint32_t semantos_host_checkmultisig(const uint8_t *pks, uint32_t pks_count,
                                     const uint8_t *sigs, uint32_t sigs_count,
                                     const uint8_t *msg, uint32_t msg_len,
                                     uint32_t threshold);

// Utility (3)
uint32_t semantos_host_get_blocktime(void);
uint32_t semantos_host_get_sequence(void);
void     semantos_host_log(const char *msg, uint32_t msg_len);

// Phase 25.5: named hostcall dispatch
uint32_t semantos_host_call_by_name(const char *name, uint32_t name_len);

// Phase 6: octave memory fetch
uint32_t semantos_host_fetch_cell(uint8_t octave, uint32_t slot, uint32_t offset, uint8_t *out_ptr);

#ifdef __cplusplus
}
#endif
