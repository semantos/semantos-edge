// runtime_wasm3.c — wasm3-backed runtime for the Semantos cell-engine.
//
// wasm3 is the smaller option: roughly 64KB of code for the interpreter,
// no PSRAM requirement, and it runs happily on the original ESP32 as well
// as ESP32-S2/S3/C3. It's the default runtime choice for the hack-kit.
//
// Each host import declared in packages/cell-engine/src/host.zig is
// bound here via m3_LinkRawFunction. The "host" namespace must match the
// extern "host" declarations in host.zig exactly, or m3_LinkRawFunction
// will fail to find the import and the module will refuse to instantiate.
//
// NOTE: This file is only compiled when CONFIG_SEMANTOS_RUNTIME_WASM3 is
// selected. The wasm3 component (espressif/wasm3) must be added to the
// application's idf_component.yml.

#include "semantos_internal.h"
#include "sdkconfig.h"

#if CONFIG_SEMANTOS_RUNTIME_WASM3

#include "wasm3.h"
#include "m3_env.h"

#include <stdlib.h>
#include <string.h>

struct semantos_runtime_backend {
    IM3Environment env;
    IM3Runtime     runtime;
    IM3Module      module;
    uint32_t       bump_top; /* tiny bump allocator for memcpy_in */
};

// ── Convenience: pull a raw pointer into WASM linear memory out of
//    the current m3 runtime. wasm3 stores it as a private member but
//    exposes m3_GetMemory in newer versions. ──

static uint8_t *wasm3_memory(IM3Runtime rt, uint32_t *out_size) {
    uint32_t mem_size = 0;
    uint8_t *mem = m3_GetMemory(rt, &mem_size, 0);
    if (out_size) *out_size = mem_size;
    return mem;
}

// ── Host import trampolines ──
//
// wasm3's m3ApiRawFunction macro hands us a stack and a memory pointer
// and gives us helpers for reading args and returning values. Each
// trampoline converts between the m3 ABI and the semantos_host_* C
// functions defined elsewhere in the component.

m3ApiRawFunction(trampoline_host_sha256) {
    m3ApiGetArgMem(const uint8_t *, data_ptr);
    m3ApiGetArg   (uint32_t,        data_len);
    m3ApiGetArgMem(uint8_t *,       out_ptr);
    semantos_host_sha256(data_ptr, data_len, out_ptr);
    m3ApiSuccess();
}

m3ApiRawFunction(trampoline_host_hash160) {
    m3ApiGetArgMem(const uint8_t *, data_ptr);
    m3ApiGetArg   (uint32_t,        data_len);
    m3ApiGetArgMem(uint8_t *,       out_ptr);
    semantos_host_hash160(data_ptr, data_len, out_ptr);
    m3ApiSuccess();
}

m3ApiRawFunction(trampoline_host_hash256) {
    m3ApiGetArgMem(const uint8_t *, data_ptr);
    m3ApiGetArg   (uint32_t,        data_len);
    m3ApiGetArgMem(uint8_t *,       out_ptr);
    semantos_host_hash256(data_ptr, data_len, out_ptr);
    m3ApiSuccess();
}

m3ApiRawFunction(trampoline_host_checksig) {
    m3ApiReturnType(uint32_t);
    m3ApiGetArgMem(const uint8_t *, pk_ptr);
    m3ApiGetArg   (uint32_t,        pk_len);
    m3ApiGetArgMem(const uint8_t *, msg_ptr);
    m3ApiGetArg   (uint32_t,        msg_len);
    m3ApiGetArgMem(const uint8_t *, sig_ptr);
    m3ApiGetArg   (uint32_t,        sig_len);
    m3ApiReturn(semantos_host_checksig(pk_ptr, pk_len, msg_ptr, msg_len, sig_ptr, sig_len));
}

m3ApiRawFunction(trampoline_host_checkmultisig) {
    m3ApiReturnType(uint32_t);
    m3ApiGetArgMem(const uint8_t *, pks_ptr);
    m3ApiGetArg   (uint32_t,        pks_count);
    m3ApiGetArgMem(const uint8_t *, sigs_ptr);
    m3ApiGetArg   (uint32_t,        sigs_count);
    m3ApiGetArgMem(const uint8_t *, msg_ptr);
    m3ApiGetArg   (uint32_t,        msg_len);
    m3ApiGetArg   (uint32_t,        threshold);
    m3ApiReturn(semantos_host_checkmultisig(pks_ptr, pks_count, sigs_ptr, sigs_count,
                                            msg_ptr, msg_len, threshold));
}

m3ApiRawFunction(trampoline_host_get_blocktime) {
    m3ApiReturnType(uint32_t);
    m3ApiReturn(semantos_host_get_blocktime());
}

m3ApiRawFunction(trampoline_host_get_sequence) {
    m3ApiReturnType(uint32_t);
    m3ApiReturn(semantos_host_get_sequence());
}

m3ApiRawFunction(trampoline_host_log) {
    m3ApiGetArgMem(const char *, msg_ptr);
    m3ApiGetArg   (uint32_t,     msg_len);
    semantos_host_log(msg_ptr, msg_len);
    m3ApiSuccess();
}

m3ApiRawFunction(trampoline_host_call_by_name) {
    m3ApiReturnType(uint32_t);
    m3ApiGetArgMem(const char *, name_ptr);
    m3ApiGetArg   (uint32_t,     name_len);
    m3ApiReturn(semantos_host_call_by_name(name_ptr, name_len));
}

m3ApiRawFunction(trampoline_host_fetch_cell) {
    m3ApiReturnType(uint32_t);
    m3ApiGetArg   (uint32_t,  octave);
    m3ApiGetArg   (uint32_t,  slot);
    m3ApiGetArg   (uint32_t,  offset);
    m3ApiGetArgMem(uint8_t *, out_ptr);
    m3ApiReturn(semantos_host_fetch_cell((uint8_t)octave, slot, offset, out_ptr));
}

// ── Import table wiring ──

static M3Result link_host_imports(IM3Module mod) {
    M3Result r;
    const char *ns = "host";

#define LINK(name, sig) \
    r = m3_LinkRawFunction(mod, ns, #name, sig, trampoline_##name); \
    if (r && r != m3Err_functionLookupFailed) return r;

    LINK(host_sha256,         "v(*i*)");
    LINK(host_hash160,        "v(*i*)");
    LINK(host_hash256,        "v(*i*)");
    LINK(host_checksig,       "i(*i*i*i)");
    LINK(host_checkmultisig,  "i(*i*i*ii)");
    LINK(host_get_blocktime,  "i()");
    LINK(host_get_sequence,   "i()");
    LINK(host_log,            "v(*i)");
    LINK(host_call_by_name,   "i(*i)");
    LINK(host_fetch_cell,     "i(iii*)");

#undef LINK
    return m3Err_none;
}

// ── Backend interface ──

esp_err_t semantos_runtime_load(semantos_t *sem, const uint8_t *wasm, size_t wasm_len) {
    semantos_runtime_backend_t *bk = calloc(1, sizeof(*bk));
    if (!bk) return ESP_ERR_NO_MEM;

    bk->env = m3_NewEnvironment();
    if (!bk->env) { free(bk); return ESP_ERR_NO_MEM; }

    bk->runtime = m3_NewRuntime(bk->env, sem->wasm_stack_size, NULL);
    if (!bk->runtime) {
        m3_FreeEnvironment(bk->env);
        free(bk);
        return ESP_ERR_NO_MEM;
    }

    M3Result r = m3_ParseModule(bk->env, &bk->module, wasm, wasm_len);
    if (r) {
        ESP_LOGE(SEMANTOS_TAG, "m3_ParseModule: %s", r);
        goto fail;
    }
    r = m3_LoadModule(bk->runtime, bk->module);
    if (r) {
        ESP_LOGE(SEMANTOS_TAG, "m3_LoadModule: %s", r);
        goto fail;
    }
    r = link_host_imports(bk->module);
    if (r) {
        ESP_LOGE(SEMANTOS_TAG, "link_host_imports: %s", r);
        goto fail;
    }

    // Initial bump pointer — we use the tail of linear memory above the
    // kernel's own working area. 256KB offset is comfortably past the
    // kernel's 256KB script stack + scratch area.
    bk->bump_top = 256 * 1024;

    sem->backend = bk;
    return ESP_OK;

fail:
    m3_FreeRuntime(bk->runtime);
    m3_FreeEnvironment(bk->env);
    free(bk);
    return ESP_FAIL;
}

void semantos_runtime_unload(semantos_t *sem) {
    if (!sem || !sem->backend) return;
    m3_FreeRuntime(sem->backend->runtime);
    m3_FreeEnvironment(sem->backend->env);
    free(sem->backend);
    sem->backend = NULL;
}

int semantos_runtime_call(semantos_t *sem, const char *export_name,
                          const uint32_t *argv, size_t argc,
                          uint32_t *result_out) {
    IM3Function fn = NULL;
    M3Result r = m3_FindFunction(&fn, sem->backend->runtime, export_name);
    if (r) {
        ESP_LOGE(SEMANTOS_TAG, "export not found: %s (%s)", export_name, r);
        return -1;
    }

    // Convert u32 argv to wasm3's "array of pointer-to-arg" calling style.
    const void *argptrs[8];
    if (argc > 8) return -1;
    for (size_t i = 0; i < argc; i++) {
        argptrs[i] = &argv[i];
    }

    r = m3_Call(fn, argc, argptrs);
    if (r) {
        ESP_LOGE(SEMANTOS_TAG, "m3_Call(%s): %s", export_name, r);
        return -1;
    }

    if (result_out) {
        uint32_t tmp = 0;
        const void *result_ptrs[1] = { &tmp };
        r = m3_GetResults(fn, 1, result_ptrs);
        if (r) {
            // Function returns void — leave result_out alone.
            *result_out = 0;
        } else {
            *result_out = tmp;
        }
    }
    return 0;
}

uint32_t semantos_runtime_memcpy_in(semantos_t *sem, const void *host_src, size_t len) {
    if (len == 0) return 0;
    uint32_t mem_size = 0;
    uint8_t *mem = wasm3_memory(sem->backend->runtime, &mem_size);
    if (!mem || sem->backend->bump_top + len > mem_size) return 0;
    uint32_t offset = sem->backend->bump_top;
    memcpy(mem + offset, host_src, len);
    sem->backend->bump_top += (len + 15) & ~15u; /* 16-byte align */
    return offset;
}

void semantos_runtime_memfree(semantos_t *sem, uint32_t wasm_ptr, size_t len) {
    // Simple bump allocator — we only free in LIFO order. Good enough for
    // the kernel wrapper's script/unlock load pattern.
    size_t aligned = (len + 15) & ~15u;
    if (sem->backend->bump_top >= wasm_ptr + aligned) {
        sem->backend->bump_top = wasm_ptr;
    }
}

#endif /* CONFIG_SEMANTOS_RUNTIME_WASM3 */
