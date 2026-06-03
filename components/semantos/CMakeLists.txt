# Semantos cell-engine (embedded profile) — ESP-IDF component
#
# Embeds the 29KB cell-engine-embedded.wasm blob as a binary asset and builds
# the host-side glue: crypto imports backed by mbedTLS, utility imports, four
# adapter no-op stubs, and the WAMR runtime backend.
#
# The original kit supported wasm3 and WAMR via a Kconfig choice. wasm3 is
# no longer in the Espressif component registry (as of 2026-05), so the
# build is now hard-wired to WAMR. runtime_wasm3.c is left in src/ for
# reference but is not compiled.

set(SEMANTOS_SRCS
    "src/semantos.c"
    "src/host_crypto_mbedtls.c"
    "src/host_utility.c"
    "src/adapters_noop.c"
    "src/runtime_wamr.c"
)

idf_component_register(
    SRCS ${SEMANTOS_SRCS}
    INCLUDE_DIRS "include"
    EMBED_FILES "wasm/cell-engine-embedded.wasm"
    REQUIRES mbedtls wasm-micro-runtime
)
