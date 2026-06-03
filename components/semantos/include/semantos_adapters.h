// semantos_adapters.h — the four adapter patterns the Semantos kernel uses
// to reach out of its sandbox and touch the real world.
//
// The kernel itself is pure: no I/O, no time, no async, nothing that could
// make a formal proof cry. Every interaction with the outside world goes
// through one of these four adapter interfaces, which you implement and
// register via semantos_init().
//
// From the kernel's perspective every call is synchronous — it blocks on
// the callback return. The host can do whatever it wants internally (spin
// a task, wait on an event group, hit a hardware peripheral) as long as it
// eventually returns.
//
//   1. Storage   — read/write named blobs (NVS, SPIFFS, FATFS, flash, ...)
//   2. Identity  — resolve and derive certificates (BRC-42/BKDS-ish)
//   3. Anchor    — submit a state hash somewhere durable (HTTP, BLE, LoRa)
//   4. Network   — publish / query semantic objects (MQTT, ESP-NOW, IP, ...)
//
// Each callback returns 0 on success or a negative SEMANTOS_ERR_* code on
// failure. Callbacks that return data follow a "host-fills-caller-buffer"
// protocol: the kernel passes in a buffer and a pointer to its length; on
// success the host writes the payload and updates *inout_len to the number
// of bytes written. If the buffer is too small, set *inout_len to the
// required size and return SEMANTOS_ERR_BADARG.

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── 1. Storage adapter ──────────────────────────────────────────────────

// Read a named blob. `key` is a NUL-terminated string (usually a type hash
// or cell ID). On success, write value bytes into `out_buf` and set
// `*inout_len` to the number of bytes written.
typedef int32_t (*semantos_storage_read_fn)(
    const char  *key,
    size_t       key_len,
    uint8_t     *out_buf,
    size_t      *inout_len
);

// Persist a named blob. The kernel owns `key` and `data` only for the
// duration of the call; the adapter must copy anything it wants to keep.
typedef int32_t (*semantos_storage_write_fn)(
    const char    *key,
    size_t         key_len,
    const uint8_t *data,
    size_t         data_len
);

// ── 2. Identity adapter ─────────────────────────────────────────────────

// Resolve a certificate by its identifier and return the certificate as
// JSON (or whatever serialization your host convention uses — the kernel
// treats this as an opaque byte blob).
typedef int32_t (*semantos_identity_resolve_fn)(
    const uint8_t *cert_id,
    size_t         cert_id_len,
    uint8_t       *out_json,
    size_t        *inout_len
);

// Derive a new child certificate from a parent certificate under a given
// resource ID and functional domain flag. Mirrors BRC-42 key-derivation
// semantics but the kernel doesn't care what crypto you use under the hood.
typedef int32_t (*semantos_identity_derive_fn)(
    const char    *parent_cert,
    size_t         parent_cert_len,
    const char    *resource_id,
    size_t         resource_id_len,
    uint32_t       domain_flag,
    uint8_t       *out_json,
    size_t        *inout_len
);

// ── 3. Anchor adapter ───────────────────────────────────────────────────

// Submit a 32-byte state hash for anchoring and receive a proof back. The
// definition of "anchor" is intentionally loose: it could be a Bitcoin
// merkle proof via HTTP, an ESP-NOW broadcast, a signed receipt from a
// gateway, or a LoRaWAN uplink — whatever makes sense for your device.
typedef int32_t (*semantos_anchor_submit_fn)(
    const uint8_t *state_hash,
    size_t         state_hash_len,  /* always 32 */
    const char    *metadata_json,
    size_t         metadata_len,
    uint8_t       *out_proof,
    size_t        *inout_len
);

// ── 4. Network adapter ──────────────────────────────────────────────────

// Publish a semantic object to the network. The kernel does not specify
// transport — MQTT, HTTP, BLE advertisement, whatever. Return 0 on
// acknowledged publish, negative on failure.
typedef int32_t (*semantos_network_publish_fn)(
    const char *object_json,
    size_t      object_len
);

// Resolve / query the network for matching objects. The query shape is a
// JSON blob; results are written back into `out_results` as a JSON array.
typedef int32_t (*semantos_network_resolve_fn)(
    const char *query_json,
    size_t      query_len,
    uint8_t    *out_results,
    size_t     *inout_len
);

// ── Adapter table ───────────────────────────────────────────────────────

typedef struct {
    // Storage
    semantos_storage_read_fn      storage_read;
    semantos_storage_write_fn     storage_write;

    // Identity
    semantos_identity_resolve_fn  identity_resolve;
    semantos_identity_derive_fn   identity_derive;

    // Anchor
    semantos_anchor_submit_fn     anchor_submit;

    // Network
    semantos_network_publish_fn   network_publish;
    semantos_network_resolve_fn   network_resolve;
} semantos_adapter_table_t;

// Pre-built no-op table — every callback returns SEMANTOS_ERR_DENIED (-2).
// Use this to prove your wasm loads and runs before wiring real I/O.
extern const semantos_adapter_table_t semantos_adapters_noop;

#ifdef __cplusplus
}
#endif
