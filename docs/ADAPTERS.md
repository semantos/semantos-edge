# The Four Adapter Patterns

The Semantos cell-engine is a pure interpreter. It does not do I/O, does
not know the time, cannot hit the network, cannot read a sensor, cannot
write to flash. Everything outside the sandbox happens through one of
four **adapter patterns**, each backed by one or two callback function
pointers that you supply at boot.

Every callback is synchronous from the kernel's perspective. Your host
code can internally spin a FreeRTOS task, wait on an event group, or
block on a peripheral — but the callback must return before the kernel
continues. This keeps kernel execution deterministic, which is the
property that lets the project have Lean 4 proofs about it at all.

All callback signatures are in `components/semantos/include/semantos_adapters.h`.

---

## 1. Storage

```c
typedef int32_t (*semantos_storage_read_fn)(
    const char *key, size_t key_len,
    uint8_t *out_buf, size_t *inout_len);

typedef int32_t (*semantos_storage_write_fn)(
    const char *key, size_t key_len,
    const uint8_t *data, size_t data_len);
```

Named key/value storage. Keys are NUL-terminated strings, usually type
hashes or cell IDs. Values are opaque blobs.

**ESP32-friendly bindings:**
- **NVS** for small hot-path values — cert hashes, counters, last-seen
  state hashes.
- **SPIFFS / LittleFS / FAT** for larger blobs (multi-KB cells).
- **PSRAM ring buffer** if you just want an in-memory sandbox.
- **SD card** if you're on a board that has one.

The length-out protocol: on read, pass in the buffer you have and the
size pointer; on success, the host writes bytes and updates
`*inout_len`. If the buffer is too small, set `*inout_len` to the
required size and return `SEMANTOS_ERR_BADARG` (-3).

---

## 2. Identity

```c
typedef int32_t (*semantos_identity_resolve_fn)(
    const uint8_t *cert_id, size_t cert_id_len,
    uint8_t *out_json, size_t *inout_len);

typedef int32_t (*semantos_identity_derive_fn)(
    const char *parent_cert, size_t parent_cert_len,
    const char *resource_id, size_t resource_id_len,
    uint32_t domain_flag,
    uint8_t *out_json, size_t *inout_len);
```

Resolve a certificate by its ID; derive a child certificate from a
parent. Mirrors BRC-42 / BKDS semantics but the kernel treats
certificates as opaque JSON blobs — it doesn't care what crypto you use
under the hood.

**ESP32-friendly bindings:**
- Store a tiny cert root in encrypted NVS.
- Provision a device cert once via BLE or serial at first boot and
  cache it in flash.
- Use the ESP32's built-in eFuse key as the root of a local identity
  tree.
- If your hack is multi-device, designate one ESP32 as the provisioner
  and have the others pull certs from it over ESP-NOW.

The domain flag is a uint32 namespace for "what is this certificate
for" — signing, encryption, messaging, etc. See the main repo's
`domain-flags.ts` for the well-known values.

---

## 3. Anchor

```c
typedef int32_t (*semantos_anchor_submit_fn)(
    const uint8_t *state_hash, size_t state_hash_len,  /* always 32 */
    const char *metadata_json, size_t metadata_len,
    uint8_t *out_proof, size_t *inout_len);
```

Submit a 32-byte state hash somewhere durable and receive a proof back.

"Anchor" is intentionally loose. In the main Semantos system an anchor
is typically a Bitcoin merkle proof, but on an ESP32 it could be any of:

- **HTTP POST** to a gateway service that actually anchors to Bitcoin
  on your behalf.
- **ESP-NOW broadcast** — cheap, but relies on peers receiving and
  retaining the broadcast.
- **LoRa uplink** (LoRaWAN or point-to-point) — low bandwidth but good
  for remote devices.
- **SD card log file** — append-only, timestamped, good for offline
  devices that sync later.
- **BLE advertisement** — a phone app nearby can scoop up anchor
  requests and relay them.

The "proof" you return back into `out_proof` can also be whatever shape
you want; the kernel stores it opaquely and hands it back to scripts
that ask for proof of a given state hash.

---

## 4. Network

```c
typedef int32_t (*semantos_network_publish_fn)(
    const char *object_json, size_t object_len);

typedef int32_t (*semantos_network_resolve_fn)(
    const char *query_json, size_t query_len,
    uint8_t *out_results, size_t *inout_len);
```

Publish a semantic object; query the network for matching objects. The
transport is entirely your choice.

**ESP32-friendly bindings:**
- **MQTT** over Wi-Fi is the obvious one. `esp_mqtt_client_enqueue()`
  for publish, subscribe to a wildcard topic and cache results in an
  in-memory index for resolve.
- **ESP-NOW** for mesh-ish behaviour between meetup members' boards
  without a Wi-Fi AP.
- **mDNS** for resolve-only ("who has a certificate for vendor X?"
  queries).
- **CoAP** if you want something HTTP-ish but frugal.
- **BLE GATT** with a characteristic per object class.

The publish side is fire-and-forget (return 0 on success). The resolve
side follows the same length-out protocol as the read callbacks.

---

## Wiring it up

```c
static const semantos_adapter_table_t my_adapters = {
    .storage_read     = my_nvs_read,
    .storage_write    = my_nvs_write,
    .identity_resolve = my_identity_resolve,
    .identity_derive  = my_identity_derive,
    .anchor_submit    = my_http_anchor,
    .network_publish  = my_mqtt_publish,
    .network_resolve  = my_mqtt_resolve,
};

void app_main(void) {
    semantos_config_t cfg = SEMANTOS_DEFAULT_CONFIG();
    cfg.adapters = &my_adapters;

    semantos_t *sem;
    ESP_ERROR_CHECK(semantos_init(&cfg, &sem));
    // ...
}
```

You can leave any individual callback NULL — calls to a NULL callback
return `SEMANTOS_ERR_DENIED` (-2) without crashing. Use this for
progressive bringup: start with `.storage_read` and `.storage_write`
only, prove it works, then add identity, then anchor, then network.

## Error codes

| Code | Name | Meaning |
| --- | --- | --- |
|  0 | `SEMANTOS_OK` | Success |
| -1 | `SEMANTOS_ERR_UNINIT` | Kernel not initialized |
| -2 | `SEMANTOS_ERR_DENIED` | Adapter absent or refused |
| -3 | `SEMANTOS_ERR_BADARG` | Invalid argument / buffer too small |
| -4 | `SEMANTOS_ERR_BADSTATE` | Kernel in wrong state for this op |
| -99 | `SEMANTOS_ERR_INTERNAL` | Something exploded in the runtime |
