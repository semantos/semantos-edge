# Host Imports

The cell-engine embedded WASM module declares **ten imports** in the
`"host"` namespace. The hack-kit provides concrete implementations for
all ten — you should not need to touch these unless you want to replace
mbedTLS, add a tighter RTC source, or hook up higher-octave cell
storage.

Source of truth: `packages/cell-engine/src/host.zig` in the main
Semantos repo. If the main-repo list changes and this table drifts,
`host.zig` wins.

## The five crypto imports

All five are backed by mbedTLS in `host_crypto_mbedtls.c`. ESP-IDF ships
mbedTLS so there's no additional dependency to install.

| Symbol | Signature | Implementation |
| --- | --- | --- |
| `host_sha256` | `(data_ptr, data_len, out_ptr)` → `void` | `mbedtls_sha256` |
| `host_hash160` | `(data_ptr, data_len, out_ptr)` → `void` | SHA-256 then RIPEMD-160 |
| `host_hash256` | `(data_ptr, data_len, out_ptr)` → `void` | Double SHA-256 |
| `host_checksig` | `(pk, pk_len, msg, msg_len, sig, sig_len)` → `u32` | `mbedtls_ecdsa_read_signature` over secp256k1 |
| `host_checkmultisig` | `(pks, pks_count, sigs, sigs_count, msg, msg_len, threshold)` → `u32` | Walks keys in order; calls `host_checksig` per sig |

Output sizes:
- `host_sha256` → 32 bytes
- `host_hash160` → 20 bytes (SHA-256 then RIPEMD-160)
- `host_hash256` → 32 bytes (double SHA-256)

### `checksig` notes

The embedded profile of the kernel hands `host_checksig` a pre-hashed
32-byte sighash. If `msg_len` is not 32 we re-hash with SHA-256 as a
fallback. Public keys are parsed with `mbedtls_ecp_point_read_binary`
in SEC format (33 bytes compressed or 65 bytes uncompressed).
Signatures are parsed with `mbedtls_ecdsa_read_signature`, which
expects DER encoding without a trailing sighash type byte (strip it
before calling if you're parsing full Bitcoin sigs).

### `checkmultisig` notes

The packing format of the keys and signatures is
`[len_byte][data...]` repeated. Each sig is matched against successive
keys until one verifies; we fail fast if remaining keys cannot satisfy
the threshold. This follows standard Bitcoin Script multisig semantics.

## The three utility imports

| Symbol | Signature | Implementation |
| --- | --- | --- |
| `host_get_blocktime` | `()` → `u32` | `gettimeofday()` unix epoch, or boot monotonic |
| `host_get_sequence` | `()` → `u32` | Global monotonic counter, increments per call |
| `host_log` | `(msg_ptr, msg_len)` → `void` | `ESP_LOGI` with "wasm:" prefix |

`host_get_blocktime` returns the unix epoch if the system clock has
been set to something reasonable (> Sept 2020). Otherwise it returns
`esp_timer_get_time() / 1_000_000` — monotonic seconds since boot.
Scripts that depend on wall-clock time should call `sntp_start()` or
provision an RTC before first use.

`host_get_sequence` is a process-wide monotonic counter starting at 1.
It resets on reboot. Do not treat it as a nonce for any crypto
purpose.

## The hostcall-by-name import

```c
uint32_t host_call_by_name(const char *name, uint32_t name_len);
```

This is the hook for opening the kernel up to your own device-specific
primitives. Scripts invoke it via the `OP_HOSTCALL` opcode family
(Phase 25.5) with a string name; the host is expected to look up the
name in its own dispatch table and return a result. Unknown names
should return `0xFFFFFFFF`.

The default implementation in `host_utility.c` knows nothing. To add
your own:

```c
uint32_t semantos_host_call_by_name(const char *name, uint32_t name_len) {
    if (name_len == 7 && memcmp(name, "led.on", 7) == 0) {
        gpio_set_level(GPIO_NUM_2, 1);
        return 1;
    }
    if (name_len == 8 && memcmp(name, "led.off", 8) == 0) {
        gpio_set_level(GPIO_NUM_2, 0);
        return 1;
    }
    return 0xFFFFFFFFu;
}
```

Naming convention: `domain.verb` (lowercase, dot-separated). Keep
strings short — every call allocates a slice on the WASM side.

## The octave fetch import

```c
uint32_t host_fetch_cell(uint8_t octave, uint32_t slot, uint32_t offset, uint8_t *out_ptr);
```

The cell-engine has a multi-octave memory model where the WASM module
only ever holds 1 KB "octave-0" cells directly; larger cells live in
host-provided higher octaves, and the kernel calls `host_fetch_cell`
to page in a 1 KB window at `(octave, slot, offset)`.

The hack-kit stubs this out: it always returns 0 (failure). Scripts
that only touch octave-0 cells will work fine. If your hack needs
bigger cells, implement this against SPIFFS, LittleFS, or an SD card.
`out_ptr` is a pointer into WASM linear memory — write exactly 1024
bytes to it on success.

## Why these aren't adapters

The ten host imports are "primitives the kernel cannot live without" —
they're wired at module instantiation time and their signatures are
fixed by the embedded-profile ABI. The four adapter patterns are
"things the kernel delegates to host policy" — they're wired via a
callback table at runtime and their set can grow (the main repo's
Phase 30B adds more callbacks over time).

If you find yourself wanting to add a new host import, stop: it
probably wants to be an adapter, or it wants to be a hostcall-by-name
entry. Host imports are the thinnest possible layer.
