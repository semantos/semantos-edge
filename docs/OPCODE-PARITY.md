# Opcode parity

The edge kit runs the same embedded cell-engine WASM that Semantos core builds
with `zig build -Dembedded=true`. There is no separate opcode implementation in
the ESP-IDF component; parity means the vendored blob is byte-identical to the
current core embedded build.

Run this before publishing or flashing a parity-sensitive build:

```bash
# in semantos-core/core/cell-engine
zig build -Dembedded=true

# in semantos-edge-kit
bun run opcode:parity
```

The parity check compares
`components/semantos/wasm/cell-engine-embedded.wasm` against
`../semantos-core/core/cell-engine/zig-out/bin/cell-engine-embedded.wasm`.
Set `SEMANTOS_CORE=/path/to/core/cell-engine` or pass
`--core /path/to/core/cell-engine` if your checkout layout differs.

## Bitcoin Script plus Semantos extensions

The embedded engine carries the Bitcoin Script / BSV-restored opcode surface
through `0xAF` (`OP_CHECKMULTISIGVERIFY`), then Semantos extension families
above that range. Reserved/version opcodes fail. This is a
Bitcoin-Script-compatible embedded VM, not a claim of consensus-identical node
behavior.

## Current Semantos extension families

| Range | Family | Implemented opcodes |
| --- | --- | --- |
| `0xB0..0xBF` | Craig macros | `XSWAP-2`, `XSWAP-3`, `XSWAP-4`, `XDROP-2`, `XDROP-3`, `XDROP-4`, `XROT-3`, `XROT-4`, `HASHCAT`; `0xB9..0xBF` reserved |
| `0xC0..0xCF` | Plexus | `OP_CHECKLINEARTYPE`, `OP_CHECKAFFINETYPE`, `OP_CHECKRELEVANTTYPE`, `OP_CHECKCAPABILITY`, `OP_CHECKIDENTITY`, `OP_ASSERTLINEAR`, `OP_CHECKDOMAINFLAG`, `OP_CHECKTYPEHASH`, `OP_DEREF_POINTER`, `OP_READHEADER`, `OP_CELLCREATE`, `OP_DEMOTE`, `OP_READPAYLOAD`, `OP_SIGN`, `OP_DECREMENT_BUDGET`, `OP_REFILL_BUDGET` |
| `0xD0` | Hostcall | `OP_CALLHOST` |
| `0xD1` | Plexus mutation | `OP_WRITEPAYLOAD` |
| `0xE0..0xEF` | Routing | `OP_BRANCHONOUTPUT`; rest reserved |

`OP_BRANCHONOUTPUT` requires the host to set the current output index before
execution. Edge exposes this as:

```c
int semantos_kernel_set_output_index(semantos_t *sem, uint32_t output_index);
```
