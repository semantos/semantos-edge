# Zig Mesh-Core Architecture

The public kit now uses Zig for the mesh/state brain. ESP-IDF, ESP-NOW, mbedTLS,
and WAMR still expose C-shaped integration points, so the firmware keeps a small
`cm_*` C ABI and a few C glue files. The duplicate C implementation of the pure
mesh modules has been removed.

`components/cell-mesh-zig` exports the same `cm_*` C ABI for the pure mesh
modules. Its C-ABI harness links the existing C tests against the Zig static
library, and `components/cell-mesh/CMakeLists.txt` links that same Zig archive
into ESP-IDF builds for ESP32 RISC-V targets.

```bash
bun run zig:test
bun run zig:test:c-abi
```

## Current Core Status

These modules are implemented in Zig, exported through the `cm_*` ABI, and
covered by the C ABI harness:

- `cell_wire`
- `cell_meter`
- `cell_ring`
- `cell_channel`
- `cell_forward`
- `cell_forward_v1`
- `cell_forward_v2`
- `cell_frame`
- `cell_capability`
- `cell_rules`
- `cell_mnca`

The remaining C files are integration-facing:

- `cell_radio`: ESP-NOW / ESP-IDF transport glue.
- `cell_sig`: mbedTLS secp256k1 wrappers.

Those can stay C-facing until there is a proven reason to wrap the ESP-IDF and
mbedTLS APIs directly from Zig. They are boundary glue, not a second mesh core.

The intended architecture is **Zig mesh logic with a stable C ABI shim**:

```text
ESP-IDF app / examples
        |
        v
stable cm_* C ABI
        |
        v
Zig mesh-core library
        |
        v
cell wire, frames, rules, channels, meters, capabilities
```

## Why Zig

- Fixed-size byte layouts map cleanly to packed structs and slices.
- Bounds-checked parsing is a better default for adversarial radio frames.
- Deterministic state machines stay allocation-light and testable.
- The same language can eventually cover the cell-engine and mesh-core.
- Zig can export C ABI functions, preserving ESP-IDF ergonomics.

## Keep C At The Boundary

These pieces remain C or C-facing because they bind directly into vendor APIs:

- ESP-IDF lifecycle glue.
- ESP-NOW / Wi-Fi callbacks.
- WAMR native-symbol registration.
- mbedTLS host import wrappers.

## Completed Port

1. `cell_wire`: canonical offsets, getters/setters, magic checks. Done.
2. `cell_frame`: fragmentation and reassembly. Done.
3. `cell_ring`: fixed-size recent-cell index. Done.
4. `cell_rules`: hot-swappable rule evaluation. Done.
5. `cell_channel` and `cell_meter`: payment-channel and draining meter state. Done.
6. `cell_capability` and `cell_forward_v1/v2`: capability-gated routing. Done.
7. `cell_mnca`: incentive / settle logic. Done.

The old C implementations for those modules are intentionally not shipped in
this repo. The C tests stay because they prove the exported ABI from firmware's
point of view.

## Target Policy

The first public Zig firmware target is ESP32-C6. The component maps ESP32
RISC-V targets to `riscv32-freestanding-none`; broader ESP32-family support
should not be promised until the Zig toolchain story is reliable for those
chips.
