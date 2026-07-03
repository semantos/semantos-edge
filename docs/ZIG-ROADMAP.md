# Zig Mesh-Core Roadmap

The public kit currently ships `components/cell-mesh` as C because ESP-IDF,
ESP-NOW, mbedTLS, and WAMR all expose C-shaped integration points. That was the
fastest path to running hardware demos.

`components/cell-mesh-zig` is the seed port. It exports the same `cm_*` C ABI
for the pure mesh modules already ported, and its C-ABI harness links the
existing C tests against the Zig static library. It is not wired into the
ESP-IDF firmware build yet.

```bash
bun run zig:test
bun run zig:test:c-abi
```

## Current Port Status

These modules already have Zig implementations with existing C tests passing
against `libcell_mesh_zig.a`:

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

The remaining C modules are integration-facing:

- `cell_radio`: ESP-NOW / ESP-IDF transport glue.
- `cell_sig`: mbedTLS secp256k1 wrappers.

Those should stay C-facing until the Zig ESP-IDF and crypto integration story is
proven on ESP32-C6 hardware.

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

## Keep C For Now

These pieces should remain C or C-facing until there is a proven Zig build for
the target board:

- ESP-IDF lifecycle glue.
- ESP-NOW / Wi-Fi callbacks.
- WAMR native-symbol registration.
- mbedTLS host import wrappers.

## Port Order

1. `cell_wire`: canonical offsets, getters/setters, magic checks. Done.
2. `cell_frame`: fragmentation and reassembly. Done.
3. `cell_ring`: fixed-size recent-cell index. Done.
4. `cell_rules`: hot-swappable rule evaluation. Done.
5. `cell_channel` and `cell_meter`: payment-channel and draining meter state. Done.
6. `cell_capability` and `cell_forward_v1/v2`: capability-gated routing. Done.
7. `cell_mnca`: incentive / settle logic. Done.

Each step should keep the existing `cm_*` ABI and pass the existing C tests
byte-for-byte before the C implementation is deleted.

## Target Policy

The first public Zig target is ESP32-C6. Broader ESP32-family support should not
be promised until the Zig toolchain story is reliable for those chips.
