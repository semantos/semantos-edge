# Agent guide for semantos-edge-kit

This repo is an early-access ESP32-C6 edge kit for Semantos. Treat it as a
research preview: useful for experiments, not production firmware.

## First read

Start with these files before editing:

- `README.md` for the kit overview and smoke-test flow.
- `docs/RESEARCH-COLLABORATION.md` for the intended collaboration shape.
- `docs/VM-ENFORCEMENT.md` for what the VM actually accepts/rejects.
- `docs/CLEAVAGE-APPARATUS.md` before claiming the edge kit has the full core
  cleavage workflow.
- `docs/OPCODE-PARITY.md` before touching the embedded WASM.
- `docs/HOST_IMPORTS.md` before changing runtime imports or host calls.
- `docs/ADAPTERS.md` before binding real hardware or storage.
- `docs/ZIG-ROADMAP.md` before changing `components/cell-mesh-zig`.

## Sanity checks

Run the smallest relevant set for your change:

```bash
bun install
bun test
bun run opcode:parity
bun run zig:test
bun run zig:test:c-abi
```

For ESP32-C6 firmware integration:

```bash
cd examples/hello_cell
idf.py set-target esp32c6
idf.py build
```

Only flash hardware when the user explicitly asks.

## Repository map

- `components/semantos`: ESP-IDF component wrapping the embedded cell-engine
  WASM, WAMR runtime, host imports, and public `semantos_*` API.
- `components/semantos/wasm/cell-engine-embedded.wasm`: vendored core engine.
  Do not edit manually. Rebuild from `semantos-core/core/cell-engine` with
  `zig build -Dembedded=true`, copy it here, then run `bun run opcode:parity`.
- `components/cell-mesh`: current C ABI mesh/policy implementation used by
  firmware examples.
- `components/cell-mesh-zig`: Zig implementation of the pure mesh-state core,
  preserving the `cm_*` C ABI.
- `examples/hello_cell`: first hardware smoke test.
- `examples/mesh_demo`: multi-board ESP-NOW mesh demo.
- `tools/mesh-observer`: serial telemetry viewer.
- `tools/x402-bridge`: payment-triggered device actuation tools.

## Good first tasks

- Prove the toolchain: run `bun test`, `bun run opcode:parity`, and build
  `examples/hello_cell` for `esp32c6`.
- Add a small `host_call_by_name` device primitive, such as `led.on`.
- Replace a fail-closed cursor stub with NVS, SPIFFS, LittleFS, SD, or a gateway
  store.
- Extend `components/cell-mesh-zig` while keeping `bun run zig:test:c-abi`
  green.
- Build a gateway benchmark that separates per-device verification from
  broadcaster throughput.

## Important boundaries

- Devices verify and broadcast; they do not hold wallet-tier private keys by
  default.
- `host_sign` is bound but intentionally fail-closed.
- Cursor/cell-store host imports are bound but stubbed until an app wires
  storage.
- Public throughput claims should follow `docs/SMART-CITY-THROUGHPUT.md`.
- The full lockscript cleavage apparatus lives in core / gateway / wallet code
  today; edge has the VM substrate and mesh transport.
- The edge kit contains the embedded runtime and extension surface, not the full
  Semantos core.

## Hardware notes

The expected `hello_cell` success log includes:

```text
semantos: init: loading cell-engine-embedded.wasm (36647 bytes), stack=16384
hello_cell: semantos_init ok
hello_cell: kernel_init rc=0
hello_cell: load_script rc=0
hello_cell: execute rc=0 opcount=3 stack_depth=1 ... err=0x00000000
hello_cell: === hello cell: success ===
```

ESP32-C6 boards often appear as `/dev/cu.usbmodem*` on macOS. If multiple boards
are attached, identify them with:

```bash
esptool.py --chip esp32c6 --port /dev/cu.usbmodemXXXX chip_id
```

## Editing style

- Keep C ABI names stable unless intentionally changing public API.
- Prefer small, testable changes over broad rewrites.
- Document new host imports, adapter hooks, or opcodes in `docs/`.
- Do not make production-security claims from this kit alone.
