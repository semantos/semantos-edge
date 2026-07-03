# Research collaboration brief

`semantos-edge-kit` is the shareable edge/runtime layer of Semantos: an
ESP32-C6-ready kit for verifiable IoT policy, mesh forwarding, metering, and
BSV settlement experiments. It is meant to open collaboration without requiring
the whole Semantos core repository.

## Why a lab might care

Smart-city and smart-factory systems need cheap devices to make local decisions
while still producing an auditable, settleable record. This kit explores that
split:

- ESP32 devices verify policy locally and actuate.
- Wallets and operators sign policies/cells off-device.
- Gateways aggregate device evidence and broadcast settlement/audit records.
- The chain is the durable public record, not the microcontroller's workload.

The current research question is not "can one MCU do 60k TPS?" It cannot, and
should not. The better question is: what edge/gateway architecture lets many
cheap devices enforce policy locally while horizontally scaled broadcasters
handle smart-city-scale settlement?

## What is included

- An ESP-IDF `semantos` component with the embedded cell-engine WASM blob.
- A Bitcoin Script-compatible VM surface: original / BSV-restored script
  opcodes plus Semantos linear-type, capability, hostcall, and routing
  extensions.
- Opcode parity guard: `bun run opcode:parity` checks the edge blob against the
  current core embedded build.
- ESP32-C6 examples:
  - `hello_cell`: smallest proof that the VM loads and executes.
  - `mesh_demo`: multi-board ESP-NOW telemetry, forwarding, signed rule cells.
  - `cold_chain`: custody-style sensor cell flow.
- Host tools:
  - `mesh-observer`: serial telemetry dashboard.
  - `x402-bridge`: payment-triggered device actuation flow.
  - `sign-cell-deck.ts`: pre-signs cells so devices verify/broadcast rather
    than holding wallet keys.
- A Zig implementation of the pure mesh-state core behind the existing C ABI.

## Useful first experiments

1. **Two-board C6 smoke test**
   Flash `examples/hello_cell` or `examples/mesh_demo` to two ESP32-C6 boards,
   then capture serial logs and mesh telemetry.

2. **Factory-cell policy experiment**
   Model a simple machine policy: "operator certificate + paid meter budget +
   current cell type permits actuation." Implement the hardware effect through
   `host_call_by_name` or an adapter.

3. **Smart-city gateway experiment**
   Treat ESP32 devices as local verifiers. Use a laptop or gateway to aggregate
   signed cells and measure batching / broadcaster throughput separately from
   per-device verification.

4. **Storage/cursor extension**
   Replace the fail-closed cursor stubs with NVS, SPIFFS, LittleFS, SD card, or
   a gateway-backed cell store. This is a good academic systems contribution:
   memory-bounded streaming over a constrained runtime.

5. **Zig mesh-core extension**
   Extend `components/cell-mesh-zig` while preserving the `cm_*` C ABI and
   running `bun run zig:test:c-abi`.

## Using an AI coding agent

The repo includes `AGENTS.md` and `docs/AI-PAIRING.md` so collaborators can use
a coding agent without needing a long private walkthrough. A good first prompt
is:

```text
Read AGENTS.md and docs/AI-PAIRING.md, then run the Semantos edge sanity checks.
Explain the safe extension points before editing anything.
```

## Good collaboration questions

- What is the real per-device event rate in a smart-city deployment?
- Which events require immediate local actuation, and which only need audit?
- What belongs on the MCU, gateway, broadcaster, or chain?
- How should cell stores be indexed for city/factory workloads?
- What is the smallest useful policy language for facilities engineers?
- What benchmark would make a 60k TPS smart-city claim scientifically honest?

## Current boundaries

This is a research-preview kit, not a production product.

- Devices verify and broadcast; they do not hold wallet-tier private keys by
  default.
- `host_sign` is bound but fail-closed.
- Cursor/cell-store host imports are bound but stubbed until an app wires
  storage.
- The edge kit includes the embedded runtime and extension surface, not the
  whole Semantos core.
- Public throughput claims should use the language in
  `docs/SMART-CITY-THROUGHPUT.md`.

## Suggested first week

```bash
bun install
bun test
bun run opcode:parity
bun run zig:test
bun run zig:test:c-abi

cd examples/hello_cell
idf.py set-target esp32c6
idf.py build flash monitor
```

Then pick one concrete lab problem: a gateway benchmark, a factory-metering
policy, or a constrained cell-store implementation.
