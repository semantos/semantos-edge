# semantos-edge-kit

**A Bitcoin-Script virtual machine, small enough to run on a microcontroller,
networked into a self-organizing mesh.**

`semantos-edge-kit` is the IoT / edge distribution of the Semantos cell-engine: a
**36 KB** dual-stack pushdown automaton that executes Bitcoin Script extended
with linear-type opcodes, packaged as a plug-and-play ESP-IDF component and
wired into a small mesh stack with signed-policy hot-swap, capability-gated
forwarding, on-device metering, and BSV settlement.

It runs today on the ESP32 family including the **ESP32-C6** (RISC-V), inside a
sub-128 KB WASM linear-memory footprint, leaving room for Wi-Fi / ESP-NOW
alongside it.

> **Status: pre-alpha, but real.** Everything here boots and runs on hardware —
> the mesh demo, the on-chain x402 device-rental bridge, and the cold-chain
> example have all been exercised on physical XIAO ESP32-C6 boards. It is not a
> product or a stable release. APIs will move. See the per-component caveats.

---

## Why this exists

The usual smart-city / IoT-at-scale argument runs aground on a contradiction:
you want millions of cheap devices acting autonomously, but you also want every
action to be **verifiable, accountable, and settleable** — without a trusted
central server in the loop.

Semantos resolves it by pushing a real Bitcoin-Script VM down onto the device:

- **Devices verify and act; wallets sign; the chain settles.** Each cell is a
  1 KB self-describing unit carrying a script. A device verifies the frame
  signature and runs the script in a pure sandbox before it actuates anything.
  No device holds a spending key.
- **Policy is a signed cell, not a firmware flash.** Swarm/forwarding rules
  arrive over the air as signed `rule`-class cells and hot-swap at runtime. A
  new routing or pricing policy propagates through the mesh as data.
- **Throughput lives where it belongs.** The edge device's job is cheap local
  verification and actuation; high-volume settlement rides BSV L1 (the layer
  that scales to the tens-of-thousands-of-tps range a smart city actually
  needs). The device is the *honest sensor/actuator*, not the ledger.

This is the kit you grab to put that whole stack on a board on your desk.
It is C6-first today: the public firmware path uses Espressif's WAMR package,
while the pure mesh state machines are kept behind a small C ABI so they can be
ported to a Zig core without changing examples.

---

## What's in the box

```
semantos-edge-kit/
├── components/
│   ├── semantos/                 the cell-engine itself
│   │   ├── wasm/
│   │   │   └── cell-engine-embedded.wasm   (36 KB — Bitcoin Script + linear types)
│   │   ├── include/              public API + the 4 adapter callback types
│   │   ├── src/
│   │   │   ├── semantos.c                 lifecycle + kernel wrappers
│   │   │   ├── host_crypto_mbedtls.c      sha256 / hash160 / checksig / ...
│   │   │   ├── host_utility.c             log, blocktime, sequence, dispatch
│   │   │   └── runtime_wamr.c             WAMR backend (public path)
│   │   ├── CMakeLists.txt / Kconfig / idf_component.yml
│   ├── cell-mesh/                 current C ABI for the networking + policy stack
│       ├── cell_frame / cell_wire / cell_radio     framing + ESP-NOW transport
│       ├── cell_forward (v1/v2)                     capability-gated multicast forwarding
│       ├── cell_channel                             payment-channel state on-device
│       ├── cell_capability                          capability certificates
│       ├── cell_rules                               hot-swappable signed swarm policy
│       ├── cell_mnca                                MNCA incentive / settle logic
│       ├── cell_meter                               on-device metered-flow draining
│       └── cell_sig / cell_ring                     frame signatures + ring buffer
│   └── cell-mesh-zig/             Zig implementation of the pure cm_* mesh core
├── examples/
│   ├── hello_cell/               minimal: prove the VM loads and runs
│   ├── mesh_demo/                multi-board swarm, 20 Hz telemetry, signed deck
│   └── cold_chain/               sensor → signed cell → anchor (cold-chain custody)
├── tools/                        host-side (Bun + @bsv/sdk)
│   ├── mesh-observer/            read-only USB viewer + live telemetry dashboard
│   ├── x402-bridge/             agent pays an x402 endpoint → device actuates on-chain
│   └── sign-cell-deck.ts        pre-signs the cell deck flashed into a device
└── docs/
    ├── ADAPTERS.md              the 4 adapter patterns you implement
    ├── AI-PAIRING.md            how to use this repo with a coding agent
    ├── CLEAVAGE-APPARATUS.md    what is and is not included from core cleavage
    ├── HOST_IMPORTS.md          the 12 host imports the kernel calls
    ├── OPCODE-PARITY.md         keeping edge opcodes matched to core
    ├── RESEARCH-COLLABORATION.md academic / lab collaboration brief
    ├── ZIG-ROADMAP.md           plan for a Zig mesh-core with C ABI shim
    ├── SMART-CITY-THROUGHPUT.md smart-city throughput positioning
    ├── VM-ENFORCEMENT.md        what scripts actually accept/reject
    ├── CHALLENGE.md             "fun ideas for a Sunday" build list
    └── x402-over-cells.md       the on-chain device-rental flow
```

---

## The execution model in one paragraph

The cell-engine runs scripts inside a pure sandbox: no I/O, no async, no direct
side effects. Everything the kernel wants from the outside world arrives through
**twelve host imports** plus **seven adapter callbacks** grouped into **four
patterns**. mbedTLS, which ESP-IDF already ships, covers the crypto imports
natively. The four adapter patterns are where you bind the VM to your hardware.

Enforcement is real but deliberately narrow: `kernel_execute()` accepts only when
the unlock+lock script pair executes cleanly and leaves a truthy stack top,
matching Bitcoin Script success semantics. Firmware then gates physical actions
on that accept/reject result. See `docs/VM-ENFORCEMENT.md`.

| Adapter pattern | What it does | Example ESP32 bindings |
| --- | --- | --- |
| **Storage** | Read/write named blobs | NVS, SPIFFS, LittleFS, SD, PSRAM ring |
| **Identity** | Resolve / derive certificates | flash cert store, BLE-provisioned, Wi-Fi Manager |
| **Anchor** | Submit a 32-byte state hash for durable record | HTTP gateway, LoRa uplink, ESP-NOW broadcast, SD log |
| **Network** | Publish / query semantic objects | ESP-NOW, MQTT, BLE advertisement, mDNS |

A no-op adapter table is wired in by default so you can prove the WASM loads and
the kernel runs before touching real I/O. See `docs/ADAPTERS.md`.

---

## Quick start — `hello_cell`

With ESP-IDF 5.x installed and a board plugged in:

```bash
cd examples/hello_cell
idf.py set-target esp32c6       # or esp32, esp32s3, esp32c3, ...
idf.py build flash monitor
```

Expected:

```
I (530) semantos: init: loading cell-engine-embedded.wasm (36647 bytes)
I (544) hello_cell: load_script rc=0
I (546) hello_cell: execute rc=0 opcount=3 stack_depth=1 top_ptr=0x... err=0x0
I (548) hello_cell: === hello cell: success ===
```

If you see that, you have a 2-PDA Bitcoin-Script-with-linear-types VM running on
a microcontroller.

### Runtime backend

The public kit is WAMR-only via `espressif/wasm-micro-runtime`. Earlier
bring-up carried a wasm3 backend, but the Espressif registry path moved and the
active examples now pin WAMR for reproducible builds. The old wasm3 source is
left in the tree only as a reference for future runtime ports.

---

## The mesh demo (the interesting one)

`examples/mesh_demo` turns a handful of XIAO ESP32-C6 boards into a swarm:
each board runs the cell-engine, broadcasts a 20 Hz pose/telemetry cell over
ESP-NOW, forwards capability-gated cells for its neighbors, and hot-swaps its
forwarding policy when a signed `rule` cell arrives. Watch it live from your
laptop with no firmware changes:

```bash
bun install
bun run observe          # discovers XIAOs on /dev/cu.usbmodem*, opens http://localhost:3500
bun run observe:sim      # no hardware? drive 3 synthetic speeders instead
```

See `tools/mesh-observer/README.md`.

## Pair-programming with an AI agent

This repo includes an `AGENTS.md` file and `docs/AI-PAIRING.md`. If you are
using Codex, Cursor, Claude, or another coding agent, ask it to read those first.
They describe the safe extension points, the smoke tests, and the places where
the kit is intentionally fail-closed.

## Zig mesh core

The current firmware still uses the C `components/cell-mesh` component. The
Zig core lives in `components/cell-mesh-zig`: the pure byte/state modules export
the same `cm_*` C ABI and are verified by linking the existing C tests against
the Zig static library. ESP-NOW radio glue and mbedTLS secp256k1 wrappers remain
C-facing until Zig ESP-IDF integration is proven on ESP32-C6 hardware.

```bash
bun run zig:test
bun run zig:test:c-abi
```

## On-chain device rental (x402 over cells)

`tools/x402-bridge` lets an autonomous agent pay an x402 endpoint in BSV and
have a physical mesh device actuate in response — payment verified, then a
wallet-signed `actuator_activate.v0` cell is broadcast and the device acks
`*** ACTUATOR ACTIVATED ***`. Dry-run/simulated payment is the default. Any
mainnet spend or settlement path requires an explicit `--real-payment`,
`--live`, or `--settle` flag. See `tools/x402-bridge/README.md` and
`docs/x402-over-cells.md`.

## Smart-city / factory throughput

The edge device is not the high-throughput broadcaster; it is the local verifier
and actuator. High-volume settlement belongs upstream on BSV L1 and the relay /
gateway layer. A short laptop burst from the broader Semantos broadcaster work
has reached 14.7k tx/s into GorillaPool ARC before the local machine became the
bottleneck, which is useful evidence for the architecture but not a formal
network-capacity claim. The smart-city target is horizontal scaling: many edge
devices verify locally, while gateway broadcasters batch and parallelize
settlement streams. See `docs/SMART-CITY-THROUGHPUT.md`.

---

## Honest caveats

- **Pre-alpha.** It boots and the demos run on hardware, but nothing here is
  hardened or tested at serious scale.
- **Per-device verification is not fast.** A single secp256k1 verify on a C6
  with hardware SHA + MPI is on the order of a few hundred milliseconds, so a
  device tops out around a handful of full-`CHECKSIG` cells per second. Volume
  comes from *many devices* and from settling on L1 — not from one MCU pretending
  to be a chain.
- **Sighash is partial.** The `checksig` / `checkmultisig` in
  `host_crypto_mbedtls.c` parse SEC pubkeys and DER sigs and verify *pre-hashed*
  32-byte messages (which the embedded profile feeds them). Full raw-tx sighash
  machinery is not implemented on-device.
- **Adapters are stubs by default** — the no-op table returns "feature not
  available"; binding them to real hardware is the work.
- **Payloads stay under 1 KB** (the octave-0 cell size); there's no large-cell
  streaming across WASM calls yet.
- No warranty. May not build on your exact ESP-IDF version. Patches welcome.

---

## License

This kit is released under the Open BSV License v4. It is open for use,
modification, and redistribution on Bitcoin SV chains, with no warranty. See
`LICENSE`.

## Where the WASM blob comes from

The vendored `components/semantos/wasm/cell-engine-embedded.wasm` is built from
the upstream Semantos cell-engine source with the `embedded` profile. Consumers
do not need the upstream source to build or run this kit; the blob is committed
so the repo works standalone.

Maintainers rebuild it from the Semantos monorepo like this:

```bash
# inside semantos-core
cd core/cell-engine
zig build -Dembedded=true
cp zig-out/bin/cell-engine-embedded.wasm \
   ../../../semantos-edge/components/semantos/wasm/

# inside semantos-edge-kit
bun run opcode:parity
```

`bun run opcode:parity` checks that the vendored edge blob is byte-identical
to the current core embedded build and that the edge C wrapper exposes the
entrypoint needed by `OP_BRANCHONOUTPUT`.

## Next

Read `docs/CHALLENGE.md`, pick a build, implement the adapter it needs, and
open an issue or pull request with what you found.
