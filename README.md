# semantos-edge

**A Bitcoin-Script virtual machine, small enough to run on a microcontroller,
networked into a self-organizing mesh.**

`semantos-edge` is the IoT / edge distribution of the Semantos cell-engine: a
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

---

## What's in the box

```
semantos-edge/
├── components/
│   ├── semantos/                 the cell-engine itself
│   │   ├── wasm/
│   │   │   └── cell-engine-embedded.wasm   (36 KB — Bitcoin Script + linear types)
│   │   ├── include/              public API + the 4 adapter callback types
│   │   ├── src/
│   │   │   ├── semantos.c                 lifecycle + kernel wrappers
│   │   │   ├── host_crypto_mbedtls.c      sha256 / hash160 / checksig / ...
│   │   │   ├── host_utility.c             log, blocktime, sequence, dispatch
│   │   │   ├── runtime_wamr.c             WAMR backend (faster, C6/S3)
│   │   │   └── runtime_wasm3.c            wasm3 backend (tiny, runs anywhere)
│   │   ├── CMakeLists.txt / Kconfig / idf_component.yml
│   └── cell-mesh/                 the networking + policy stack
│       ├── cell_frame / cell_wire / cell_radio     framing + ESP-NOW transport
│       ├── cell_forward (v1/v2)                     capability-gated multicast forwarding
│       ├── cell_channel                             payment-channel state on-device
│       ├── cell_capability                          capability certificates
│       ├── cell_rules                               hot-swappable signed swarm policy
│       ├── cell_mnca                                MNCA incentive / settle logic
│       ├── cell_meter                               on-device metered-flow draining
│       └── cell_sig / cell_ring                     frame signatures + ring buffer
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
    ├── HOST_IMPORTS.md          the 10 host imports the kernel calls
    ├── CHALLENGE.md             "fun ideas for a Sunday" build list
    └── x402-over-cells.md       the on-chain device-rental flow
```

---

## The execution model in one paragraph

The cell-engine runs scripts inside a pure sandbox: no I/O, no clock, no async,
no side effects. Everything the kernel wants from the outside world arrives
through **ten host imports** (five crypto, three utility, one named dispatch,
one octave fetch) plus **seven adapter callbacks** grouped into **four
patterns**. mbedTLS — which ESP-IDF already ships — covers all five crypto
imports natively. The four adapter patterns are where you bind the VM to your
hardware.

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
idf.py add-dependency "espressif/wamr^2.0.0"   # or espressif/wasm3^0.5.0
idf.py build flash monitor
```

Expected:

```
I (530) semantos: init: loading cell-engine-embedded.wasm (36019 bytes)
I (544) hello_cell: load_script rc=0
I (546) hello_cell: execute rc=0 opcount=3 stack_depth=1 top=1 err=0x0
I (548) hello_cell: === hello cell: success ===
```

If you see that, you have a 2-PDA Bitcoin-Script-with-linear-types VM running on
a microcontroller.

### Runtime choice (wasm3 vs WAMR)

Pick one via `idf.py menuconfig` → *Component config → Semantos cell-engine →
WASM runtime backend*:

- **wasm3** — tiny (~64 KB code), no PSRAM. Runs on plain ESP32, S2, C3, S3.
- **WAMR** (`espressif/wamr`) — bigger, faster, AOT-capable. Recommended for
  C6 / S3.

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

## On-chain device rental (x402 over cells)

`tools/x402-bridge` lets an autonomous agent pay an x402 endpoint in BSV and
have a physical mesh device actuate in response — payment verified, then a
wallet-signed `actuator_activate.v0` cell is broadcast and the device acks
`*** ACTUATOR ACTIVATED ***`. This is the "devices verify and act, the chain
settles" loop, end to end. See `tools/x402-bridge/README.md` and
`docs/x402-over-cells.md`.

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

## Where the WASM blob comes from

The vendored `components/semantos/wasm/cell-engine-embedded.wasm` is built from
the main Semantos monorepo's cell-engine (`core/cell-engine`) with the
`embedded` profile:

```bash
# inside semantos-core
cd core/cell-engine
zig build -Dembedded=true
cp zig-out/bin/cell-engine-embedded.wasm \
   ../../semantos-edge/components/semantos/wasm/
```

The blob is committed so this repo builds standalone without the monorepo.

## Next

Read `docs/CHALLENGE.md`, pick a build, implement the adapter it needs, and
bring it to the next meetup.
