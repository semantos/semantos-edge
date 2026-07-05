# Pair-programming with an AI agent

This kit is agent-friendly if the agent is pointed at the right files first.
Without that, it may get distracted by the demos and miss the core extension
points.

## Tell the agent to start here

Use this prompt:

```text
Read AGENTS.md, README.md, docs/RESEARCH-COLLABORATION.md,
docs/VM-ENFORCEMENT.md, docs/CLEAVAGE-APPARATUS.md,
docs/OPCODE-PARITY.md, docs/HOST_IMPORTS.md, and docs/ADAPTERS.md.
Then summarize the architecture, the safe extension points, and the smallest
hardware smoke test before editing anything.
```

## Good prompts

### Check the kit

```text
Run the Semantos edge sanity checks: Bun tests, opcode parity, Zig tests, and an
ESP32-C6 build of examples/hello_cell. Report exact failures and do not flash
hardware unless I ask.
```

### Smoke test two C6 boards

```text
Find the two ESP32-C6 serial ports, flash examples/hello_cell to both, reset
each board, and capture the serial output until hello_cell reports success.
```

### Build a factory policy demo

```text
Create a small smart-factory demo where a signed policy cell permits actuation
only when the operator/capability check and metered budget both pass. Keep
private keys off-device; use pre-signed cells.
```

### Add a device primitive

```text
Add a host_call_by_name primitive called led.blink to the ESP32 example. Keep
unknown names fail-closed and document the primitive in docs/HOST_IMPORTS.md.
```

### Wire a cell store

```text
Replace the fail-closed cursor host-import stubs with a small NVS-backed or
SPIFFS-backed cell store. Add a focused example and update docs/HOST_IMPORTS.md.
```

### Work on the Zig core

```text
Extend components/cell-mesh-zig while preserving the existing cm_* C ABI. Run
bun run zig:test and bun run zig:test:c-abi before summarizing the change.
```

## What the agent can do well

- Build and flash `hello_cell`.
- Trace host-import and opcode parity.
- Explain which pieces are edge primitives and which pieces still live in core.
- Add focused C ABI boundary wrappers or hostcall-by-name entries.
- Add docs, tests, and small Zig mesh-core changes.
- Build gateway-side tools and telemetry harnesses.

## Where the human still matters

- Choosing which physical actuator or sensor matters for the experiment.
- Supplying real facility constraints and target event rates.
- Deciding whether a device may ever hold signing keys.
- Interpreting throughput claims and benchmark relevance.
- Confirming before flashing boards used for another demo.

## Expected first milestone

A useful first collaboration milestone is not a large rewrite. It is:

1. `hello_cell` boots on one or two ESP32-C6 boards.
2. `mesh_demo` telemetry is visible in `tools/mesh-observer`.
3. One domain-specific policy or hostcall is added.
4. A short lab note separates MCU verification rate from gateway/broadcaster
   throughput.
