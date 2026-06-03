# mesh-observer

Laptop-side **read-only** viewer for the C6 mesh demo. Discovers
`/dev/cu.usbmodem*` ports, opens each XIAO over USB-CDC, parses
`mesh_demo`'s log lines into structured events, maintains a per-device
state snapshot, and pushes everything to a browser UI over WebSocket.

No firmware changes required — works against the existing mesh_demo
in this repo.

## Run

```sh
bun tools/mesh-observer/server.ts
# → http://localhost:3500

# No hardware? Drive synthetic speeders instead:
bun tools/mesh-observer/server.ts --sim 3
# 3 figure-8 speeders @ 20Hz with an injected ESP-NOW-class transport profile.
# SIM_HZ=50 PORT=3500 ... to override rate/port.
```

Plug in 1–3 XIAOs first; the server discovers them at startup. Reset
them (replug or `idf.py -p … reset`) if you want to see boot events
(mac, role, deck contents, verify bench) in the timeline.

## Speeder telemetry (real-time performance harness)

`mesh_demo` firmware broadcasts an **unsigned** `cellmesh.telem.v0` pose cell
at 20 Hz per device (figure-8 path; payload = seq, spd, x/y mm, hdg mrad,
v mm/s, tx micros). Unsigned because per-frame ECDSA verify (~270 ms) would
cap signed throughput at ~3 cells/sec — telemetry is the hot path; only
results get signed. The observer parses TELEM TX/RX lines into a live track
view + a per-(receiver, speeder) performance panel:

- **rate (Hz)**, **jitter (ms)**, **p99 interval**, **drop %** — computed from
  one receiver clock, so they need NO clock sync and are accurate on day one.
- **latency above floor (ms)** — assumes the fastest cell in the window had
  ~0 delay; this is *relative*, not absolute. Absolute one-hop latency needs
  a two-device clock handshake (not yet in firmware).

The track shows each speeder's originator "truth" pose (solid dot + heading)
against the **sideline-received** pose (hollow ring); a dashed halo marks a
pose that was extrapolated by an in-network transform-on-hop relay
(`telem-pred` lines) — the prediction story that goes beyond endpoint-only
dead reckoning.

The metrics math is unit-tested against synthetic ground truth:
`bun test tools/mesh-observer/telemetry.test.ts`.

## What you see

- Three device cards: MAC, role (originator / relay / destination /
  spectator), TX counters per kind, RX total, verify-bench cost, an
  LED indicator that mirrors the on-device LED:
  - dim yellow on recent blink (tap / heartbeat-via-hot-swap / forward /
    quorum)
  - steady amber when the device is in `CM_CHAN_ACTIVE` (the
    lightbulb is paid for; only device C)
- Channel widget per device (state badge + current seq / device_share /
  expiry).
- Live event timeline (newest first, last 200): color-coded by type
  (tx / rx / effect / channel / rule / boot).

## Architecture

```
┌──────────┐  USB-CDC  ┌────────────┐  WebSocket  ┌──────────┐
│ XIAO C6  │ ────────► │ Bun server │ ──────────► │ browser  │
│ (mesh_   │ log lines │ parser +   │ events +    │ UI       │
│  demo)   │           │ state agg. │ state       │          │
└──────────┘           └────────────┘             └──────────┘
```

- Read path: `stty raw 115200` → `cat /dev/cu.usbmodem…` → line-buffer
  → regex parse → per-device state update → `server.publish('events', …)`.
- Web path: `Bun.serve` (HTTP + WS upgrade) → static `web/index.html` +
  WS stream of `snapshot` then `event` messages.

The browser is **pure vanilla JS** + CSS — no build step, no framework.

## v1 = read-only

This is the observer. **Injection / sending** commands from the browser
back into the mesh is v2 work — needs a separate "bridge" firmware
variant that emits structured binary cell frames over USB-CDC and
accepts injection commands. Not implemented here.

## Parser coverage

| Log line shape | event type | extracted fields |
|---|---|---|
| `mesh_demo up. mac=…` | `boot` | mac |
| `forward-demo role: …` | `role` | role |
| `bench: verify (parse-per-call) …` | `bench` | per_us |
| `deck: … entries; for-me: …` | `deck` | (counts) |
| `TX heartbeat #N (deck)` | `tx` | kind=heartbeat, counter |
| `TX *** TAP #N ***` | `tx` | kind=tap, counter |
| `TX *** EMIT #N ***` | `tx` | kind=emit_confirmed_tap, counter |
| `TX *** FORWARD ORIGINATED #N ***` | `tx` | kind=forward_originated |
| `TX *** FORWARD RELAY *** …` | `tx` | hop_index, remaining |
| `TX *** HOT-SWAP RULE ***` | `tx` | kind=hot_swap_rule |
| `TX *** channel_open ***` | `tx` | step |
| `TX *** channel_commit *** step=N` | `tx` | step |
| `TX *** channel_close *** step=N` | `tx` | step |
| `RX [mac] kind verified (rx_total=N)` | `rx` | sender, kind, rx_total |
| `RX [mac] forward → relay; next=… remaining=N` | `rx` | next, remaining |
| `*** QUORUM FIRED *** (BLINK N ms)` | `effect` | blink_ms |
| `*** FORWARD DELIVERED *** from=[…] hop_index=N inner='…'` | `effect` | from, hop_index, inner |
| `*** CHANNEL OPEN *** capacity=N …` | `channel` | capacity, locktime_ms |
| `*** CHANNEL COMMIT seq=N *** …` | `channel` | seq, device_share, expiry |
| `*** CHANNEL EXPIRED ***` | `channel` | seq, device_share |
| `*** CHANNEL CLOSED ***` | `channel` | final_seq, final_device_share |
| `RX rule: *** HOT-SWAP INSTALLED at slot N ***` | `rule` | slot |
| `RX rule: already installed — skipping (dedup)` | `rule` | (dedup) |
