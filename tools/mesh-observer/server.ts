#!/usr/bin/env bun
/**
 * mesh-observer/server.ts — laptop-side observer for the C6 mesh demo.
 *
 * Pure read-only. Discovers /dev/cu.usbmodem* ports, opens each via
 * `cat` (after stty-configuring baud rate), parses mesh_demo's log
 * lines into structured events, maintains a per-device state snapshot,
 * and broadcasts everything to connected browsers over WebSocket.
 *
 * Usage:
 *   bun tools/mesh-observer/server.ts
 *
 * Then open http://localhost:3500 in a browser.
 */

import { readdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseTelemTx, parseTelemRx, StreamStats, type Pose, type StreamMetrics,
} from './telemetry';
import { generateFleet } from './telemetry-sim';
import { positionError } from './telemetry-predict';

const PORT      = Number(process.env.PORT ?? 3500);
const BAUD      = 115200;
const PORT_GLOB = /^cu\.usbmodem\d+$/;
const WEB_DIR   = join(dirname(fileURLToPath(import.meta.url)), 'web');
// `--sim [N]` runs N synthetic speeders instead of (or alongside) real serial.
const SIM_ARG   = process.argv.indexOf('--sim');
const SIM_ON    = SIM_ARG !== -1;
const SIM_N     = SIM_ON ? Math.max(1, Number(process.argv[SIM_ARG + 1] || 2)) : 0;
const SIM_HZ    = Number(process.env.SIM_HZ ?? 20);
// `--predict` turns the sim's relay into a transform-on-hop predictor.
const PREDICT   = process.argv.includes('--predict');

// ── Types ────────────────────────────────────────────────────────────
interface Event {
  ts_ms:  number;         // device millis since boot
  wall_ms: number;        // server wall-clock at receipt
  port:   string;
  type:   string;
  data:   Record<string, unknown>;
}

interface ChannelState {
  state:        'closed' | 'open' | 'active' | 'expired';
  seq?:         number;
  device_share?: number;
  capacity?:    number;
  expiry_ms?:   number;
  base_ms?:     number;        // server wall-clock at channel_open RX
}

interface DeviceState {
  port:           string;
  mac:            string | null;
  role:           string | null;
  tx:             Record<string, number>;
  rx_total:       number;
  rx_by_kind:     Record<string, number>;
  channel:        ChannelState;
  last_event_ms:  number;
  rule_installed: boolean;
  bench_us:       number | null;
  blink_until_ms: number;       // server wall-clock that LED-blink ends
}

function newDeviceState(port: string): DeviceState {
  return {
    port,
    mac:            null,
    role:            null,
    tx:             { heartbeat: 0, tap: 0, emit: 0, forward_originated: 0, forward_relay: 0,
                       hot_swap: 0, channel_open: 0, channel_commit: 0, channel_close: 0 },
    rx_total:       0,
    rx_by_kind:     {},
    channel:        { state: 'closed' },
    last_event_ms:  0,
    rule_installed: false,
    bench_us:       null,
    blink_until_ms: 0,
  };
}

const STATE: Record<string, DeviceState> = {};
const EVENT_LOG: Event[] = [];
const MAX_EVENT_LOG = 200;

// ── Telemetry tracking ───────────────────────────────────────────────
// Latest pose per speeder, keyed by spd id, separately for the originator's
// own TX ("truth") and what a receiving node actually saw ("rx"/"pred").
interface SpeederView {
  spd:        number;
  truth:      Pose | null;   // last TX pose from the originator
  rx:         Pose | null;   // last received pose at a sideline node
  predicted:  boolean;       // last RX was a transform-on-hop prediction
  last_seq:   number;
}
const SPEEDERS: Record<number, SpeederView> = {};
// Arrival stats per (receiving device, speeder). Each receiver sees every
// other speeder, so a device's serial shows RX lines for multiple speeders;
// keying by receiver+speeder keeps each link's jitter/Hz independent rather
// than conflating arrivals from different receivers into one stream.
const RX_STATS: Record<string, StreamStats> = {};
const RX_META:  Record<string, { port: string; spd: number }> = {};
// Recent sideline position error (mm): received pose vs the originator's live
// truth pose at receive time. Naive lag ≈ how far it moved in one latency;
// with --predict the relay extrapolates that away, so this collapses toward
// the dead-reckoning residual. The on-screen proof that prediction works.
const RX_ERR:   Record<string, number[]> = {};
const linkKey = (port: string, spd: number) => `${port}|${spd}`;
const fmtPort = (p: string) => p.replace('/dev/cu.', '').replace('/dev/', '');

function speeder(spd: number): SpeederView {
  return SPEEDERS[spd] ??= { spd, truth: null, rx: null, predicted: false, last_seq: -1 };
}

type LinkMetrics = StreamMetrics & {
  port: string; spd: number; predicted: boolean; errMeanMm: number | null;
};
function telemetryMetrics(): Record<string, LinkMetrics> {
  const out: Record<string, LinkMetrics> = {};
  for (const [key, stats] of Object.entries(RX_STATS)) {
    const { port, spd } = RX_META[key];
    const errs = RX_ERR[key];
    const errMeanMm = errs && errs.length
      ? errs.reduce((s, x) => s + x, 0) / errs.length : null;
    out[key] = {
      ...stats.metrics(stats.floorOffsetUs()),
      port: fmtPort(port), spd,
      predicted: SPEEDERS[spd]?.predicted ?? false,
      errMeanMm,
    };
  }
  return out;
}

// ── Port discovery ───────────────────────────────────────────────────
async function discoverPorts(): Promise<string[]> {
  const files = await readdir('/dev');
  return files
    .filter(f => PORT_GLOB.test(f))
    .map(f => '/dev/' + f)
    .sort();
}

// ── ANSI stripping ───────────────────────────────────────────────────
const ANSI_RE = /\x1b\[[\d;]*m/g;
const LINE_RE = /^I \((\d+)\) mesh_demo: (.+)$/;

// ── Parser ───────────────────────────────────────────────────────────
function parseLine(line: string, port: string): Omit<Event, 'wall_ms'> | null {
  line = line.replace(ANSI_RE, '').trim();
  const m = line.match(LINE_RE);
  if (!m) return null;
  const ts_ms = parseInt(m[1], 10);
  const msg   = m[2];

  // Telemetry (speeder pose) — the real-time-performance path.
  const telTx = parseTelemTx(msg);
  if (telTx) {
    return { ts_ms, port, type: 'telem_tx', data: {
      seq: telTx.seq, spd: telTx.spd, pose: telTx.pose, tx_us: telTx.txUs } };
  }
  const telRx = parseTelemRx(msg);
  if (telRx) {
    return { ts_ms, port, type: 'telem_rx', data: {
      seq: telRx.seq, spd: telRx.spd, pose: telRx.pose, tx_us: telRx.txUs,
      predicted: telRx.predicted, extrap_us: telRx.extrapUs } };
  }

  let mm;
  // Boot info
  if ((mm = msg.match(/^mesh_demo up\. mac=([0-9a-f:]+) wallet_pubkey/))) {
    return { ts_ms, port, type: 'boot', data: { mac: mm[1] } };
  }
  if ((mm = msg.match(/^forward-demo role: (.+)$/))) {
    return { ts_ms, port, type: 'role', data: { role: mm[1] } };
  }
  if ((mm = msg.match(/^bench: verify \(parse-per-call\)\s+\d+\/\d+ OK\s+(\d+) us\/verify/))) {
    return { ts_ms, port, type: 'bench', data: { per_us: parseInt(mm[1], 10) } };
  }
  if ((mm = msg.match(/^deck: \d+ entries; for-me: hb=(\d+) tap=(\d+) rule=(\d+) conf_tap=(\d+) chan_open=(\d+) chan_commit=(\d+) chan_close=(\d+)/))) {
    return { ts_ms, port, type: 'deck', data: {
      hb: +mm[1], tap: +mm[2], rule: +mm[3], conf_tap: +mm[4],
      chan_open: +mm[5], chan_commit: +mm[6], chan_close: +mm[7],
    }};
  }
  // TX events
  if ((mm = msg.match(/^TX heartbeat #(\d+) \(deck\)/))) {
    return { ts_ms, port, type: 'tx', data: { kind: 'heartbeat', counter: +mm[1] } };
  }
  if ((mm = msg.match(/^TX \*\*\* TAP #(\d+) \*\*\* \(deck/))) {
    return { ts_ms, port, type: 'tx', data: { kind: 'tap', counter: +mm[1] } };
  }
  if ((mm = msg.match(/^TX \*\*\* EMIT #(\d+) \*\*\* \(deck confirmed_tap/))) {
    return { ts_ms, port, type: 'tx', data: { kind: 'emit_confirmed_tap', counter: +mm[1] } };
  }
  if ((mm = msg.match(/^TX \*\*\* FORWARD ORIGINATED #(\d+) \*\*\* segments=\[B,C\]/))) {
    return { ts_ms, port, type: 'tx', data: { kind: 'forward_originated', counter: +mm[1] } };
  }
  if ((mm = msg.match(/^TX \*\*\* FORWARD RELAY \*\*\* hop_index=(\d+) remaining=(\d+)/))) {
    return { ts_ms, port, type: 'tx', data: { kind: 'forward_relay', hop_index: +mm[1], remaining: +mm[2] } };
  }
  if (msg.startsWith('TX *** HOT-SWAP RULE ***')) {
    return { ts_ms, port, type: 'tx', data: { kind: 'hot_swap_rule' } };
  }
  if ((mm = msg.match(/^TX \*\*\* SCRIPTED \*\*\* \(deck, cell_id=0x([0-9a-f]+)/))) {
    return { ts_ms, port, type: 'tx', data: { kind: 'scripted', cell_id: parseInt(mm[1], 16) } };
  }
  if ((mm = msg.match(/^TX \*\*\* channel_open \*\*\* \(step=(\d+)/))) {
    return { ts_ms, port, type: 'tx', data: { kind: 'channel_open', step: +mm[1] } };
  }
  if ((mm = msg.match(/^TX \*\*\* channel_commit \*\*\* \(step=(\d+)/))) {
    return { ts_ms, port, type: 'tx', data: { kind: 'channel_commit', step: +mm[1] } };
  }
  if ((mm = msg.match(/^TX \*\*\* channel_close \*\*\* \(step=(\d+)/))) {
    return { ts_ms, port, type: 'tx', data: { kind: 'channel_close', step: +mm[1] } };
  }
  // RX events
  if ((mm = msg.match(/^RX \[([0-9a-f:]+)\] (\w+) verified \(rx_total=(\d+)\)/))) {
    return { ts_ms, port, type: 'rx', data: { kind: mm[2], sender: mm[1], rx_total: +mm[3] } };
  }
  if ((mm = msg.match(/^RX \[([0-9a-f:]+)\] forward → relay; next=([0-9a-f:]+) remaining=(\d+)/))) {
    return { ts_ms, port, type: 'rx', data: { kind: 'forward_relay_decision', sender: mm[1], next: mm[2], remaining: +mm[3] } };
  }
  // Effects
  if ((mm = msg.match(/^\*\*\* QUORUM FIRED \*\*\* \(BLINK (\d+) ms\)/))) {
    return { ts_ms, port, type: 'effect', data: { kind: 'quorum_fired', blink_ms: +mm[1] } };
  }
  if ((mm = msg.match(/^\*\*\* FORWARD DELIVERED \*\*\* from=\[([0-9a-f:]+)\] hop_index=(\d+) inner='([^']*)'/))) {
    return { ts_ms, port, type: 'effect', data: { kind: 'forward_delivered', from: mm[1], hop_index: +mm[2], inner: mm[3] } };
  }
  if ((mm = msg.match(/^\*\*\* SCRIPT ACCEPTED \*\*\* from=\[([0-9a-f:]+)\] opcount=(\d+) depth=(\d+) top=0x([0-9a-f]+)/))) {
    return { ts_ms, port, type: 'effect', data: { kind: 'script_accepted', from: mm[1], opcount: +mm[2], depth: +mm[3], top: parseInt(mm[4], 16) } };
  }
  if ((mm = msg.match(/^scripted \[([0-9a-f:]+)\] REJECTED: rc=(-?\d+) err=(\d+) opcount=(\d+) depth=(\d+) top=0x([0-9a-f]+)/))) {
    return { ts_ms, port, type: 'effect', data: { kind: 'script_rejected', from: mm[1], rc: +mm[2], err: +mm[3], opcount: +mm[4], depth: +mm[5], top: parseInt(mm[6], 16) } };
  }
  if ((mm = msg.match(/^\*\*\* ACTUATOR ACTIVATED \*\*\* from=\[([0-9a-f:]+)\] activations=(\d+) ms_remaining=(\d+)/))) {
    return { ts_ms, port, type: 'effect', data: { kind: 'actuator_activated', from: mm[1], activations: +mm[2], ms_remaining: +mm[3] } };
  }
  if ((mm = msg.match(/^\*\*\* ACTUATOR DEACTIVATED \*\*\* activations=(\d+)/))) {
    return { ts_ms, port, type: 'effect', data: { kind: 'actuator_deactivated', activations: +mm[1] } };
  }
  if (msg.startsWith('TX *** ACTUATOR OFFER ***')) {
    return { ts_ms, port, type: 'tx', data: { kind: 'actuator_offer' } };
  }
  if (msg.startsWith('TX *** ACTUATOR ACTIVATE ***')) {
    return { ts_ms, port, type: 'tx', data: { kind: 'actuator_activate' } };
  }
  // Channel state
  if ((mm = msg.match(/^\*\*\* CHANNEL OPEN \*\*\* capacity=(\d+) locktime=(\d+)/))) {
    return { ts_ms, port, type: 'channel', data: { kind: 'open', capacity: +mm[1], locktime_ms: +mm[2] } };
  }
  if ((mm = msg.match(/^\*\*\* CHANNEL COMMIT seq=(\d+) \*\*\* device_share=(\d+) expiry=(\d+) \(rel_now=(\d+)/))) {
    return { ts_ms, port, type: 'channel', data: { kind: 'commit', seq: +mm[1], device_share: +mm[2], expiry: +mm[3], rel_now: +mm[4] } };
  }
  if ((mm = msg.match(/^\*\*\* CHANNEL EXPIRED \*\*\*.*seq=(\d+) device_share=(\d+)/))) {
    return { ts_ms, port, type: 'channel', data: { kind: 'expired', seq: +mm[1], device_share: +mm[2] } };
  }
  if ((mm = msg.match(/^\*\*\* CHANNEL CLOSED \*\*\* final_seq=(\d+) final_device_share=(\d+)/))) {
    return { ts_ms, port, type: 'channel', data: { kind: 'closed', final_seq: +mm[1], final_device_share: +mm[2] } };
  }
  if ((mm = msg.match(/^RX rule: \*\*\* HOT-SWAP INSTALLED at slot (\d+) \*\*\*/))) {
    return { ts_ms, port, type: 'rule', data: { kind: 'installed', slot: +mm[1] } };
  }
  if (msg.startsWith('RX rule: already installed')) {
    return { ts_ms, port, type: 'rule', data: { kind: 'dedup' } };
  }
  return null;
}

// ── State aggregator ─────────────────────────────────────────────────
function applyEvent(ev: Event) {
  const d = STATE[ev.port] ??= newDeviceState(ev.port);
  d.last_event_ms = ev.wall_ms;

  if (ev.type === 'boot')  d.mac  = ev.data.mac as string;
  if (ev.type === 'role')  d.role = ev.data.role as string;
  if (ev.type === 'bench') d.bench_us = ev.data.per_us as number;

  if (ev.type === 'telem_tx') {
    const sv = speeder(ev.data.spd as number);
    sv.truth = ev.data.pose as Pose;
  }
  if (ev.type === 'telem_rx') {
    const spd = ev.data.spd as number;
    const sv = speeder(spd);
    sv.rx = ev.data.pose as Pose;
    sv.predicted = ev.data.predicted as boolean;
    sv.last_seq = ev.data.seq as number;
    const key = linkKey(ev.port, spd);
    RX_META[key] ??= { port: ev.port, spd };
    (RX_STATS[key] ??= new StreamStats(3000))
      .push(ev.wall_ms, ev.data.seq as number, ev.data.tx_us as number);
    // Position error vs the originator's live truth pose (if we've seen it).
    if (sv.truth) {
      const errs = (RX_ERR[key] ??= []);
      errs.push(positionError(ev.data.pose as Pose, sv.truth));
      if (errs.length > 60) errs.shift();
    }
  }

  if (ev.type === 'tx') {
    const kind = ev.data.kind as string;
    d.tx[kind] = (d.tx[kind] ?? 0) + 1;
    // Heuristic: TX TAP gives this device a 500ms self-blink.
    if (kind === 'tap') d.blink_until_ms = ev.wall_ms + 500;
  }
  if (ev.type === 'rx') {
    const kind = ev.data.kind as string;
    d.rx_total = ev.data.rx_total as number ?? d.rx_total;
    d.rx_by_kind[kind] = (d.rx_by_kind[kind] ?? 0) + 1;
    if (kind === 'tap')       d.blink_until_ms = ev.wall_ms + 500;
    if (kind === 'heartbeat' && d.rule_installed) d.blink_until_ms = ev.wall_ms + 100;
  }
  if (ev.type === 'effect') {
    const kind = ev.data.kind as string;
    if (kind === 'quorum_fired')      d.blink_until_ms = ev.wall_ms + (ev.data.blink_ms as number);
    if (kind === 'forward_delivered') d.blink_until_ms = ev.wall_ms + 800;
    if (kind === 'script_accepted')   d.blink_until_ms = ev.wall_ms + 600;
    if (kind === 'actuator_activated') {
      // Steady-on for the remaining window — same LED priority as on-device.
      d.blink_until_ms = ev.wall_ms + (ev.data.ms_remaining as number);
    }
  }
  if (ev.type === 'channel') {
    const k = ev.data.kind as string;
    if (k === 'open') {
      d.channel = { state: 'open', capacity: ev.data.capacity as number, base_ms: ev.wall_ms };
    } else if (k === 'commit') {
      d.channel.state        = 'active';
      d.channel.seq          = ev.data.seq as number;
      d.channel.device_share = ev.data.device_share as number;
      d.channel.expiry_ms    = ev.data.expiry as number;
    } else if (k === 'expired') {
      d.channel.state = 'expired';
    } else if (k === 'closed') {
      d.channel = { state: 'closed' };
    }
  }
  if (ev.type === 'rule' && ev.data.kind === 'installed') {
    d.rule_installed = true;
  }
}

// ── Serial readers ───────────────────────────────────────────────────
async function streamPort(port: string, onEvent: (e: Event) => void) {
  // Configure baud + raw on macOS. Harmless on Linux too (stty -F differs;
  // we'll fall back). The C6 over USB-CDC ignores baud rate but stty still
  // sets the tty discipline to raw which is what we need.
  try {
    Bun.spawnSync({ cmd: ['stty', '-f', port, String(BAUD), 'raw', '-echo'] });
  } catch {
    try { Bun.spawnSync({ cmd: ['stty', '-F', port, String(BAUD), 'raw', '-echo'] }); } catch {}
  }

  console.log(`[observer] opening ${port}`);
  const proc = Bun.spawn(['cat', port], { stdout: 'pipe', stderr: 'pipe' });

  STATE[port] ??= newDeviceState(port);

  const decoder = new TextDecoder();
  let buf = '';
  const reader = proc.stdout.getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        const parsed = parseLine(line, port);
        if (!parsed) continue;
        const ev: Event = { ...parsed, wall_ms: Date.now() };
        applyEvent(ev);
        EVENT_LOG.push(ev);
        if (EVENT_LOG.length > MAX_EVENT_LOG) EVENT_LOG.shift();
        onEvent(ev);
      }
    }
  } catch (e) {
    console.error(`[observer] ${port} reader error:`, e);
  } finally {
    proc.kill();
    console.log(`[observer] ${port} closed`);
  }
}

// ── HTTP + WebSocket server ──────────────────────────────────────────
const server = Bun.serve({
  port: PORT,
  async fetch(req, server) {
    const url = new URL(req.url);
    if (url.pathname === '/ws') {
      if (server.upgrade(req)) return;
      return new Response('Upgrade failed', { status: 500 });
    }
    let path = url.pathname === '/' ? '/index.html' : url.pathname;
    const file = Bun.file(join(WEB_DIR, path));
    if (await file.exists()) {
      return new Response(file, {
        headers: { 'cache-control': 'no-store' },
      });
    }
    return new Response('Not found', { status: 404 });
  },
  websocket: {
    open(ws) {
      ws.subscribe('events');
      ws.send(JSON.stringify({
        type: 'snapshot',
        state: STATE,
        events: EVENT_LOG,
        speeders: SPEEDERS,
        metrics: telemetryMetrics(),
      }));
    },
    message(_ws, _msg) {
      // Observer is read-only for v1.
    },
    close(_ws) {},
  },
});

console.log(`[observer] http://localhost:${server.port}`);

function broadcast(ev: Event) {
  const isTelem = ev.type === 'telem_tx' || ev.type === 'telem_rx';
  server.publish('events', JSON.stringify({
    type: 'event',
    event: ev,
    state: STATE[ev.port],
    // Pose + metric updates ride along with telemetry events so the view and
    // the readout stay live without a separate poll.
    speeders: isTelem ? SPEEDERS : undefined,
    metrics:  isTelem ? telemetryMetrics() : undefined,
  }));
}

// ── Synthetic source (--sim) ─────────────────────────────────────────
// Replays the emulator in real time through the SAME parse/apply path the
// serial readers use, so the metrics shown are computed identically to live
// hardware. Loops the figure-8 fleet forever.
function startSim(n: number) {
  const speeders = Array.from({ length: n }, (_, i) => ({
    id: i + 1, sizeMm: 6000, lapSeconds: 8 + i * 1.5, phase: (i * Math.PI) / n,
  }));
  // Injected transport profile. Defaults to an ESP-NOW-local class; override
  // via env to demo prediction over longer (cross-internet) links where the
  // win is dramatic: SIM_LAT_MS=100 SIM_JIT_MS=15 SIM_DROP=0.02.
  const transport = {
    baseLatencyMs: Number(process.env.SIM_LAT_MS ?? 9),
    jitterMs:      Number(process.env.SIM_JIT_MS ?? 3),
    dropProb:      Number(process.env.SIM_DROP   ?? 0.01),
  };
  const CHUNK_SEC = 5;
  const simEpoch = Date.now();          // wall time mapped to sim ms 0
  const rxTotals = new Map<number, number>();
  let nextTick = 0;
  const tickPerChunk = Math.floor(CHUNK_SEC * SIM_HZ);

  const pump = () => {
    // Continuous, monotonic stream: seq + txUs keep climbing across chunks so
    // the floor-offset and drop-rate math stay valid (matches real firmware,
    // which has one ever-increasing micros clock).
    const events = generateFleet({
      speeders, hz: SIM_HZ, durationSec: CHUNK_SEC, transport,
      startTick: nextTick, rxTotals, predict: PREDICT,
    });
    nextTick += tickPerChunk;
    for (const e of events) {
      setTimeout(() => {
        const parsed = parseLine(`I (${e.atMs | 0}) mesh_demo: ${e.msg}`, e.port);
        if (!parsed) return;
        const ev: Event = { ...parsed, wall_ms: Date.now() };
        applyEvent(ev);
        EVENT_LOG.push(ev);
        if (EVENT_LOG.length > MAX_EVENT_LOG) EVENT_LOG.shift();
        broadcast(ev);
      }, Math.max(0, simEpoch + e.atMs - Date.now()));
    }
    setTimeout(pump, CHUNK_SEC * 1000);
  };
  console.log(`[observer] SIM mode: ${n} speeder(s) @ ${SIM_HZ}Hz, injected ${transport.baseLatencyMs}±${transport.jitterMs}ms${PREDICT ? ' · in-network prediction ON' : ''}`);
  pump();
}

// ── Boot: discover ports + start readers ─────────────────────────────
if (SIM_ON) {
  startSim(SIM_N);
} else {
  const ports = await discoverPorts();
  if (ports.length === 0) {
    console.warn('[observer] no /dev/cu.usbmodem* ports found — plug a XIAO in, or run with --sim.');
  } else {
    console.log(`[observer] watching ${ports.length} port(s): ${ports.join(', ')}`);
    for (const p of ports) {
      streamPort(p, broadcast).catch(e => console.error(`[observer] ${p} fatal:`, e));
    }
  }
}
