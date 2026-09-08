#!/usr/bin/env bun
/**
 * mesh-console.ts — an interactive console for driving the C6 cell-mesh from
 * the laptop: sign + inject cells through a connected C6 (the #558
 * serial-injection path), AND tail device serial in one view, so you can
 * push a change and watch the mesh react live.
 *
 *   bun mesh-console.ts [--inject-port /dev/cu.usbmodemB] \
 *                       [--tail /dev/cu.usbmodemA,/dev/cu.usbmodemC] [--baud 115200]
 *
 * Inject via a device that is NOT a tail target's only path — and remember a
 * device never receives its OWN broadcast, so to watch a rule fire, inject
 * from one device (B) and tail the others (A, C).
 *
 * Commands (type `help`):
 *   rule <heartbeat|tap|scripted> blink <ms>     install a hot-swap rule
 *   quorum <type> blink <ms> <n> <windowMs>      install a quorum rule
 *   tap | heartbeat | scripted                    inject a trigger cell
 *   verbose                                       toggle full serial echo
 *   help | quit
 */

import readline from 'node:readline';
import { startSigner } from './signer.js';
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { openSync, writeSync, closeSync } from 'node:fs';
import { PrivateKey } from '@bsv/sdk';
import { mintCell, signCell, typeHash, writeU16LE, writeU32LE } from './cell-codec.js';
import { domainForType } from './cell-domains.js';
import { frameCell } from './serial-mesh.js';

// ── config ───────────────────────────────────────────────────────────
const flag = (n: string, d?: string) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const injectPort = flag('--inject-port', '/dev/cu.usbmodem21201')!; // device B
const tailPorts = (flag('--tail', '/dev/cu.usbmodem21301,/dev/cu.usbmodem21401')!).split(',').filter(Boolean);
const baud = flag('--baud', '115200')!;

// Cell authority. The device verifies every signed cell against the trust
// anchor in its firmware, so this must BE that anchor — it is the fleet
// operator root by default. Nothing here spends on-chain, so there is no
// second key to keep apart.
const WALLET = startSigner().key;
const OWNER = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex')).subarray(0, 16);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const TYPES: Record<string, Uint8Array> = {
  heartbeat: typeHash('cellmesh.heartbeat.v0'),
  tap: typeHash('cellmesh.tap.v0'),
  scripted: typeHash('cellmesh.scripted.v0'),
  rule: typeHash('cellmesh.rule.v0'),
};

let counter = 1;

// ── rule cell encoder (cell_rules.h schema v1, 139 B) ───────────────
function encodeRule(triggerType: Uint8Array, blinkMs: number, quorum?: { n: number; windowMs: number }): Uint8Array {
  const buf = new Uint8Array(139);
  buf[0] = 0x01;                              // schema_version
  buf[1] = quorum ? 0x02 : 0x01;              // trigger_kind: QUORUM | ON_TYPE
  buf.set(triggerType, 2);                    // trigger_type_hash (2..33)
  if (quorum) {
    buf[34] = quorum.n & 0xff;                // quorum_n
    writeU16LE(buf, 35, quorum.windowMs);     // quorum_window_ms
    buf[37] = quorum.n & 0xff;                // quorum_distinct_peers
  }
  buf[38] = 0x01;                             // effect_kind = BLINK
  writeU16LE(buf, 39, blinkMs);               // blink.duration_ms
  return buf;
}

// ── inject: sign + frame + paced write (+ retry for best-effort RF) ──
async function inject(typeHashBytes: Uint8Array, payload: Uint8Array, label: string): Promise<void> {
  const cell = mintCell(typeHashBytes, payload, OWNER, BigInt(Date.now()), domainForType(typeHashBytes));
  const sig = signCell(cell, WALLET);
  const frame = Buffer.from(frameCell(cell, sig));
  for (let r = 0; r < 2; r++) {
    const fd = openSync(injectPort, 'w');
    try {
      for (let o = 0; o < frame.length; o += 256) {
        writeSync(fd, frame, o, Math.min(256, frame.length - o));
        await sleep(2);
      }
    } finally {
      closeSync(fd);
    }
    await sleep(250);
  }
  out(`\x1b[36m[inject→${injectPort.split('modem')[1] ?? injectPort}] ${label}\x1b[0m`);
}

// ── serial tail ──────────────────────────────────────────────────────
let verbose = false;
const KEEP = /RULE|BLINK|fired|EFFECT|INSTALL|RX |TAP|tap|ACTUATOR|EMIT|quorum|QUORUM|SCRIPT|CELL INJECTED/i;
const readers: ChildProcessWithoutNullStreams[] = [];
function tail(port: string): void {
  spawnSync('stty', ['-f', port, baud, 'raw', '-echo'], { stdio: 'ignore' });
  const label = port.split('modem')[1] ?? port;
  const c = spawn('cat', [port]) as ChildProcessWithoutNullStreams;
  let buf = '';
  c.stdout.on('data', (d: Buffer) => {
    buf += d.toString();
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      const ln = buf.slice(0, i).replace(/\x1b\[[0-9;]*m/g, '').trim();
      buf = buf.slice(i + 1);
      if (ln && (verbose || KEEP.test(ln))) out(`\x1b[90m[${label}]\x1b[0m ${ln}`);
    }
  });
  readers.push(c);
}

// ── REPL plumbing (keep the prompt clean under async serial output) ──
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'mesh> ' });
function out(s: string): void {
  readline.cursorTo(process.stdout, 0);
  readline.clearLine(process.stdout, 0);
  process.stdout.write(s + '\n');
  rl.prompt(true);
}

const HELP = `commands:
  rule <heartbeat|tap|scripted> blink <ms>   install a hot-swap rule (ON_TYPE → BLINK)
  quorum <type> blink <ms> <n> <windowMs>    install a quorum rule (N-of-peers → BLINK)
  tap | heartbeat | scripted                  inject a trigger cell of that type
  verbose                                     toggle full serial echo (default: filtered)
  help | quit
note: a device never sees its own broadcast — inject from ${injectPort.split('modem')[1]}, watch ${tailPorts.map((p) => p.split('modem')[1]).join(', ')}`;

async function handle(line: string): Promise<void> {
  const a = line.trim().split(/\s+/);
  const cmd = a[0]?.toLowerCase();
  if (!cmd) return;
  try {
    if (cmd === 'help') return out(HELP);
    if (cmd === 'quit' || cmd === 'exit') { cleanup(); return; }
    if (cmd === 'verbose') { verbose = !verbose; return out(`verbose ${verbose ? 'ON' : 'OFF'}`); }
    if (cmd === 'sleep') { return await sleep(Number(a[1]) || 0); }
    if (cmd === 'tap' || cmd === 'heartbeat' || cmd === 'scripted') {
      const p = new Uint8Array(8); writeU32LE(p, 0, counter++); writeU32LE(p, 4, Date.now() & 0xffffffff);
      return await inject(TYPES[cmd], p, `${cmd}.v0 #${counter - 1}`);
    }
    if (cmd === 'rule') {
      const trig = TYPES[a[1]]; const ms = Number(a[3]);
      if (!trig || a[2] !== 'blink' || !Number.isFinite(ms)) return out('usage: rule <heartbeat|tap|scripted> blink <ms>');
      return await inject(TYPES.rule, encodeRule(trig, ms), `rule.v0 (on ${a[1]} → blink ${ms}ms)`);
    }
    if (cmd === 'quorum') {
      const trig = TYPES[a[1]]; const ms = Number(a[3]); const n = Number(a[4]); const win = Number(a[5]);
      if (!trig || a[2] !== 'blink' || ![ms, n, win].every(Number.isFinite)) return out('usage: quorum <type> blink <ms> <n> <windowMs>');
      return await inject(TYPES.rule, encodeRule(trig, ms, { n, windowMs: win }), `rule.v0 (QUORUM ${n} ${a[1]} in ${win}ms → blink ${ms}ms)`);
    }
    out(`unknown: ${cmd} — type 'help'`);
  } catch (e) {
    out(`\x1b[31merror: ${(e as Error).message}\x1b[0m`);
  }
}

function cleanup(): void {
  for (const c of readers) c.kill();
  rl.close();
  process.exit(0);
}

// ── boot ─────────────────────────────────────────────────────────────
console.log(`mesh console — inject via ${injectPort}, tail ${tailPorts.join(', ')}`);
console.log(HELP);
for (const p of tailPorts) tail(p);

const runScript = flag('--run'); // e.g. "rule tap blink 500 | sleep 2000 | tap | sleep 800 | tap"
if (runScript) {
  // Non-interactive: run a '|'-separated command list sequentially, drain, exit.
  (async () => {
    await sleep(800); // let the tails attach
    for (const seg of runScript.split('|').map((s) => s.trim()).filter(Boolean)) {
      out(`\x1b[33m> ${seg}\x1b[0m`);
      await handle(seg);
    }
    await sleep(3000); // drain serial
    cleanup();
  })();
} else {
  rl.prompt();
  rl.on('line', (l) => handle(l).then(() => rl.prompt()));
  rl.on('SIGINT', cleanup);
}
