#!/usr/bin/env bun
/**
 * scripted-vm-demo.ts — the VM-focused demo.
 *
 * Proves the 36 KB on-device WASM cell-engine is doing the work, not the C
 * rule layer. It injects a real `cellmesh.scripted.v0` cell carrying a
 * P2PK + OP_CHECKSIG Bitcoin script with a BIP-143 tx context. The board
 * that *receives* the broadcast runs the lock+unlock through the cell-engine
 * (`dispatch_scripted_cell` → `semantos_kernel_execute`):
 *
 *   good →  engine ACCEPTs → "*** SCRIPT ACCEPTED ***" + a 600 ms LED blink
 *   bad  →  one byte of the in-script ECDSA signature is flipped → the
 *           engine's OP_CHECKSIG fails → "REJECTED" + the LED stays dark
 *
 * The crucial bit: the *frame* signature stays valid in BOTH cases, so the
 * bad cell sails through the radio's frame-auth gate and is rejected *by the
 * VM itself* — not by the transport. That's the whole pitch, on hardware.
 *
 * Topology: a board never receives its own broadcast, so inject into one
 * board (the broadcaster) and watch the other (where the VM runs + LED is).
 *
 *   bun scripted-vm-demo.ts --inject-port /dev/cu.usbmodem11201 \
 *                           --watch /dev/cu.usbmodem11301
 *   then type:  g (good) · b (bad) · help · quit
 *   or non-interactive:  bun scripted-vm-demo.ts --run "good|bad"
 */

import readline from 'node:readline';
import { startSigner } from './signer.js';
import { DOMAIN } from '../domains.js';
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { openSync, writeSync, closeSync } from 'node:fs';
import { PrivateKey, ECDSA, BigNumber } from '@bsv/sdk';
import {
  mintCell, signCell, typeHash, bip143Sighash, ecdsaDer,
  writeU16LE, writeU32LE, writeU64LE,
} from './cell-codec.js';
import { frameCell } from './serial-mesh.js';

// ── config ───────────────────────────────────────────────────────────
const flag = (n: string, d?: string) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
// Auto-discover boards so a reset/replug (renames the CDC device) never breaks it.
function discoverPorts(): string[] {
  try { return require('node:fs').readdirSync('/dev').filter((f: string) => /^cu\.usbmodem\d+$/.test(f)).map((f: string) => `/dev/${f}`).sort(); }
  catch { return []; }
}
const ports = discoverPorts();
const injectPort = flag('--inject-port') ?? ports[0] ?? '/dev/cu.usbmodem11201'; // broadcaster
const watchPort  = flag('--watch') ?? ports[1] ?? ports[0] ?? '/dev/cu.usbmodem11301'; // VM runs here, LED here
const baud       = flag('--baud', '115200')!;
const runScript  = flag('--run');                                    // e.g. "good|bad"

// The wallet the boards were provisioned to trust (matches sign-cell-deck.ts
// + mesh-console.ts). Frame sigs and the P2PK lock both key off it.
// Cell authority. The device verifies every signed cell against the trust
// anchor in its firmware, so this must BE that anchor — it is the fleet
// operator root by default. Nothing here spends on-chain, so there is no
// second key to keep apart.
const WALLET = startSigner().key;
const OWNER  = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex')).subarray(0, 16);
const WALLET_PUBKEY = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex')); // 33-byte compressed SEC
const SCRIPTED_TYPE = typeHash('cellmesh.scripted.v0');
const SIGHASH_ALL_FORKID = 0x41;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
let counter = 1;

// ── build a P2PK + OP_CHECKSIG scripted.v0 payload ──────────────────
// Layout read by mesh_demo's dispatch_scripted_cell():
//   u16 lock_len | lock | u16 unlock_len | unlock | u16 tx_len | tx |
//   u32 input_idx | u64 input_value | u32 counter (uniqueness)
function buildScriptedPayload(tamper: boolean): Uint8Array {
  // Lock: PUSH33 <wallet pubkey> OP_CHECKSIG
  const lock = new Uint8Array(1 + 33 + 1);
  lock[0] = 0x21; lock.set(WALLET_PUBKEY, 1); lock[34] = 0xac;

  // Minimal raw spending tx the engine parses for the BIP-143 sighash:
  // version=1, 1 input (zero prevout, empty scriptSig, seq=ffffffff),
  // 1 output (value=10000, scriptPubKey=OP_1), locktime=0.
  const PREV_TXID = new Uint8Array(32);
  const tx = new Uint8Array([
    0x01, 0x00, 0x00, 0x00,                                  // version
    0x01,                                                    // vin count
    ...PREV_TXID, 0x00, 0x00, 0x00, 0x00,                    // prevout
    0x00,                                                    // scriptSig len
    0xff, 0xff, 0xff, 0xff,                                  // sequence
    0x01,                                                    // vout count
    0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,          // value = 10000
    0x01, 0x51,                                              // scriptPubKey OP_1
    0x00, 0x00, 0x00, 0x00,                                  // locktime
  ]);
  const inputValue = 50000n;
  const inputIdx = 0;

  // BIP-143 sighash (mirrors the engine's sighash.zig), signed by the wallet.
  const sighash = bip143Sighash(
    1,
    [{ prevTxid: PREV_TXID, prevVout: 0, sequence: 0xffffffff }],
    [{ value: 10000n, script: new Uint8Array([0x51]) }],
    0, inputIdx, lock, inputValue, SIGHASH_ALL_FORKID,
  );
  const sigObj = ECDSA.sign(new BigNumber(Array.from(sighash) as unknown as number[]), WALLET, true);
  const der = ecdsaDer(sigObj);
  const scriptSig = new Uint8Array(der.length + 1);
  scriptSig.set(der, 0);
  scriptSig[der.length] = SIGHASH_ALL_FORKID; // append sighash type byte

  if (tamper) {
    // Flip one byte INSIDE the s-value of the DER sig (second-to-last byte,
    // just before the sighash-type byte). DER stays structurally valid, so
    // the engine parses it fine and fails at the ECDSA check — a genuine
    // "this signature is cryptographically wrong" rejection by the VM.
    scriptSig[scriptSig.length - 2] ^= 0x01;
  }

  const unlock = new Uint8Array(1 + scriptSig.length);
  unlock[0] = scriptSig.length;               // PUSH N
  unlock.set(scriptSig, 1);

  const payload = new Uint8Array(2 + lock.length + 2 + unlock.length + 2 + tx.length + 4 + 8 + 4);
  let o = 0;
  writeU16LE(payload, o, lock.length);   o += 2; payload.set(lock, o);   o += lock.length;
  writeU16LE(payload, o, unlock.length); o += 2; payload.set(unlock, o); o += unlock.length;
  writeU16LE(payload, o, tx.length);     o += 2; payload.set(tx, o);     o += tx.length;
  writeU32LE(payload, o, inputIdx);      o += 4;
  writeU64LE(payload, o, inputValue);    o += 8;
  writeU32LE(payload, o, counter++);     o += 4;
  return payload;
}

function buildFrame(tamper: boolean): Buffer {
  const payload = buildScriptedPayload(tamper);
  const cell = mintCell(SCRIPTED_TYPE, payload, OWNER, BigInt(Date.now()), DOMAIN.meshScript);
  const sig = signCell(cell, WALLET); // frame sig over the final cell — valid in BOTH cases
  return Buffer.from(frameCell(cell, sig));
}

// ── inject: one paced write over USB serial (reliable; no RF retry —
// the firmware stages a single broadcast and acks with a 3-pulse blink) ──
async function injectFrame(frame: Buffer): Promise<void> {
  const fd = openSync(injectPort, 'w');
  try {
    for (let o = 0; o < frame.length; o += 256) {
      writeSync(fd, frame, o, Math.min(256, frame.length - o));
      await sleep(2);
    }
  } finally {
    closeSync(fd);
  }
}

async function send(kind: 'good' | 'bad'): Promise<void> {
  const frame = buildFrame(kind === 'bad');
  await injectFrame(frame);
  if (kind === 'good') {
    out('\x1b[36m→ VALID P2PK+OP_CHECKSIG script injected — expect ' +
        '\x1b[32m*** SCRIPT ACCEPTED ***\x1b[36m + LED blink on the watch board\x1b[0m');
  } else {
    out('\x1b[36m→ TAMPERED signature injected (frame sig still valid) — expect the VM to ' +
        '\x1b[31mREJECT\x1b[36m it, LED stays dark\x1b[0m');
  }
}

// ── watch the receiving board's serial (where the VM runs) ──────────
const readers: ChildProcessWithoutNullStreams[] = [];
function watch(port: string): void {
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
      if (/SCRIPT ACCEPTED/i.test(ln))      out(`\x1b[32m[${label}] [OK]  ${ln}\x1b[0m`);
      else if (/scripted.*REJECTED/i.test(ln)) out(`\x1b[31m[${label}] [NO]  ${ln}\x1b[0m`);
      else if (/REJECTED|SCRIPT/i.test(ln))    out(`\x1b[90m[${label}] ${ln}\x1b[0m`);
    }
  });
  readers.push(c);
}

// ── REPL ─────────────────────────────────────────────────────────────
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'vm> ' });
function out(s: string): void {
  readline.cursorTo(process.stdout, 0);
  readline.clearLine(process.stdout, 0);
  process.stdout.write(s + '\n');
  rl.prompt(true);
}
const HELP = `commands:
  g | good    inject a VALID Bitcoin script  → VM ACCEPTs → LED blink
  b | bad     inject a TAMPERED signature    → VM REJECTs → LED dark
  help | quit
inject → ${injectPort.split('modem')[1] ?? injectPort}   watch (VM + LED) → ${watchPort.split('modem')[1] ?? watchPort}`;

function cleanup(): void { for (const c of readers) c.kill(); rl.close(); process.exit(0); }

async function handle(line: string): Promise<void> {
  const cmd = line.trim().toLowerCase();
  if (!cmd) return;
  try {
    if (cmd === 'help') return out(HELP);
    if (cmd === 'quit' || cmd === 'exit' || cmd === 'q') return cleanup();
    if (cmd === 'g' || cmd === 'good') return await send('good');
    if (cmd === 'b' || cmd === 'bad')  return await send('bad');
    out(`unknown: ${cmd} — type 'help'`);
  } catch (e) {
    out(`\x1b[31merror: ${(e as Error).message}\x1b[0m`);
  }
}

// ── boot ─────────────────────────────────────────────────────────────
if (process.argv.includes('--dry')) {
  // Offline self-check: build both cells, no serial port touched.
  const good = buildScriptedPayload(false);
  const bad  = buildScriptedPayload(true);
  const gf = buildFrame(false), bf = buildFrame(true);
  // Compare excluding the trailing 4-byte uniqueness counter so the diff
  // isolates the tamper itself.
  const n = Math.min(good.length, bad.length) - 4;
  let diff = 0; for (let i = 0; i < n; i++) if (good[i] !== bad[i]) diff++;
  console.log(`[dry] good payload = ${good.length} B, bad payload = ${bad.length} B`);
  console.log(`[dry] payloads differ in ${diff} byte(s) excluding counter (expect 1 — the flipped sig byte)`);
  console.log(`[dry] good frame = ${gf.length} B, bad frame = ${bf.length} B (IJ-line, newline-terminated)`);
  console.log(`[dry] frame starts "${gf.subarray(0, 2).toString()}" — OK`);
  process.exit(diff === 1 ? 0 : 1);
}

console.log(`scripted-vm demo — inject via ${injectPort}, watch ${watchPort}`);
console.log(HELP);
watch(watchPort);

if (runScript) {
  (async () => {
    await sleep(800); // let the tail attach
    for (const seg of runScript.split('|').map((s) => s.trim()).filter(Boolean)) {
      out(`\x1b[33m> ${seg}\x1b[0m`);
      await handle(seg);
      await sleep(2500); // let the VM run + log land
    }
    await sleep(1500);
    cleanup();
  })();
} else {
  rl.prompt();
  rl.on('line', (l) => handle(l).then(() => rl.prompt()));
  rl.on('SIGINT', cleanup);
}
