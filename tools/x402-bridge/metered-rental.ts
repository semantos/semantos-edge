#!/usr/bin/env bun
/**
 * metered-rental.ts — DEVICE-ENFORCED pay-per-second. The chip is the meter.
 *
 * A payment channel funds a draining meter ON the device. The device stays lit
 * only while the value it has *consumed* (at 1.2 sats/s) stays under the value
 * it has been *paid* (device_share). It cuts ITSELF off the instant the meter
 * overruns the payment — reuse is impossible, the meter only drains. Top it up
 * with another commitment (more payment) to keep it alive. Settle on-chain at
 * close. Nothing off-device decides when to cut power — the chip does.
 *
 *   open            open the channel (state OPEN; light still off)
 *   pay [sats]      send a commitment (+sats paid) → device meters + stays lit
 *                   while paid-ahead; ~1.2 sats/s, so `pay 12` ≈ 10 s of light
 *   close           close the channel; optionally settle device_share on-chain
 *   help | quit
 *
 *   bun metered-rental.ts            # auto-discovers the two boards, no mainnet settlement
 *   bun metered-rental.ts --settle   # enable Metanet+ARC mainnet settlement on close
 */

import readline from 'node:readline';
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { openSync, writeSync, closeSync, readdirSync } from 'node:fs';
import { PrivateKey } from '@bsv/sdk';
import { mintCell, signCell, typeHash, writeU32LE, writeU64LE } from './cell-codec.js';
import { frameCell } from './serial-mesh.js';
import { createAction, getPublicKey, p2pkhScriptHexFromPubkey, rawTxHexFromCreateAction } from './metanet.js';
import { broadcastTxHex } from './arc.js';

const flag = (n: string, d?: string) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
function discoverPorts(): string[] {
  try { return readdirSync('/dev').filter((f) => /^cu\.usbmodem\d+$/.test(f)).map((f) => `/dev/${f}`).sort(); }
  catch { return []; }
}
const ports = discoverPorts();
const injectPort = flag('--inject-port') ?? ports[0] ?? '/dev/cu.usbmodem11201';
const watchPort  = flag('--watch') ?? ports[1] ?? ports[0] ?? '/dev/cu.usbmodem11301';
const baud       = flag('--baud', '115200')!;
const settleOnClose = process.argv.includes('--settle') || process.argv.includes('--real-payment');

const WALLET = new PrivateKey('0000000000000000000000000000000000000000000000000000000000000042', 16);
const OWNER  = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex')).subarray(0, 16);
const WALLET_PUBKEY = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex'));
const OPEN_TYPE       = typeHash('cellmesh.channel_open.v0');
const COMMITMENT_TYPE = typeHash('cellmesh.channel_commitment.v0');
const CLOSE_TYPE      = typeHash('cellmesh.channel_close.v0');
const CAPACITY = 1_000_000;
const EXPIRY_MS = 3_600_000n; // relative-to-open; far enough out to not expire mid-demo
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let channel: { id: Uint8Array; seq: number; deviceShare: number } | null = null;

// ── channel cell encoders (match cell_channel.c byte layouts) ───────
function encodeOpen(id: Uint8Array): Uint8Array {            // 61 bytes
  const b = new Uint8Array(61);
  b.set(id, 0); b.set(WALLET_PUBKEY, 16); writeU64LE(b, 49, BigInt(Date.now())); writeU32LE(b, 57, CAPACITY);
  return b;
}
function encodeCommitment(id: Uint8Array, seq: number, deviceShare: number): Uint8Array { // 68 bytes
  const b = new Uint8Array(68);
  b.set(id, 0); writeU32LE(b, 16, seq); writeU32LE(b, 20, deviceShare); writeU32LE(b, 24, 0);
  writeU64LE(b, 28, EXPIRY_MS); /* cert_hash[32] @36 left zero — not validated */
  return b;
}
function encodeClose(id: Uint8Array, finalSeq: number, finalDeviceShare: number): Uint8Array { // 24 bytes
  const b = new Uint8Array(24);
  b.set(id, 0); writeU32LE(b, 16, finalSeq); writeU32LE(b, 20, finalDeviceShare);
  return b;
}

async function inject(type: Uint8Array, payload: Uint8Array): Promise<void> {
  const cell = mintCell(type, payload, OWNER, BigInt(Date.now()));
  const sig = signCell(cell, WALLET);
  const frame = Buffer.from(frameCell(cell, sig));
  const fd = openSync(injectPort, 'w');
  try { for (let o = 0; o < frame.length; o += 256) { writeSync(fd, frame, o, Math.min(256, frame.length - o)); await sleep(2); } }
  finally { closeSync(fd); }
}

// ── watch the device's own metering decisions ───────────────────────
const readers: ChildProcessWithoutNullStreams[] = [];
function watch(port: string): void {
  spawnSync('stty', ['-f', port, baud, 'raw', '-echo'], { stdio: 'ignore' });
  const label = port.split('modem')[1] ?? port;
  const c = spawn('cat', [port]) as ChildProcessWithoutNullStreams;
  c.on('exit', (code) => { if (code && code !== 0) out(`\x1b[31m⚠ watch on ${label} exited (code ${code}) — port busy?\x1b[0m`); });
  let buf = '';
  c.stdout.on('data', (d: Buffer) => {
    buf += d.toString(); let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      const ln = buf.slice(0, i).replace(/\x1b\[[0-9;]*m/g, '').trim(); buf = buf.slice(i + 1);
      if (/CHANNEL OPEN/i.test(ln))            out(`\x1b[36m[${label}] ${ln}\x1b[0m`);
      else if (/CHANNEL COMMIT/i.test(ln))     out(`\x1b[32m[${label}] [PAID] ${ln}\x1b[0m`);
      else if (/METER EXHAUSTED/i.test(ln))    out(`\x1b[31m[${label}] [DARK] ${ln}\x1b[0m`);
      else if (/METER RE-AUTHORIZED/i.test(ln))out(`\x1b[32m[${label}] [LIT ] ${ln}\x1b[0m`);
      else if (/CHANNEL (CLOSED|EXPIRED)/i.test(ln)) out(`\x1b[90m[${label}] ${ln}\x1b[0m`);
    }
  });
  readers.push(c);
}

// ── actions ──────────────────────────────────────────────────────────
async function open(): Promise<void> {
  const id = crypto.getRandomValues(new Uint8Array(16));
  channel = { id, seq: 0, deviceShare: 0 };
  out(`\x1b[36m→ opening channel ${Buffer.from(id).toString('hex').slice(0, 12)}… (light still off until you pay)\x1b[0m`);
  await inject(OPEN_TYPE, encodeOpen(id));
}
async function pay(satsArg?: string): Promise<void> {
  if (!channel) return out('\x1b[31mno channel — run `open` first\x1b[0m');
  const sats = Math.max(1, parseInt(satsArg ?? '12', 10));
  channel.seq += 1; channel.deviceShare += sats;
  out(`\x1b[36m→ commitment seq=${channel.seq}, device_share=${channel.deviceShare} sats (+${sats}) — buys ~${(sats / 1.2).toFixed(0)}s of light\x1b[0m`);
  await inject(COMMITMENT_TYPE, encodeCommitment(channel.id, channel.seq, channel.deviceShare));
}
async function close(): Promise<void> {
  if (!channel) return out('\x1b[31mno channel — run `open` first\x1b[0m');
  const { id, seq, deviceShare } = channel;
  out(`\x1b[36m→ closing channel; final device_share=${deviceShare} sats\x1b[0m`);
  await inject(CLOSE_TYPE, encodeClose(id, seq, deviceShare));
  channel = null;
  if (!settleOnClose || deviceShare < 1) {
    if (!settleOnClose && deviceShare >= 1) {
      out('\x1b[33msettlement skipped by default; rerun with --settle to broadcast on mainnet\x1b[0m');
    }
    return;
  }
  // Settle the metered total on-chain: the operator collects device_share sats.
  try {
    out('settling device_share on-chain (Metanet + ARC)...');
    const opPubkey = await getPublicKey({ identityKey: true });
    const action = await createAction([{ lockingScript: p2pkhScriptHexFromPubkey(opPubkey), satoshis: deviceShare, outputDescription: 'semantos-edge metered-rental settlement' }],
                                      'semantos-edge: channel settlement');
    const rawHex = rawTxHexFromCreateAction(action);
    if (!rawHex) throw new Error('createAction returned no tx');
    const bc = await broadcastTxHex(rawHex);
    if (!bc.ok) throw new Error(bc.reason);
    out(`\x1b[32m*** SETTLED ${deviceShare} sats ON MAINNET *** ${bc.txid}\n    https://whatsonchain.com/tx/${bc.txid}\x1b[0m`);
  } catch (e) { out(`\x1b[33mclose recorded on-device; on-chain settle skipped: ${(e as Error).message}\x1b[0m`); }
}

// ── REPL ─────────────────────────────────────────────────────────────
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'meter> ' });
function out(s: string): void { readline.cursorTo(process.stdout, 0); readline.clearLine(process.stdout, 0); process.stdout.write(s + '\n'); rl.prompt(true); }
const HELP = `commands:
  open         open the channel (light off until paid)
  pay [sats]   commitment (+sats) → device meters; ~1.2 sats/s (pay 12 ≈ 10s lit)
  close        close${settleOnClose ? ' + settle device_share on-chain → txid' : ' (no mainnet settlement by default)'}
  help | quit
inject → ${injectPort.split('modem')[1] ?? injectPort}   meter board → ${watchPort.split('modem')[1] ?? watchPort}   ${settleOnClose ? '[MAINNET SETTLEMENT ENABLED]' : '[no settlement; pass --settle]'}`;
function cleanup(): void { for (const c of readers) c.kill(); rl.close(); process.exit(0); }
async function handle(line: string): Promise<void> {
  const a = line.trim().split(/\s+/); const cmd = a[0]?.toLowerCase();
  if (!cmd) return;
  try {
    if (cmd === 'help') return out(HELP);
    if (cmd === 'quit' || cmd === 'exit' || cmd === 'q') return cleanup();
    if (cmd === 'open') return await open();
    if (cmd === 'pay') return await pay(a[1]);
    if (cmd === 'close') return await close();
    out(`unknown: ${cmd} — type 'help'`);
  } catch (e) { out(`\x1b[31merror: ${(e as Error).message}\x1b[0m`); }
}

console.log(`metered rental — the device meters its own pay-per-second (${settleOnClose ? 'mainnet settlement enabled' : 'no mainnet settlement by default'})`);
console.log(`discovered ${ports.length} board(s): ${ports.join(', ') || '(none)'}`);
console.log(HELP);
watch(watchPort);
const runScript = flag('--run');
if (runScript) {
  (async () => { await sleep(800); for (const seg of runScript.split('|').map((s) => s.trim()).filter(Boolean)) { out(`\x1b[33m> ${seg}\x1b[0m`); await handle(seg); await sleep(Number(flag('--gap', '3000'))); } await sleep(1500); cleanup(); })();
} else { rl.prompt(); rl.on('line', (l) => handle(l).then(() => rl.prompt())); rl.on('SIGINT', cleanup); }
