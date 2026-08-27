#!/usr/bin/env bun
/**
 * actuator-demo.ts — the COUPLED demo: the device drives its own output.
 *
 * A valid `cellmesh.actuator_activate.v0` cell (operator-signed, carrying a
 * P2PK + OP_CHECKSIG authorization) is injected; board A broadcasts it; board B
 * runs it through the cell-engine and — on ACCEPT — turns on **its own actuator**
 * (the onboard LED, the stand-in for a lock / charger / valve) for the rental
 * window. The laptop does NOTHING after the verdict: the device is the actor.
 *
 *   a | activate   valid authorization → device ACTUATES its own output (5 s)
 *   t | tamper     one sig byte flipped → device REFUSES → output stays off
 *   pay [sats]     (optional, requires --real-payment) real on-chain payment to the operator via
 *                  Metanet+ARC → real txid; the next `a` commits to that txid,
 *                  so the activation is bound to a settled payment (x402 shape).
 *
 * This is the honest "how it actually works": chain settles the payment (a
 * gateway/agent job — the device has no internet); the device validates the
 * authorization offline, holds no key, and physically acts. Not decoupled —
 * the consequence lives on the device.
 *
 *   bun actuator-demo.ts                  # auto-discovers the two boards, no mainnet payment
 *   bun actuator-demo.ts --real-payment   # enable Metanet+ARC payment command
 */

import readline from 'node:readline';
import { DOMAIN } from '../domains.js';
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { openSync, writeSync, closeSync, readdirSync } from 'node:fs';
import { PrivateKey, ECDSA, BigNumber } from '@bsv/sdk';
import {
  mintCell, signCell, typeHash, bip143Sighash, ecdsaDer,
  writeU16LE, writeU32LE, writeU64LE,
} from './cell-codec.js';
import { frameCell } from './serial-mesh.js';
import { createAction, getPublicKey, p2pkhScriptHexFromPubkey, rawTxHexFromCreateAction } from './metanet.js';
import { broadcastTxHex } from './arc.js';

// ── config ───────────────────────────────────────────────────────────
const flag = (n: string, d?: string) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
function discoverPorts(): string[] {
  try { return readdirSync('/dev').filter((f) => /^cu\.usbmodem\d+$/.test(f)).map((f) => `/dev/${f}`).sort(); }
  catch { return []; }
}
const ports = discoverPorts();
const injectPort = flag('--inject-port') ?? ports[0] ?? '/dev/cu.usbmodem11201';
const watchPort  = flag('--watch') ?? ports[1] ?? ports[0] ?? '/dev/cu.usbmodem11301';
const baud       = flag('--baud', '115200')!;
const realPayment = process.argv.includes('--real-payment');

// Operator wallet: the key every board is provisioned to trust. The operator
// signs the activation (frame auth) + the P2PK authorization script.
const WALLET = new PrivateKey('0000000000000000000000000000000000000000000000000000000000000042', 16);
const OWNER  = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex')).subarray(0, 16);
const WALLET_PUBKEY = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex'));
const ACTUATOR_ACTIVATE_TYPE = typeHash('cellmesh.actuator_activate.v0');
const SIGHASH_ALL_FORKID = 0x41;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
let counter = 1;
let paidTxid: string | null = null; // last on-chain payment, bound into the next activation

// ── build an actuator_activate.v0 (operator-signed P2PK authorization) ──
function buildActivation(tamper: boolean): Buffer {
  const lock = new Uint8Array([0x21, ...WALLET_PUBKEY, 0xac]); // PUSH33 <pk> OP_CHECKSIG
  const PREV = new Uint8Array(32);
  const tx = new Uint8Array([
    0x01,0x00,0x00,0x00, 0x01, ...PREV, 0x00,0x00,0x00,0x00,
    0x00, 0xff,0xff,0xff,0xff, 0x01,
    0x10,0x27,0x00,0x00,0x00,0x00,0x00,0x00, 0x01,0x51, 0x00,0x00,0x00,0x00,
  ]);
  const inputValue = 50000n, inputIdx = 0;
  const sighash = bip143Sighash(1,
    [{ prevTxid: PREV, prevVout: 0, sequence: 0xffffffff }],
    [{ value: 10000n, script: new Uint8Array([0x51]) }],
    0, inputIdx, lock, inputValue, SIGHASH_ALL_FORKID);
  const sigObj = ECDSA.sign(new BigNumber(Array.from(sighash) as unknown as number[]), WALLET, true);
  const der = ecdsaDer(sigObj);
  const scriptSig = new Uint8Array(der.length + 1);
  scriptSig.set(der, 0); scriptSig[der.length] = SIGHASH_ALL_FORKID;
  if (tamper) scriptSig[scriptSig.length - 2] ^= 0x01; // OP_CHECKSIG fails in the VM
  const unlock = new Uint8Array(1 + scriptSig.length);
  unlock[0] = scriptSig.length; unlock.set(scriptSig, 1);

  // offerId (16B): bind this activation to the settled payment, if any.
  const offerId = new Uint8Array(16);
  if (paidTxid) offerId.set(new Uint8Array(Buffer.from(paidTxid, 'hex')).subarray(0, 16), 0);

  const payload = new Uint8Array(2 + lock.length + 2 + unlock.length + 2 + tx.length + 4 + 8 + 16 + 4);
  let o = 0;
  writeU16LE(payload, o, lock.length);   o += 2; payload.set(lock, o);   o += lock.length;
  writeU16LE(payload, o, unlock.length); o += 2; payload.set(unlock, o); o += unlock.length;
  writeU16LE(payload, o, tx.length);     o += 2; payload.set(tx, o);     o += tx.length;
  writeU32LE(payload, o, inputIdx);      o += 4;
  writeU64LE(payload, o, inputValue);    o += 8;
  payload.set(offerId, o);               o += 16;
  writeU32LE(payload, o, counter++);     o += 4;

  const cell = mintCell(ACTUATOR_ACTIVATE_TYPE, payload, OWNER, BigInt(Date.now()), DOMAIN.meshControl);
  const sig = signCell(cell, WALLET); // operator frame-auth (covers the txid binding)
  return Buffer.from(frameCell(cell, sig));
}

async function injectFrame(frame: Buffer): Promise<void> {
  const fd = openSync(injectPort, 'w');
  try { for (let o = 0; o < frame.length; o += 256) { writeSync(fd, frame, o, Math.min(256, frame.length - o)); await sleep(2); } }
  finally { closeSync(fd); }
}

// ── watch the rentable board's own actuator decision ────────────────
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
      if (/ACTUATOR ACTIVATED/i.test(ln))   out(`\x1b[32m[${label}] [ON]   ${ln}\x1b[0m`);
      else if (/ACTUATOR DEACTIVATED/i.test(ln)) out(`\x1b[90m[${label}] [off]  ${ln}\x1b[0m`);
      else if (/scripted.*REJECTED/i.test(ln))   out(`\x1b[31m[${label}] [NO]   ${ln}\x1b[0m`);
    }
  });
  readers.push(c);
}

// ── pay: a real on-chain payment to the operator (the agent paying) ──
async function pay(satsArg?: string): Promise<void> {
  if (!realPayment) {
    return out('\x1b[33mpayment disabled by default; restart with --real-payment to broadcast on mainnet\x1b[0m');
  }
  const sats = Math.max(1, parseInt(satsArg ?? '1000', 10));
  out(`agent paying the operator ${sats} sats on-chain (Metanet + ARC)...`);
  const opPubkey = await getPublicKey({ identityKey: true });
  const scriptHex = p2pkhScriptHexFromPubkey(opPubkey);
  const action = await createAction([{ lockingScript: scriptHex, satoshis: sats, outputDescription: 'semantos-edge actuator rental payment' }],
                                    'semantos-edge: x402 actuator rental');
  const rawHex = rawTxHexFromCreateAction(action);
  if (!rawHex) throw new Error('createAction returned no tx');
  const bc = await broadcastTxHex(rawHex);
  if (!bc.ok) throw new Error(`payment broadcast failed: ${bc.reason}`);
  paidTxid = bc.txid;
  out(`\x1b[32mpaid: ${bc.txid} → https://whatsonchain.com/tx/${bc.txid}\x1b[0m`);
  out(`the next \`a\` activation is bound to this payment (operator signs over the txid).`);
}

async function activate(tamper: boolean): Promise<void> {
  out(tamper
    ? '\x1b[36m→ injecting a TAMPERED authorization — the device should REFUSE to actuate\x1b[0m'
    : `\x1b[36m→ injecting a valid authorization${paidTxid ? ` (bound to payment ${paidTxid.slice(0, 12)}…)` : ''} — the device actuates its OWN output\x1b[0m`);
  await injectFrame(buildActivation(tamper));
}

// ── REPL ─────────────────────────────────────────────────────────────
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'rent> ' });
function out(s: string): void { readline.cursorTo(process.stdout, 0); readline.clearLine(process.stdout, 0); process.stdout.write(s + '\n'); rl.prompt(true); }
const HELP = `commands:
  a | activate   valid authorization → device ACTUATES its own output (5s)
  t | tamper     tampered sig → device REFUSES (output stays off)
  pay [sats]     ${realPayment ? 'real on-chain payment to the operator → txid; binds next `a`' : 'disabled by default; restart with --real-payment'}
  help | quit
inject → ${injectPort.split('modem')[1] ?? injectPort}   actuator board → ${watchPort.split('modem')[1] ?? watchPort}   ${realPayment ? '[MAINNET PAYMENT ENABLED]' : '[no payment; pass --real-payment]'}`;
function cleanup(): void { for (const c of readers) c.kill(); rl.close(); process.exit(0); }
async function handle(line: string): Promise<void> {
  const a = line.trim().split(/\s+/); const cmd = a[0]?.toLowerCase();
  if (!cmd) return;
  try {
    if (cmd === 'help') return out(HELP);
    if (cmd === 'quit' || cmd === 'exit' || cmd === 'q') return cleanup();
    if (cmd === 'a' || cmd === 'activate') return await activate(false);
    if (cmd === 't' || cmd === 'tamper')   return await activate(true);
    if (cmd === 'pay') return await pay(a[1]);
    out(`unknown: ${cmd} — type 'help'`);
  } catch (e) { out(`\x1b[31merror: ${(e as Error).message}\x1b[0m`); }
}

console.log(`actuator demo — device drives its own output (${realPayment ? 'mainnet payment enabled' : 'no mainnet payment by default'})`);
console.log(`discovered ${ports.length} board(s): ${ports.join(', ') || '(none)'}`);
console.log(HELP);
watch(watchPort);
const runScript = flag('--run');
if (runScript) {
  (async () => { await sleep(800); for (const seg of runScript.split('|').map((s) => s.trim()).filter(Boolean)) { out(`\x1b[33m> ${seg}\x1b[0m`); await handle(seg); await sleep(6500); } await sleep(1000); cleanup(); })();
} else { rl.prompt(); rl.on('line', (l) => handle(l).then(() => rl.prompt())); rl.on('SIGINT', cleanup); }
