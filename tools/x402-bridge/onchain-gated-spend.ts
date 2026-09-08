#!/usr/bin/env bun
/**
 * onchain-gated-spend.ts — the C6's verdict gates a REAL mainnet settlement.
 *
 * Flow:
 *   1. fund  — Metanet Desktop (localhost:3321) funds a P2PK UTXO locked to a
 *              fresh demo key. Broadcast via ARC → real funding txid.
 *   2. g/b   — build a REAL spend of that UTXO (P2PK + OP_CHECKSIG, BIP-143
 *              sighash), inject it as a cellmesh.scripted.v0 cell. Board A
 *              broadcasts; board B runs the spend through the cell-engine.
 *                g → engine ACCEPTs  → we release the tx to ARC → real txid
 *                b → one sig byte flipped → engine REJECTs → nothing broadcast
 *
 * The cell-engine's sighash is byte-identical to the canonical one miners
 * enforce (verified separately), so a C6-accepted spend is valid on mainnet.
 * The device is the gatekeeper: only spends it validates ever reach the chain.
 *
 *   # offline/default: prove the C6 validates a real-format spend, no money, no wallet
 *   bun onchain-gated-spend.ts --dry
 *
 *   # live (needs Metanet Desktop running + a few thousand spendable sats):
 *   bun onchain-gated-spend.ts --live --inject-port /dev/cu.usbmodem11201 \
 *                              --watch /dev/cu.usbmodem11301 --fund-sats 1200
 *   fund      → creates + broadcasts the P2PK UTXO
 *   b         → gated-reject a tampered spend (nothing settles)
 *   g         → gated-accept the real spend → prints the mainnet txid
 */

import readline from 'node:readline';
import { startSigner } from './signer.js';
import { DOMAIN } from '../domains.js';
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { openSync, writeSync, closeSync, existsSync, writeFileSync, readFileSync, unlinkSync, readdirSync } from 'node:fs';
import { PrivateKey, Transaction, Script, P2PKH, ECDSA, BigNumber } from '@bsv/sdk';
import {
  mintCell, signCell, typeHash, bip143Sighash, ecdsaDer,
  writeU16LE, writeU32LE, writeU64LE,
} from './cell-codec.js';
import { frameCell } from './serial-mesh.js';
import { createAction, rawTxHexFromCreateAction } from './metanet.js';
import { broadcastTxHex } from './arc.js';

// ── config ───────────────────────────────────────────────────────────
const flag = (n: string, d?: string) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const has  = (n: string) => process.argv.includes(n);
// Auto-discover the boards so a reset/replug (which renames the CDC device on
// native-USB C6s, e.g. 11201→21201) never breaks the demo. Flags still override.
function discoverPorts(): string[] {
  // Numeric-suffix usbmodem only — that's the ESP32 native-USB-CDC pattern;
  // excludes phones/other gadgets (e.g. cu.usbmodemRF8R…).
  try { return readdirSync('/dev').filter((f) => /^cu\.usbmodem\d+$/.test(f)).map((f) => `/dev/${f}`).sort(); }
  catch { return []; }
}
const ports = discoverPorts();
const injectPort = flag('--inject-port') ?? ports[0] ?? '/dev/cu.usbmodem11201';
const watchPort  = flag('--watch') ?? ports[1] ?? ports[0] ?? '/dev/cu.usbmodem11301';
const baud       = flag('--baud', '115200')!;
const fundSats   = parseInt(flag('--fund-sats', '1200')!, 10);
const feeSats    = parseInt(flag('--fee-sats', '300')!, 10);
const maxSats    = parseInt(flag('--max-sats', '5000')!, 10);   // hard safety cap
const LIVE       = has('--live') && !has('--dry');
const DRY        = !LIVE;

// Transport wallet (frame-auth): the key every board is provisioned to trust.
// Cell authority. The device verifies every signed cell against the trust
// anchor in its firmware, so this must BE that anchor — it is the fleet
// operator root by default. Nothing here spends on-chain, so there is no
// second key to keep apart.
const WALLET = startSigner().key;
const OWNER  = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex')).subarray(0, 16);
const SCRIPTED_TYPE = typeHash('cellmesh.scripted.v0');
const SIGHASH_ALL_FORKID = 0x41;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
let counter = 1;

if (fundSats > maxSats) { console.error(`fund-sats ${fundSats} exceeds safety cap ${maxSats}`); process.exit(1); }

// ── funding state: a spendable P2PK UTXO ────────────────────────────
interface Funding { tx: Transaction; vout: number; value: number; key: PrivateKey; }
let funding: Funding | null = null;
// Last successfully-built good spend's broadcaster — a manual `settle` fallback
// for when the serial watch misses the ACCEPT (e.g. the port was contended).
let lastGood: (() => Promise<string>) | null = null;

// Persist the funded UTXO (incl. spend key) so a crash/restart never strands
// real sats — on boot we resume it instead of funding a fresh one.
const STATE_FILE = `${import.meta.dir}/.gated-spend-state.json`;
function saveFunding(f: Funding): void {
  if (DRY) return;
  writeFileSync(STATE_FILE, JSON.stringify({ keyWif: f.key.toWif(), txHex: f.tx.toHex(), vout: f.vout, value: f.value }));
}
function loadFunding(): Funding | null {
  if (DRY || !existsSync(STATE_FILE)) return null;
  try {
    const s = JSON.parse(readFileSync(STATE_FILE, 'utf8'));
    return { tx: Transaction.fromHex(s.txHex), vout: s.vout, value: s.value, key: PrivateKey.fromWif(s.keyWif) };
  } catch { return null; }
}
function clearFunding(): void { funding = null; lastGood = null; try { if (existsSync(STATE_FILE)) unlinkSync(STATE_FILE); } catch {} }

function p2pkLockOf(key: PrivateKey): Uint8Array {
  const pk = new Uint8Array(Buffer.from(key.toPublicKey().toString(), 'hex')); // 33B
  return new Uint8Array([0x21, ...pk, 0xac]);                                   // PUSH33 <pk> OP_CHECKSIG
}

// ── build a REAL spend of the funded UTXO ───────────────────────────
// Returns the scripted-cell frame for the C6 AND a broadcaster for the
// fully-signed tx (only to be called on the engine's ACCEPT).
function buildGatedSpend(f: Funding, tamper: boolean): { frame: Buffer; broadcast: () => Promise<string> } {
  const lock = p2pkLockOf(f.key);
  const outValue = f.value - feeSats;
  if (outValue < 1) throw new Error(`fund ${f.value} < fee ${feeSats}`);
  const outScript = new P2PKH().lock(f.key.toAddress()); // return change to the demo key

  // The spend tx (empty scriptSig template — what the engine parses).
  const spend = new Transaction();
  spend.addInput({ sourceTransaction: f.tx, sourceOutputIndex: f.vout, unlockingScript: new Script(), sequence: 0xffffffff });
  spend.addOutput({ satoshis: outValue, lockingScript: outScript });
  spend.version = 1; spend.lockTime = 0;
  const cellTx = new Uint8Array(spend.toBinary()); // input scriptSig empty here

  // BIP-143 sighash (== canonical) over the spend, signed by the UTXO key.
  const prevTxidLE = new Uint8Array(Buffer.from(f.tx.id('hex'), 'hex')).reverse();
  const sighash = bip143Sighash(
    1,
    [{ prevTxid: prevTxidLE, prevVout: f.vout, sequence: 0xffffffff }],
    [{ value: BigInt(outValue), script: new Uint8Array(outScript.toBinary()) }],
    0, 0, lock, BigInt(f.value), SIGHASH_ALL_FORKID,
  );
  const sigObj = ECDSA.sign(new BigNumber(Array.from(sighash) as unknown as number[]), f.key, true);
  const der = ecdsaDer(sigObj);
  const scriptSig = new Uint8Array(der.length + 1);
  scriptSig.set(der, 0);
  scriptSig[der.length] = SIGHASH_ALL_FORKID;
  if (tamper) scriptSig[scriptSig.length - 2] ^= 0x01; // corrupt the s-value → OP_CHECKSIG fails in the VM

  const unlock = new Uint8Array(1 + scriptSig.length);
  unlock[0] = scriptSig.length;
  unlock.set(scriptSig, 1);

  // scripted.v0 payload: u16 lock_len|lock|u16 unlock_len|unlock|u16 tx_len|tx|u32 idx|u64 value|u32 ctr
  const payload = new Uint8Array(2 + lock.length + 2 + unlock.length + 2 + cellTx.length + 4 + 8 + 4);
  let o = 0;
  writeU16LE(payload, o, lock.length);   o += 2; payload.set(lock, o);   o += lock.length;
  writeU16LE(payload, o, unlock.length); o += 2; payload.set(unlock, o); o += unlock.length;
  writeU16LE(payload, o, cellTx.length); o += 2; payload.set(cellTx, o); o += cellTx.length;
  writeU32LE(payload, o, 0);             o += 4;            // input_idx
  writeU64LE(payload, o, BigInt(f.value)); o += 8;          // input_value
  writeU32LE(payload, o, counter++);     o += 4;            // uniqueness

  const cell = mintCell(SCRIPTED_TYPE, payload, OWNER, BigInt(Date.now()), DOMAIN.meshScript);
  const sig = signCell(cell, WALLET);                      // frame auth (trusted wallet)
  const frame = Buffer.from(frameCell(cell, sig));

  const broadcast = async (): Promise<string> => {
    // Attach the real unlock and ship the fully-signed tx (BEEF carries the
    // funding ancestry so ARC can validate the input).
    spend.inputs[0].unlockingScript = Script.fromBinary(Array.from(unlock));
    const res = await broadcastTxHex(spend.toHexBEEF());
    if (!res.ok) throw new Error(`ARC rejected: ${res.reason}`);
    return res.txid;
  };
  return { frame, broadcast };
}

// ── inject (one paced USB write) ────────────────────────────────────
async function injectFrame(frame: Buffer): Promise<void> {
  const fd = openSync(injectPort, 'w');
  try { for (let o = 0; o < frame.length; o += 256) { writeSync(fd, frame, o, Math.min(256, frame.length - o)); await sleep(2); } }
  finally { closeSync(fd); }
}

// ── watch board B's verdict; resolve accept/reject ──────────────────
const readers: ChildProcessWithoutNullStreams[] = [];
let pendingVerdict: ((accepted: boolean) => void) | null = null;
function watch(port: string): void {
  spawnSync('stty', ['-f', port, baud, 'raw', '-echo'], { stdio: 'ignore' });
  const label = port.split('modem')[1] ?? port;
  const c = spawn('cat', [port]) as ChildProcessWithoutNullStreams;
  c.on('exit', (code) => {
    if (code && code !== 0) out(`\x1b[31m⚠ watch on ${label} exited (code ${code}) — port busy? verdicts won't be seen; use \`settle\` after a visible ACCEPT.\x1b[0m`);
  });
  let buf = '';
  c.stdout.on('data', (d: Buffer) => {
    buf += d.toString();
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      const ln = buf.slice(0, i).replace(/\x1b\[[0-9;]*m/g, '').trim();
      buf = buf.slice(i + 1);
      if (/SCRIPT ACCEPTED/i.test(ln))       { out(`\x1b[32m[${label}] [OK]  ${ln}\x1b[0m`); pendingVerdict?.(true);  pendingVerdict = null; }
      else if (/scripted.*REJECTED/i.test(ln)) { out(`\x1b[31m[${label}] [NO]  ${ln}\x1b[0m`); pendingVerdict?.(false); pendingVerdict = null; }
    }
  });
  readers.push(c);
}
function awaitVerdict(ms = 8000): Promise<boolean> {
  return new Promise((resolve) => {
    pendingVerdict = resolve;
    setTimeout(() => { if (pendingVerdict) { pendingVerdict = null; resolve(false); } }, ms);
  });
}

// ── actions ──────────────────────────────────────────────────────────
async function doFund(): Promise<void> {
  if (DRY) {
    // Fabricate a spendable-looking UTXO (random txid). The engine validates
    // the spend regardless; we just never broadcast in --dry.
    const key = PrivateKey.fromRandom();
    const lock = p2pkLockOf(key);
    const fake = new Transaction();
    fake.addInput({ sourceTXID: '11'.repeat(32), sourceOutputIndex: 0, unlockingScript: new Script(), sequence: 0xffffffff });
    fake.addOutput({ satoshis: fundSats, lockingScript: Script.fromBinary(Array.from(lock)) });
    funding = { tx: fake, vout: 0, value: fundSats, key };
    out(`\x1b[33m[dry] fabricated P2PK UTXO ${fake.id('hex')}:0 = ${fundSats} sats (NOT on chain)\x1b[0m`);
    return;
  }
  const key = PrivateKey.fromRandom();
  const lockHex = Buffer.from(p2pkLockOf(key)).toString('hex');
  out(`funding a P2PK UTXO (${fundSats} sats) via Metanet Desktop...`);
  const action = await createAction([{ lockingScript: lockHex, satoshis: fundSats, outputDescription: 'semantos-edge C6-gated spend UTXO' }],
                                    'semantos-edge: fund C6-gated spend demo');
  const rawHex = rawTxHexFromCreateAction(action);
  if (!rawHex) throw new Error('createAction returned no tx');
  const tx = (() => { try { return Transaction.fromHexBEEF(rawHex); } catch { return Transaction.fromHex(rawHex); } })();
  // Locate our P2PK output.
  const wantHex = Buffer.from(p2pkLockOf(key)).toString('hex');
  const vout = tx.outputs.findIndex((o) => o.lockingScript.toHex() === wantHex);
  if (vout < 0) throw new Error('funded tx has no matching P2PK output');
  const bc = await broadcastTxHex(action.beef ? rawHex : tx.toHex());
  if (!bc.ok) throw new Error(`funding broadcast failed: ${bc.reason}`);
  funding = { tx, vout, value: fundSats, key };
  saveFunding(funding); // crash-safe: resumable on restart
  out(`\x1b[32mfunded: ${bc.txid}:${vout} = ${fundSats} sats → https://whatsonchain.com/tx/${bc.txid}\x1b[0m`);
  out(`(give it a few seconds to propagate before spending)`);
}

async function doSpend(kind: 'good' | 'bad'): Promise<void> {
  if (!funding) return out('\x1b[31mno funded UTXO — run `fund` first\x1b[0m');
  const { frame, broadcast } = buildGatedSpend(funding, kind === 'bad');
  if (kind === 'good') lastGood = broadcast; // arm the manual `settle` fallback
  out(kind === 'good'
    ? '\x1b[36m→ injecting a REAL spend; on the engine’s ACCEPT it settles on mainnet\x1b[0m'
    : '\x1b[36m→ injecting a TAMPERED spend; the engine should REJECT it and nothing settles\x1b[0m');
  await injectFrame(frame);
  const accepted = await awaitVerdict();
  if (!accepted) {
    out('\x1b[33mdid not see the engine’s verdict on serial.\x1b[0m');
    if (kind === 'good') out('\x1b[33mIf board B’s LED lit / it logged SCRIPT ACCEPTED, type `settle` to broadcast.\x1b[0m');
    return;
  }
  if (kind === 'bad') return; // rejected as intended
  if (DRY) { out('\x1b[33m[dry] engine ACCEPTED — would broadcast here (skipped, no real UTXO)\x1b[0m'); return; }
  await settle();
}

// Broadcast the last good spend (called on ACCEPT, or manually via `settle`).
async function settle(): Promise<void> {
  if (!lastGood) return out('\x1b[31mnothing to settle — run `g` first\x1b[0m');
  if (DRY) { out('\x1b[33m[dry] would broadcast the last good spend (skipped)\x1b[0m'); return; }
  out('releasing the tx to ARC...');
  try {
    const txid = await lastGood();
    clearFunding(); // UTXO consumed
    out(`\x1b[32m*** SETTLED ON MAINNET *** ${txid}\n    https://whatsonchain.com/tx/${txid}\x1b[0m`);
  } catch (e) { out(`\x1b[31mbroadcast failed: ${(e as Error).message}\x1b[0m`); }
}

// ── REPL ─────────────────────────────────────────────────────────────
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: 'chain> ' });
function out(s: string): void { readline.cursorTo(process.stdout, 0); readline.clearLine(process.stdout, 0); process.stdout.write(s + '\n'); rl.prompt(true); }
const HELP = `commands:
  fund        ${DRY ? 'fabricate a P2PK UTXO (no chain)' : 'fund + broadcast a real P2PK UTXO via Metanet+ARC'}
  g | good    inject a REAL spend → engine ACCEPT → ${DRY ? '(would) ' : ''}settle on mainnet
  b | bad     inject a TAMPERED spend → engine REJECT → nothing settles
  settle      broadcast the last good spend (fallback if the watch missed ACCEPT)
  help | quit
inject → ${injectPort.split('modem')[1] ?? injectPort}   watch → ${watchPort.split('modem')[1] ?? watchPort}   ${DRY ? '[DRY: no broadcast; pass --live for mainnet]' : '[LIVE MAINNET]'}`;
function cleanup(): void { for (const c of readers) c.kill(); rl.close(); process.exit(0); }
async function handle(line: string): Promise<void> {
  const cmd = line.trim().toLowerCase();
  if (!cmd) return;
  try {
    if (cmd === 'help') return out(HELP);
    if (cmd === 'quit' || cmd === 'exit' || cmd === 'q') return cleanup();
    if (cmd === 'fund') return await doFund();
    if (cmd === 'g' || cmd === 'good') return await doSpend('good');
    if (cmd === 'b' || cmd === 'bad')  return await doSpend('bad');
    if (cmd === 'settle') return await settle();
    out(`unknown: ${cmd} — type 'help'`);
  } catch (e) { out(`\x1b[31merror: ${(e as Error).message}\x1b[0m`); }
}

// ── boot ─────────────────────────────────────────────────────────────
console.log(`onchain gated-spend — ${DRY ? 'DRY (no broadcast; pass --live for mainnet)' : 'LIVE MAINNET'}`);
console.log(`discovered ${ports.length} board(s): ${ports.join(', ') || '(none)'}`);
if (ports.length < 2 && !DRY) console.log('\x1b[33m⚠ fewer than 2 boards found — pass --inject-port/--watch if needed\x1b[0m');
console.log(HELP);
watch(watchPort);
// Resume a previously-funded UTXO so a crash/restart never strands real sats.
funding = loadFunding();
if (funding) console.log(`\x1b[32mresumed funded UTXO ${funding.tx.id('hex')}:${funding.vout} = ${funding.value} sats — spend with \`g\`\x1b[0m`);
const runScript = flag('--run');
if (runScript) {
  (async () => {
    await sleep(800);
    for (const seg of runScript.split('|').map((s) => s.trim()).filter(Boolean)) { out(`\x1b[33m> ${seg}\x1b[0m`); await handle(seg); await sleep(2500); }
    await sleep(1500); cleanup();
  })();
} else {
  rl.prompt();
  rl.on('line', (l) => handle(l).then(() => rl.prompt()));
  rl.on('SIGINT', cleanup);
}
