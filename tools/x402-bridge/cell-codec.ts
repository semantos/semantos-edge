/**
 * cell-codec.ts — the bytes the x402 bridge needs to speak the cell-mesh.
 *
 * A focused reproduction of the canonical 1024-byte cell wire + the
 * actuator_offer.v0 / actuator_activate.v0 payloads, mirroring
 * tools/sign-cell-deck.ts and docs/
 * x402-over-cells.md byte-for-byte. The firmware (cell_wire.c +
 * main.c actuator handling) parses exactly these.
 *
 * The bridge is a host process — it holds the wallet key and signs the
 * actuator unlock on the consumer's behalf, once the consumer has paid
 * it over x402. (No keys on the C6; the bridge is not the C6.)
 */

import { PrivateKey, ECDSA, BigNumber } from '@bsv/sdk';
import { createHash } from 'node:crypto';
import { SIGHASH_ALL_FORKID } from './sighash.js';

// ── Constants matching cell_wire.h ───────────────────────────────────
export const CELL_SIZE = 1024;
export const PAYLOAD_SIZE = 768;
const CELL_VERSION = 2;
const MAGIC = [0xdeadbeef, 0xcafebabe, 0x13371337, 0x42424242];

const OFF_LINEARITY = 16;
const OFF_VERSION = 20;
const OFF_TYPE_HASH = 30;
const OFF_OWNER_ID = 62;
const OFF_TIMESTAMP = 78;
const OFF_PAYLOAD_TOTAL = 90;
const OFF_DOMAIN_PAYLOAD_ROOT = 224;
const OFF_PAYLOAD = 256;
const LINEARITY_AFFINE = 2;

// ── little-endian writers/readers ────────────────────────────────────
export function writeU16LE(b: Uint8Array, o: number, v: number) {
  b[o] = v & 0xff;
  b[o + 1] = (v >>> 8) & 0xff;
}
export function writeU32LE(b: Uint8Array, o: number, v: number) {
  b[o] = v & 0xff;
  b[o + 1] = (v >>> 8) & 0xff;
  b[o + 2] = (v >>> 16) & 0xff;
  b[o + 3] = (v >>> 24) & 0xff;
}
export function writeU64LE(b: Uint8Array, o: number, v: bigint) {
  for (let i = 0; i < 8; i++) b[o + i] = Number((v >> BigInt(i * 8)) & 0xffn);
}
export function readU16LE(b: Uint8Array, o: number): number {
  return b[o] | (b[o + 1] << 8);
}
export function readU32LE(b: Uint8Array, o: number): number {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}
export function readU64LE(b: Uint8Array, o: number): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(b[o + i]) << BigInt(i * 8);
  return v;
}

// ── hashing / type hashes ────────────────────────────────────────────
export function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}
function dsha256(bytes: Uint8Array): Uint8Array {
  return sha256(sha256(bytes));
}
export function typeHash(name: string): Uint8Array {
  return sha256(new TextEncoder().encode(name));
}

export const ACTUATOR_OFFER_TYPE = typeHash('cellmesh.actuator_offer.v0');
export const ACTUATOR_ACTIVATE_TYPE = typeHash('cellmesh.actuator_activate.v0');

// ── cell mint + sign ─────────────────────────────────────────────────
export function mintCell(typeHashBytes: Uint8Array, payload: Uint8Array, ownerId: Uint8Array, timestampMs: bigint): Uint8Array {
  if (payload.length > PAYLOAD_SIZE) throw new Error('payload too big');
  const cell = new Uint8Array(CELL_SIZE);
  for (let i = 0; i < 4; i++) writeU32LE(cell, i * 4, MAGIC[i]);
  writeU32LE(cell, OFF_LINEARITY, LINEARITY_AFFINE);
  writeU32LE(cell, OFF_VERSION, CELL_VERSION);
  cell.set(typeHashBytes, OFF_TYPE_HASH);
  cell.set(ownerId.subarray(0, 16), OFF_OWNER_ID);
  writeU64LE(cell, OFF_TIMESTAMP, timestampMs);
  cell.set(payload, OFF_PAYLOAD);
  writeU32LE(cell, OFF_PAYLOAD_TOTAL, payload.length);
  const region = cell.subarray(OFF_PAYLOAD, OFF_PAYLOAD + PAYLOAD_SIZE);
  cell.set(sha256(region), OFF_DOMAIN_PAYLOAD_ROOT);
  return cell;
}

/** Raw r||s, 32+32 big-endian — the frame-level signature the radio verifies. */
export function signCell(cell: Uint8Array, walletKey: PrivateKey): Uint8Array {
  const sig = walletKey.sign(Array.from(cell));
  const r = (sig.r as unknown as { toArray: (e: string, n: number) => number[] }).toArray('be', 32);
  const s = (sig.s as unknown as { toArray: (e: string, n: number) => number[] }).toArray('be', 32);
  return new Uint8Array([...r, ...s]);
}

// ── BIP-143 sighash (BSV FORKID variant) — mirrors sighash.zig ───────
interface TxInputView { prevTxid: Uint8Array; prevVout: number; sequence: number; }
interface TxOutputView { value: bigint; script: Uint8Array; }

export function bip143Sighash(
  txVersion: number,
  inputs: TxInputView[],
  outputs: TxOutputView[],
  locktime: number,
  inputIdx: number,
  scriptCode: Uint8Array,
  inputValue: bigint,
  sighashType: number,
): Uint8Array {
  const op = new Uint8Array(36 * inputs.length);
  for (let i = 0; i < inputs.length; i++) {
    op.set(inputs[i].prevTxid, 36 * i);
    writeU32LE(op, 36 * i + 32, inputs[i].prevVout);
  }
  const hashPrevouts = dsha256(op);
  const sb = new Uint8Array(4 * inputs.length);
  for (let i = 0; i < inputs.length; i++) writeU32LE(sb, 4 * i, inputs[i].sequence);
  const hashSequence = dsha256(sb);
  const outBytes: number[] = [];
  for (const o of outputs) {
    const vbuf = new Uint8Array(8);
    writeU64LE(vbuf, 0, o.value);
    outBytes.push(...vbuf, o.script.length, ...o.script);
  }
  const hashOutputs = dsha256(new Uint8Array(outBytes));
  const out: number[] = [];
  const ver = new Uint8Array(4); writeU32LE(ver, 0, txVersion); out.push(...ver);
  out.push(...hashPrevouts, ...hashSequence, ...inputs[inputIdx].prevTxid);
  const voutBuf = new Uint8Array(4); writeU32LE(voutBuf, 0, inputs[inputIdx].prevVout); out.push(...voutBuf);
  out.push(scriptCode.length, ...scriptCode);
  const valBuf = new Uint8Array(8); writeU64LE(valBuf, 0, inputValue); out.push(...valBuf);
  const seqBuf = new Uint8Array(4); writeU32LE(seqBuf, 0, inputs[inputIdx].sequence); out.push(...seqBuf);
  out.push(...hashOutputs);
  const ltBuf = new Uint8Array(4); writeU32LE(ltBuf, 0, locktime); out.push(...ltBuf);
  const htBuf = new Uint8Array(4); writeU32LE(htBuf, 0, sighashType); out.push(...htBuf);
  return dsha256(new Uint8Array(out));
}

export function ecdsaDer(sig: { r: unknown; s: unknown }): Uint8Array {
  const r = (sig.r as { toArray: (e: string) => number[] }).toArray('be');
  const s = (sig.s as { toArray: (e: string) => number[] }).toArray('be');
  const rDer = r[0] & 0x80 ? [0, ...r] : r;
  const sDer = s[0] & 0x80 ? [0, ...s] : s;
  const body = [0x02, rDer.length, ...rDer, 0x02, sDer.length, ...sDer];
  return new Uint8Array([0x30, body.length, ...body]);
}

// ── actuator_offer.v0 ────────────────────────────────────────────────
export interface ActuatorOffer {
  version: number;
  costSats: number;
  durationMs: number;
  lockScript: Uint8Array;
  txTemplate: Uint8Array;
  inputIdx: number;
  inputValue: bigint;
  offerId: Uint8Array; // 16 bytes
}

/** Decode an actuator_offer.v0 payload (what the bridge "heard" from the device). */
export function decodeActuatorOffer(payload: Uint8Array): ActuatorOffer {
  let o = 0;
  const version = readU32LE(payload, o); o += 4;
  const costSats = readU32LE(payload, o); o += 4;
  const durationMs = readU32LE(payload, o); o += 4;
  const lockLen = readU16LE(payload, o); o += 2;
  const lockScript = payload.slice(o, o + lockLen); o += lockLen;
  const txLen = readU16LE(payload, o); o += 2;
  const txTemplate = payload.slice(o, o + txLen); o += txLen;
  const inputIdx = readU32LE(payload, o); o += 4;
  const inputValue = readU64LE(payload, o); o += 8;
  const offerId = payload.slice(o, o + 16); o += 16;
  return { version, costSats, durationMs, lockScript, txTemplate, inputIdx, inputValue, offerId };
}

/**
 * Build the actuator_activate.v0 payload (and full signed cell) that pays
 * the offer: ECDSA-sign the offer's BIP-143 sighash, wrap as a PUSH(N)
 * unlock, lay out per the x402-over-cells wire. `counter` gives per-cell
 * uniqueness for the device's cell-hash dedup.
 */
export function buildActuatorActivate(
  offer: ActuatorOffer,
  walletKey: PrivateKey,
  ownerId: Uint8Array,
  timestampMs: bigint,
  counter: number,
  sighashType = SIGHASH_ALL_FORKID,
): { payload: Uint8Array; cell: Uint8Array; sig: Uint8Array } {
  // The offer's tx_template is the tx the sighash is computed over. We
  // reconstruct its single input/output view to match the device + deck.
  const sighash = bip143Sighash(
    1,
    [{ prevTxid: new Uint8Array(32), prevVout: offer.inputIdx, sequence: 0xffffffff }],
    [{ value: 10000n, script: new Uint8Array([0x51]) }], // OP_1 output, value 10000 (matches RENTABLE_TX)
    0,
    offer.inputIdx,
    offer.lockScript,
    offer.inputValue,
    sighashType,
  );
  const sigObj = ECDSA.sign(new BigNumber(Array.from(sighash) as unknown as number[]), walletKey, true);
  const der = ecdsaDer(sigObj as unknown as { r: unknown; s: unknown });
  const sigPlusHashtype = new Uint8Array(der.length + 1);
  sigPlusHashtype.set(der, 0);
  sigPlusHashtype[der.length] = sighashType;
  const unlock = new Uint8Array(1 + sigPlusHashtype.length);
  unlock[0] = sigPlusHashtype.length; // PUSH N
  unlock.set(sigPlusHashtype, 1);

  const lockSec = 2 + offer.lockScript.length;
  const unlockSec = 2 + unlock.length;
  const txSec = 2 + offer.txTemplate.length;
  const tail = 4 + 8 + 16 + 4;
  const payload = new Uint8Array(lockSec + unlockSec + txSec + tail);
  let off = 0;
  writeU16LE(payload, off, offer.lockScript.length); off += 2;
  payload.set(offer.lockScript, off); off += offer.lockScript.length;
  writeU16LE(payload, off, unlock.length); off += 2;
  payload.set(unlock, off); off += unlock.length;
  writeU16LE(payload, off, offer.txTemplate.length); off += 2;
  payload.set(offer.txTemplate, off); off += offer.txTemplate.length;
  writeU32LE(payload, off, offer.inputIdx); off += 4;
  writeU64LE(payload, off, offer.inputValue); off += 8;
  payload.set(offer.offerId, off); off += 16;
  writeU32LE(payload, off, counter); off += 4;

  const cell = mintCell(ACTUATOR_ACTIVATE_TYPE, payload, ownerId, timestampMs);
  const sig = signCell(cell, walletKey);
  return { payload, cell, sig };
}

/** Decode an actuator_activate.v0 payload — for tests / round-trip checks. */
export function decodeActuatorActivate(payload: Uint8Array): {
  lockScript: Uint8Array;
  unlockScript: Uint8Array;
  txBytes: Uint8Array;
  inputIdx: number;
  inputValue: bigint;
  offerId: Uint8Array;
  counter: number;
} {
  let o = 0;
  const lockLen = readU16LE(payload, o); o += 2;
  const lockScript = payload.slice(o, o + lockLen); o += lockLen;
  const unlockLen = readU16LE(payload, o); o += 2;
  const unlockScript = payload.slice(o, o + unlockLen); o += unlockLen;
  const txLen = readU16LE(payload, o); o += 2;
  const txBytes = payload.slice(o, o + txLen); o += txLen;
  const inputIdx = readU32LE(payload, o); o += 4;
  const inputValue = readU64LE(payload, o); o += 8;
  const offerId = payload.slice(o, o + 16); o += 16;
  const counter = readU32LE(payload, o); o += 4;
  return { lockScript, unlockScript, txBytes, inputIdx, inputValue, offerId, counter };
}
