/**
 * codec.ts — the temperature logger's wire, host side.
 *
 * The batch and ack payloads, the cell they ride in, and the gateway's serial
 * lines, as docs/TEMP-LOGGER.md specifies them. The decoders mirror the Zig
 * reference in components/cell-mesh-zig/src/cell_templog.zig rule for rule;
 * codec.test.ts pins both against the same hand-written golden bytes.
 *
 * Pure: no I/O, no clock.
 */

import {
  CELL_SIZE,
  PAYLOAD_SIZE,
  readU16LE,
  readU32LE,
  readU64LE,
  sha256,
  typeHash,
  writeU16LE,
  writeU32LE,
} from '../x402-bridge/cell-codec.js';
import { crc32 } from '../x402-bridge/serial-mesh.js';

export { crc32 };

// ── Identifiers and sizes ────────────────────────────────────────────

export const TYPE_BATCH = typeHash('templog.batch.v0');
export const TYPE_ACK = typeHash('templog.ack.v0');

export const BATCH_VERSION = 0;
export const BATCH_HEADER_SIZE = 40;
export const SAMPLE_SIZE = 8;
/** 91: as many samples as fit a 768-byte payload after the header. */
export const BATCH_MAX_SAMPLES = (PAYLOAD_SIZE - BATCH_HEADER_SIZE) / SAMPLE_SIZE;

export const ACK_VERSION = 0;
export const ACK_SIZE = 16;

/** centi-°C carried when there is no valid reading. */
export const TEMP_INVALID = -32768;

/** Sample flag bits. */
export const SF = {
  /** outside the safe band, or the engine could not say */
  POLICY_REJECT: 0x01,
  /** the engine failed to evaluate, or disagreed with the node's native check (always with POLICY_REJECT) */
  VM_ERROR: 0x02,
  /** no valid reading; centi is -32768 */
  SENSOR_ERROR: 0x04,
  /** the probe returned its 85 °C power-on value on every retry; recorded as no reading */
  POR_SUSPECT: 0x08,
  /** the flash record for this seq was unreadable; a placeholder */
  RECORD_LOST: 0x10,
} as const;

// Cell header layout (components/cell-mesh/include/cell_wire.h).
const MAGIC = [0xdeadbeef, 0xcafebabe, 0x13371337, 0x42424242];
const OFF_LINEARITY = 16;
const OFF_VERSION = 20;
const OFF_FLAGS = 24;
const OFF_TYPE_HASH = 30;
const OFF_OWNER_ID = 62;
const OFF_TIMESTAMP = 78;
const OFF_PAYLOAD_TOTAL = 90;
const OFF_DOMAIN_PAYLOAD_ROOT = 224;
const OFF_PAYLOAD = 256;

// ── Types ────────────────────────────────────────────────────────────

/** What a sender chooses for a batch header; version and count follow from the samples. */
export interface BatchHeaderFields {
  firstSeq: number;
  bootId: number;
  bootNow: number;
  uptimeNowS: number;
  bootEpochS: number;
  lostThrough: number;
  sampleIntervalS: number;
  policyMinCenti: number;
  policyMaxCenti: number;
  logId: number;
  /** reserved, 0 */
  flags?: number;
}

export interface BatchHeader extends Omit<BatchHeaderFields, 'flags'> {
  version: number;
  flags: number;
  count: number;
}

export interface SampleFields {
  uptimeS: number;
  /** centi-°C, or TEMP_INVALID */
  centiC: number;
  flags: number;
}

export interface BatchSample extends SampleFields {
  seq: number;
}

export interface DecodedBatch {
  header: BatchHeader;
  samples: BatchSample[];
}

export interface Ack {
  targetMac: string;
  ackedThrough: number;
  hostUnixS: number;
}

export interface ParsedCell {
  kind: 'batch' | 'ack' | 'other';
  typeHash: Uint8Array;
  /** the sender's MAC: the first 6 bytes of owner_id */
  ownerMac: string;
  version: number;
  linearity: number;
  domainFlags: number;
  timestampMs: bigint;
  payloadTotal: number;
  /** all 768 payload bytes */
  payload: Uint8Array;
  payloadRoot: Uint8Array;
  /** domain_payload_root is the SHA-256 of the 768-byte payload, as the spec says it must be */
  payloadRootOk: boolean;
}

export interface TlLine {
  mac: string;
  cell: Uint8Array;
}

export interface AkLine {
  mac: string;
  ackedThrough: number;
  hostUnixS: number;
}

export type LineClass = ({ kind: 'tl' } & TlLine) | { kind: 'bad'; reason: string } | { kind: 'other' };

// ── Small helpers ────────────────────────────────────────────────────

function checkInt(name: string, v: number, min: number, max: number): number {
  if (!Number.isInteger(v) || v < min || v > max) throw new RangeError(`${name} must be an integer in ${min}..${max}, got ${v}`);
  return v;
}
const u32 = (name: string, v: number) => checkInt(name, v, 0, 0xffffffff);
const i16 = (name: string, v: number) => checkInt(name, v, -0x8000, 0x7fff);
const u8 = (name: string, v: number) => checkInt(name, v, 0, 0xff);

function readI16LE(b: Uint8Array, o: number): number {
  return (readU16LE(b, o) << 16) >> 16;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const hex8 = (v: number) => (v >>> 0).toString(16).padStart(8, '0');

// ── MACs ─────────────────────────────────────────────────────────────

/** `aa:bb:cc:dd:ee:ff` or `aabbccddeeff`, either case. Throws on anything else. */
export function macToBytes(mac: string): Uint8Array {
  let bare: string;
  if (/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i.test(mac)) bare = mac.replace(/:/g, '');
  else if (/^[0-9a-f]{12}$/i.test(mac)) bare = mac;
  else throw new Error(`not a MAC address: ${JSON.stringify(mac)}`);
  return Uint8Array.from(Buffer.from(bare, 'hex'));
}

/** Six bytes as `aa:bb:cc:dd:ee:ff`. */
export function macToString(bytes: Uint8Array): string {
  if (bytes.length !== 6) throw new Error(`a MAC is 6 bytes, got ${bytes.length}`);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(':');
}

// ── Cells ────────────────────────────────────────────────────────────

/** A 1024-byte cell's header fields and payload, or null if the bytes are not a cell. */
export function parseCell(bytes: Uint8Array): ParsedCell | null {
  if (bytes.length !== CELL_SIZE) return null;
  for (let i = 0; i < MAGIC.length; i++) if (readU32LE(bytes, i * 4) !== MAGIC[i]) return null;
  const type = bytes.slice(OFF_TYPE_HASH, OFF_TYPE_HASH + 32);
  const payload = bytes.slice(OFF_PAYLOAD, OFF_PAYLOAD + PAYLOAD_SIZE);
  const payloadRoot = bytes.slice(OFF_DOMAIN_PAYLOAD_ROOT, OFF_DOMAIN_PAYLOAD_ROOT + 32);
  return {
    kind: sameBytes(type, TYPE_BATCH) ? 'batch' : sameBytes(type, TYPE_ACK) ? 'ack' : 'other',
    typeHash: type,
    ownerMac: macToString(bytes.subarray(OFF_OWNER_ID, OFF_OWNER_ID + 6)),
    version: readU32LE(bytes, OFF_VERSION),
    linearity: readU32LE(bytes, OFF_LINEARITY),
    domainFlags: readU32LE(bytes, OFF_FLAGS),
    timestampMs: readU64LE(bytes, OFF_TIMESTAMP),
    payloadTotal: readU32LE(bytes, OFF_PAYLOAD_TOTAL),
    payload,
    payloadRoot,
    payloadRootOk: sameBytes(sha256(payload), payloadRoot),
  };
}

// ── Batch payload (templog.batch.v0) ─────────────────────────────────

/**
 * The batch in `p`, or null. The same rules as cm_tlog_batch_decode_header:
 * version 0, count at most 91, and `p` long enough for the header and
 * count samples. Sample i is seq first_seq + i (u32 wrap, as in Zig).
 */
export function decodeBatch(p: Uint8Array): DecodedBatch | null {
  if (p.length < BATCH_HEADER_SIZE) return null;
  if (p[0] !== BATCH_VERSION) return null;
  const count = readU16LE(p, 2);
  if (count > BATCH_MAX_SAMPLES) return null;
  if (p.length < BATCH_HEADER_SIZE + count * SAMPLE_SIZE) return null;
  const header: BatchHeader = {
    version: p[0],
    flags: p[1],
    count,
    firstSeq: readU32LE(p, 4),
    bootId: readU32LE(p, 8),
    bootNow: readU32LE(p, 12),
    uptimeNowS: readU32LE(p, 16),
    bootEpochS: readU32LE(p, 20),
    lostThrough: readU32LE(p, 24),
    sampleIntervalS: readU32LE(p, 28),
    policyMinCenti: readI16LE(p, 32),
    policyMaxCenti: readI16LE(p, 34),
    logId: readU32LE(p, 36),
  };
  const samples: BatchSample[] = [];
  for (let i = 0; i < count; i++) {
    const o = BATCH_HEADER_SIZE + i * SAMPLE_SIZE;
    samples.push({
      seq: (header.firstSeq + i) >>> 0,
      uptimeS: readU32LE(p, o),
      centiC: readI16LE(p, o + 4),
      flags: p[o + 6],
    });
  }
  return { header, samples };
}

/**
 * The used bytes of a batch payload: the 40-byte header and 8 bytes per
 * sample. Sample i is seq firstSeq + i, all from the header's boot. Throws on
 * more than 91 samples or a field that does not fit its type.
 */
export function encodeBatch(h: BatchHeaderFields, samples: SampleFields[]): Uint8Array {
  if (samples.length > BATCH_MAX_SAMPLES) throw new RangeError(`a batch holds at most ${BATCH_MAX_SAMPLES} samples, got ${samples.length}`);
  const p = new Uint8Array(BATCH_HEADER_SIZE + samples.length * SAMPLE_SIZE);
  p[0] = BATCH_VERSION;
  p[1] = u8('flags', h.flags ?? 0);
  writeU16LE(p, 2, samples.length);
  writeU32LE(p, 4, u32('firstSeq', h.firstSeq));
  writeU32LE(p, 8, u32('bootId', h.bootId));
  writeU32LE(p, 12, u32('bootNow', h.bootNow));
  writeU32LE(p, 16, u32('uptimeNowS', h.uptimeNowS));
  writeU32LE(p, 20, u32('bootEpochS', h.bootEpochS));
  writeU32LE(p, 24, u32('lostThrough', h.lostThrough));
  writeU32LE(p, 28, u32('sampleIntervalS', h.sampleIntervalS));
  writeU16LE(p, 32, i16('policyMinCenti', h.policyMinCenti) & 0xffff);
  writeU16LE(p, 34, i16('policyMaxCenti', h.policyMaxCenti) & 0xffff);
  writeU32LE(p, 36, u32('logId', h.logId));
  samples.forEach((s, i) => {
    const o = BATCH_HEADER_SIZE + i * SAMPLE_SIZE;
    writeU32LE(p, o, u32('uptimeS', s.uptimeS));
    writeU16LE(p, o + 4, i16('centiC', s.centiC) & 0xffff);
    p[o + 6] = u8('sample flags', s.flags);
    p[o + 7] = 0;
  });
  return p;
}

// ── Ack payload (templog.ack.v0) ─────────────────────────────────────

/** The 16-byte ack. A cell zero-pads it to 768, as cm_tlog_ack_encode does. */
export function encodeAck(targetMac: string, ackedThrough: number, hostUnixS: number): Uint8Array {
  const p = new Uint8Array(ACK_SIZE);
  p[0] = ACK_VERSION;
  p.set(macToBytes(targetMac), 2);
  writeU32LE(p, 8, u32('ackedThrough', ackedThrough));
  writeU32LE(p, 12, u32('hostUnixS', hostUnixS));
  return p;
}

/** The ack in `p`, or null: the same rules as cm_tlog_ack_decode. */
export function decodeAck(p: Uint8Array): Ack | null {
  if (p.length < ACK_SIZE) return null;
  if (p[0] !== ACK_VERSION) return null;
  return {
    targetMac: macToString(p.subarray(2, 8)),
    ackedThrough: readU32LE(p, 8),
    hostUnixS: readU32LE(p, 12),
  };
}

// ── Serial lines ─────────────────────────────────────────────────────
//
// Gateway to host:  TL <aa:bb:cc:dd:ee:ff> <2048 hex: the cell> <8 hex: CRC-32 of the cell>
// Host to gateway:  AK <aabbccddeeff> <acked_through> <host_unix_s>

const ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]/g;
const MAC_RE = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i;
const HEX_RE = /^[0-9a-f]+$/i;

function checkTlFrame(frame: string): LineClass {
  const bad = (reason: string): LineClass => ({ kind: 'bad', reason });
  const fields = frame.split(/\s+/);
  if (fields.length !== 4) return bad(`expected 4 fields, got ${fields.length}`);
  const [, mac, cellHex, crcHex] = fields;
  if (!MAC_RE.test(mac)) return bad(`bad MAC ${JSON.stringify(mac.slice(0, 24))}`);
  if (cellHex.length !== CELL_SIZE * 2) return bad(`cell is ${cellHex.length} hex chars, not ${CELL_SIZE * 2}`);
  if (!HEX_RE.test(cellHex)) return bad('cell has a non-hex character');
  if (crcHex.length !== 8 || !HEX_RE.test(crcHex)) return bad(`CRC field ${JSON.stringify(crcHex.slice(0, 16))} is not 8 hex digits`);
  const cell = Uint8Array.from(Buffer.from(cellHex, 'hex'));
  const got = crc32(cell);
  if (got !== parseInt(crcHex, 16) >>> 0) return bad(`CRC mismatch: line says ${crcHex.toLowerCase()}, cell gives ${hex8(got)}`);
  return { kind: 'tl', mac: mac.toLowerCase(), cell };
}

/**
 * What a serial line is: a TL frame whose CRC holds, a TL line that fails
 * its checks (worth logging), or anything else (ESP-IDF logs; ignore).
 *
 * The gateway writes TL lines and its own logs to one USB console from two
 * tasks, so a whole frame can follow a log fragment on the same line. That
 * frame is still taken — its CRC is what vouches for it — but a failed
 * check mid-line counts as noise, not as a bad TL line.
 */
export function classifyLine(raw: string): LineClass {
  const line = raw.replace(ANSI_RE, '').trim();
  if (line === 'TL' || line.startsWith('TL ')) return checkTlFrame(line);
  const at = line.lastIndexOf('TL ');
  if (at > 0) {
    const tail = checkTlFrame(line.slice(at));
    if (tail.kind === 'tl') return tail;
  }
  return { kind: 'other' };
}

/** A TL line's MAC and cell, or null for a bad TL line or any other line. */
export function parseTlLine(line: string): TlLine | null {
  const c = classifyLine(line);
  return c.kind === 'tl' ? { mac: c.mac, cell: c.cell } : null;
}

/** The TL line a gateway prints for `cell` heard from `mac`, newline included. */
export function formatTlLine(mac: string, cell: Uint8Array): string {
  if (cell.length !== CELL_SIZE) throw new Error(`a cell is ${CELL_SIZE} bytes, got ${cell.length}`);
  return `TL ${macToString(macToBytes(mac))} ${toHex(cell)} ${hex8(crc32(cell))}\n`;
}

/** `AK aabbccddeeff <acked_through> <host_unix_s>\n` — what the gateway turns into an ack cell. */
export function formatAkLine(mac: string, ackedThrough: number, hostUnixS: number): string {
  const bare = toHex(macToBytes(mac));
  return `AK ${bare} ${u32('ackedThrough', ackedThrough)} ${u32('hostUnixS', hostUnixS)}\n`;
}

/** An AK line read back, as the gateway reads it; null if it is not one. */
export function parseAkLine(line: string): AkLine | null {
  const m = /^AK ([0-9a-f]{12}) (\d{1,10}) (\d{1,10})$/i.exec(line.trim());
  if (!m) return null;
  const ackedThrough = Number(m[2]);
  const hostUnixS = Number(m[3]);
  if (ackedThrough > 0xffffffff || hostUnixS > 0xffffffff) return null;
  return { mac: macToString(macToBytes(m[1])), ackedThrough, hostUnixS };
}
