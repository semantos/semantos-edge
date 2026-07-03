#!/usr/bin/env bun
/**
 * sign-bitpiggy-cell-deck.ts — pre-sign a minimal BitPiggy chore-claim deck.
 *
 * This mirrors sign-cell-deck.ts but emits only the cells needed by the first
 * bitpiggy_mesh milestone: child/device chore claim cells carried over the
 * existing ESP32 cell-mesh substrate.
 */

import { PrivateKey } from '@bsv/sdk';
import { writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';

const CELL_SIZE = 1024;
const PAYLOAD_SIZE = 768;
const CELL_VERSION = 2;
const MAGIC = [0xDEADBEEF, 0xCAFEBABE, 0x13371337, 0x42424242];

const OFF_LINEARITY = 16;
const OFF_VERSION = 20;
const OFF_TYPE_HASH = 30;
const OFF_OWNER_ID = 62;
const OFF_TIMESTAMP = 78;
const OFF_PAYLOAD_TOTAL = 90;
const OFF_DOMAIN_PAYLOAD_ROOT = 224;
const OFF_PAYLOAD = 256;

const LINEARITY_AFFINE = 2;
const DECK_MAGIC = 0xDECDCDCD;
const DECK_VERSION = 1;
const ENTRY_PREFIX = 8;
const SIG_SIZE = 64;
const ENTRY_SIZE = ENTRY_PREFIX + CELL_SIZE + SIG_SIZE;
const KIND_BITPIGGY_CHORE_CLAIM = 32;

// Demo wallet keypair. This is intentionally the same demo key as the mesh
// deck so existing firmware wallet-pubkey verification continues to work.
const WALLET_PRIVKEY_HEX = '0000000000000000000000000000000000000000000000000000000000000042';
const WALLET_KEY = new PrivateKey(WALLET_PRIVKEY_HEX, 16);
const WALLET_PUBKEY = new Uint8Array(Buffer.from(WALLET_KEY.toPublicKey().toString(), 'hex'));
const WALLET_OWNER_ID = WALLET_PUBKEY.subarray(0, 16);

interface DeviceSpec {
  name: string;
  child: string;
  chore: string;
  mac: number[];
}

const DEFAULT_DEVICE_MACS: ReadonlyArray<DeviceSpec> = [
  { name: 'A', child: 'Theo', chore: 'Bins out', mac: [0x58, 0xe6, 0xc5, 0x1a, 0x8b, 0x28] },
  { name: 'B', child: 'Lily', chore: 'Tidy toys', mac: [0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0x54] },
  { name: 'C', child: 'Theo', chore: 'Dishwasher', mac: [0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0xf8] },
];

const CLAIMS_PER_DEVICE = 8;
const BITPIGGY_CHORE_CLAIM_TYPE = typeHash('bitpiggy.chore_claim.v0');
const PROVISIONING_TIMESTAMP_MS = BigInt(Date.now());

function usage(): never {
  console.error(`usage:
  bun esp32-hackkit/tools/sign-bitpiggy-cell-deck.ts [out.bin]
      [--mac 50:78:7d:2c:b9:c0] [--name LilyGO] [--child Theo] [--chore "Bins out"]
      [--device A,Theo,"Bins out",58:e6:c5:1a:8b:28] ...

env:
  BITPIGGY_DEVICE_MAC, BITPIGGY_DEVICE_NAME, BITPIGGY_CHILD, BITPIGGY_CHORE`);
  process.exit(1);
}

function parseMac(text: string): number[] {
  const hex = text.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (hex.length !== 12) throw new Error(`bad MAC "${text}"`);
  const out: number[] = [];
  for (let i = 0; i < 12; i += 2) out.push(Number.parseInt(hex.slice(i, i + 2), 16));
  return out;
}

function parseDeviceSpec(spec: string): DeviceSpec {
  const parts = spec.split(',').map((p) => p.trim()).filter(Boolean);
  if (parts.length !== 4) {
    throw new Error(`bad --device "${spec}" (want name,child,chore,mac)`);
  }
  return { name: parts[0], child: parts[1], chore: parts[2], mac: parseMac(parts[3]) };
}

function readArgs(): { outPath: string; devices: DeviceSpec[] } {
  const args = process.argv.slice(2);
  let outPath = 'esp32-hackkit/examples/bitpiggy_mesh/main/embed/cell_deck.bin';
  let outPathSet = false;
  let mac = process.env.BITPIGGY_DEVICE_MAC;
  let name = process.env.BITPIGGY_DEVICE_NAME ?? 'LilyGO';
  let child = process.env.BITPIGGY_CHILD ?? 'Theo';
  let chore = process.env.BITPIGGY_CHORE ?? 'Bins out';
  const deviceSpecs: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const value = (flag: string) => {
      if (a === flag) return args[++i];
      if (a.startsWith(flag + '=')) return a.slice(flag.length + 1);
      return undefined;
    };
    const device = value('--device');
    if (device !== undefined) { deviceSpecs.push(device); continue; }
    const m = value('--mac');
    if (m !== undefined) { mac = m; continue; }
    const n = value('--name');
    if (n !== undefined) { name = n; continue; }
    const c = value('--child');
    if (c !== undefined) { child = c; continue; }
    const ch = value('--chore');
    if (ch !== undefined) { chore = ch; continue; }
    if (a === '--help' || a === '-h') usage();
    if (!a.startsWith('-') && !outPathSet) {
      outPath = a;
      outPathSet = true;
      continue;
    }
    throw new Error(`unknown argument "${a}"`);
  }

  if (deviceSpecs.length > 0) {
    return { outPath, devices: deviceSpecs.map(parseDeviceSpec) };
  }
  if (mac) {
    return { outPath, devices: [{ name, child, chore, mac: parseMac(mac) }] };
  }
  return { outPath, devices: [...DEFAULT_DEVICE_MACS] };
}

const ARGS = readArgs();
const DEVICE_MACS = ARGS.devices;

function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}
function typeHash(name: string): Uint8Array {
  return sha256(new TextEncoder().encode(name));
}
function writeU32LE(buf: Uint8Array, off: number, v: number) {
  buf[off] = v & 0xff;
  buf[off + 1] = (v >>> 8) & 0xff;
  buf[off + 2] = (v >>> 16) & 0xff;
  buf[off + 3] = (v >>> 24) & 0xff;
}
function writeU64LE(buf: Uint8Array, off: number, v: bigint) {
  for (let i = 0; i < 8; i++) buf[off + i] = Number((v >> BigInt(i * 8)) & 0xffn);
}
function id16(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(label)).subarray(0, 16);
}

function mintCell(typeHashBytes: Uint8Array, payload: Uint8Array): Uint8Array {
  const cell = new Uint8Array(CELL_SIZE);
  for (let i = 0; i < 4; i++) writeU32LE(cell, i * 4, MAGIC[i]);
  writeU32LE(cell, OFF_LINEARITY, LINEARITY_AFFINE);
  writeU32LE(cell, OFF_VERSION, CELL_VERSION);
  cell.set(typeHashBytes, OFF_TYPE_HASH);
  cell.set(WALLET_OWNER_ID, OFF_OWNER_ID);
  writeU64LE(cell, OFF_TIMESTAMP, PROVISIONING_TIMESTAMP_MS);
  if (payload.length > PAYLOAD_SIZE) throw new Error('payload too big');
  cell.set(payload, OFF_PAYLOAD);
  writeU32LE(cell, OFF_PAYLOAD_TOTAL, payload.length);
  cell.set(sha256(cell.subarray(OFF_PAYLOAD, OFF_PAYLOAD + PAYLOAD_SIZE)), OFF_DOMAIN_PAYLOAD_ROOT);
  return cell;
}

function signCell(cell: Uint8Array): Uint8Array {
  const sig = WALLET_KEY.sign(Array.from(cell));
  const r = (sig.r as any).toArray('be', 32);
  const s = (sig.s as any).toArray('be', 32);
  return new Uint8Array([...r, ...s]);
}

function buildEntry(deviceMac: number[], kind: number, cell: Uint8Array, sig: Uint8Array): Uint8Array {
  const e = new Uint8Array(ENTRY_SIZE);
  e.set(deviceMac, 0);
  e[6] = kind;
  e[7] = 0;
  e.set(cell, ENTRY_PREFIX);
  e.set(sig, ENTRY_PREFIX + CELL_SIZE);
  return e;
}

function encodeClaim(dev: { name: string; child: string; chore: string }, counter: number): Uint8Array {
  // Matches cartridges/bitpiggy/brain/bitpiggy_cell_specs.zig ChoreClaim.
  const p = new Uint8Array(128);
  p.set(id16(`claim:${dev.name}:${counter}`), 0);
  p.set(id16(`assignment:${dev.child}:${dev.chore}`), 16);
  p.set(id16('household:whitfield'), 32);
  p.set(id16(`child:${dev.child}`), 48);
  p.set(id16(`device:${dev.name}`), 64);
  writeU64LE(p, 80, PROVISIONING_TIMESTAMP_MS + BigInt(counter * 60_000));
  // proof_ref zero for first loop.
  writeU32LE(p, 120, counter);
  writeU32LE(p, 124, 0);
  return p;
}

function generateDeck(): Uint8Array {
  const entries: Uint8Array[] = [];
  for (const dev of DEVICE_MACS) {
    for (let i = 1; i <= CLAIMS_PER_DEVICE; i++) {
      const cell = mintCell(BITPIGGY_CHORE_CLAIM_TYPE, encodeClaim(dev, i));
      entries.push(buildEntry(dev.mac, KIND_BITPIGGY_CHORE_CLAIM, cell, signCell(cell)));
    }
  }

  const out = new Uint8Array(16 + entries.length * ENTRY_SIZE);
  writeU32LE(out, 0, DECK_MAGIC);
  writeU32LE(out, 4, DECK_VERSION);
  writeU32LE(out, 8, entries.length);
  writeU32LE(out, 12, 0);
  let off = 16;
  for (const e of entries) {
    out.set(e, off);
    off += ENTRY_SIZE;
  }
  return out;
}

const outPath = ARGS.outPath;
const deck = generateDeck();
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, deck);
console.log(`wrote ${deck.length} bytes to ${outPath}`);
console.log(`wallet pubkey: ${Buffer.from(WALLET_PUBKEY).toString('hex')}`);
console.log(`entries: ${DEVICE_MACS.length * CLAIMS_PER_DEVICE}, kind=${KIND_BITPIGGY_CHORE_CLAIM}`);
for (const d of DEVICE_MACS) {
  console.log(`device ${d.name}: ${d.child} · ${d.chore} · ${d.mac.map((b) => b.toString(16).padStart(2, '0')).join(':')}`);
}
