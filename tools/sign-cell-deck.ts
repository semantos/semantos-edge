#!/usr/bin/env bun
/**
 * sign-cell-deck.ts — pre-sign a deck of mesh_demo cells, off-device.
 *
 * Aligns the mesh_demo with the project rule that IoT devices verify and
 * act while wallets sign. The wallet (this script) signs every heartbeat /
 * tap / hot-swap-rule cell at provisioning time; mesh_demo embeds the
 * resulting deck in flash and the device just pops + broadcasts pre-signed
 * cells. The XIAOs hold NO private key at runtime — they're
 * verifier-and-broadcaster only.
 *
 * Demo wallet keypair is committed below (it's the WALLET's identity,
 * controlled by the operator who runs this script). Replace with a
 * real wallet integration when the demo grows up.
 *
 * Usage:
 *   bun tools/sign-cell-deck.ts \
 *     [examples/mesh_demo/main/embed/cell_deck.bin]
 *
 * The generated deck embeds three sub-decks (one per device MAC). The
 * firmware filters by its own MAC at boot.
 */

import { PrivateKey, ECDSA, BigNumber } from '@bsv/sdk';
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// ── Constants matching cell_wire.h ───────────────────────────────────
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

// ── Deck wire format ─────────────────────────────────────────────────
//
//   HEADER (16 bytes, LE):
//     u32 magic = 0xDECDCDCD
//     u32 version = 1
//     u32 entry_count
//     u32 reserved = 0
//
//   ENTRIES (entry_count × 1096 bytes each):
//     u8  device_mac[6]
//     u8  kind                  // 1=heartbeat, 2=tap, 3=hot_swap_rule
//     u8  reserved (= 0)
//     u8  cell[1024]            // owner_id is wallet, NOT device
//     u8  sig[64]               // ECDSA r||s, 32+32 big-endian
//
const DECK_MAGIC = 0xDECDCDCD;
const DECK_VERSION = 1;
const ENTRY_PREFIX = 8;
const SIG_SIZE = 64;
const ENTRY_SIZE = ENTRY_PREFIX + CELL_SIZE + SIG_SIZE;

const KIND_HEARTBEAT          = 1;
const KIND_TAP                = 2;
const KIND_HOT_SWAP_RULE      = 3;
const KIND_CONFIRMED_TAP      = 4;
const KIND_CHANNEL_OPEN       = 5;
const KIND_CHANNEL_COMMITMENT = 6;
const KIND_CHANNEL_CLOSE      = 7;
const KIND_SCRIPTED           = 8;
const KIND_ACTUATOR_OFFER     = 9;
const KIND_ACTUATOR_ACTIVATE  = 10;

// ── Demo wallet keypair ──────────────────────────────────────────────
// Committed deliberately. This IS the wallet's identity — it's not
// supposed to be on the device. Rotate when moving past demo mode.
const WALLET_PRIVKEY_HEX = '0000000000000000000000000000000000000000000000000000000000000042';

// ── Devices: hardcoded MACs (matching the forward-visual demo) ────────
const DEVICE_MACS: ReadonlyArray<{ name: string; mac: number[] }> = [
  { name: 'A', mac: [0x58, 0xe6, 0xc5, 0x1a, 0x8b, 0x28] },
  { name: 'B', mac: [0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0x54] },
  { name: 'C', mac: [0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0xf8] },
];

const HEARTBEATS_PER_DEVICE     = 15;
const TAPS_PER_DEVICE           = 10;
// Rule fires confirmed_tap on every received TAP — with 3 devices each
// emitting 10 taps, every device receives ~20 taps → wants ~20 acks to
// emit. Pre-sign generously per device.
const CONFIRMED_TAPS_PER_DEVICE = 25;
// Scripted cells live on device A only. We rotate a fixed sequence so
// the demo cycles through accept/reject types deterministically.
//
//   slot 0: OP_TRUE                      → ACCEPT (baseline, opcount=1)
//   slot 1: HASH-LOCKED correct unlock   → ACCEPT (opcount=5)
//   slot 2: HASH-LOCKED wrong unlock     → REJECT (opcount=4)
//   slot 3: P2PK OP_CHECKSIG (wallet-signed, real BIP-143 sighash)
//                                        → ACCEPT (opcount=3)
//   slot 4: HASH-LOCKED accept
//   slot 5: HASH-LOCKED reject
const SCRIPTED_PER_DEVICE       = 6;
// Rentable-device demo (x402-over-cells). Device C broadcasts offers
// advertising "I rent for N sats / D ms per activation"; device A plays
// the wallet, broadcasting activations that pay the price.
const OFFERS_PER_DEVICE_C       = 8;
const ACTIVATIONS_PER_DEVICE_A  = 8;
// Each activation extends the LED-on window by ACTUATOR_DURATION_MS.
// Activations broadcast every ~3.5 s → with 5 s duration, LED stays
// continuously on across overlapping activations and goes off ~5 s
// after the last activation.
const ACTUATOR_DURATION_MS      = 5000;
const ACTUATOR_COST_SATS        = 100;

// ── Helpers ──────────────────────────────────────────────────────────
function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}
function typeHash(name: string): Uint8Array {
  return sha256(new TextEncoder().encode(name));
}
function writeU16LE(buf: Uint8Array, off: number, v: number) {
  buf[off] = v & 0xff;
  buf[off + 1] = (v >>> 8) & 0xff;
}
function writeU32LE(buf: Uint8Array, off: number, v: number) {
  buf[off]     = v & 0xff;
  buf[off + 1] = (v >>> 8) & 0xff;
  buf[off + 2] = (v >>> 16) & 0xff;
  buf[off + 3] = (v >>> 24) & 0xff;
}
function writeU64LE(buf: Uint8Array, off: number, v: bigint) {
  for (let i = 0; i < 8; i++) buf[off + i] = Number((v >> BigInt(i * 8)) & 0xffn);
}

// ── Type hashes ──────────────────────────────────────────────────────
const HEARTBEAT_TYPE          = typeHash('cellmesh.heartbeat.v0');
const TAP_TYPE                = typeHash('cellmesh.tap.v0');
const RULE_TYPE               = typeHash('cellmesh.rule.v0');
const CONFIRMED_TAP_TYPE      = typeHash('cellmesh.confirmed_tap.v0');
const CHANNEL_OPEN_TYPE       = typeHash('cellmesh.channel_open.v0');
const CHANNEL_COMMITMENT_TYPE = typeHash('cellmesh.channel_commitment.v0');
const CHANNEL_CLOSE_TYPE      = typeHash('cellmesh.channel_close.v0');
const SCRIPTED_TYPE           = typeHash('cellmesh.scripted.v0');
const ACTUATOR_OFFER_TYPE     = typeHash('cellmesh.actuator_offer.v0');
const ACTUATOR_ACTIVATE_TYPE  = typeHash('cellmesh.actuator_activate.v0');

// ── Wallet key ───────────────────────────────────────────────────────
const WALLET_KEY = new PrivateKey(WALLET_PRIVKEY_HEX, 16);
const WALLET_PUBKEY_COMP_HEX = WALLET_KEY.toPublicKey().toString();  // 66-char compressed hex
const WALLET_PUBKEY = new Uint8Array(Buffer.from(WALLET_PUBKEY_COMP_HEX, 'hex'));
// Use first 16 bytes of compressed pubkey as wallet's owner-id tag.
const WALLET_OWNER_ID = WALLET_PUBKEY.subarray(0, 16);

const PROVISIONING_TIMESTAMP_MS = BigInt(Date.now());

// ── Cell builder ─────────────────────────────────────────────────────
function mintCell(typeHashBytes: Uint8Array, payload: Uint8Array): Uint8Array {
  const cell = new Uint8Array(CELL_SIZE);
  for (let i = 0; i < 4; i++) writeU32LE(cell, i * 4, MAGIC[i]);
  writeU32LE(cell, OFF_LINEARITY, LINEARITY_AFFINE);
  writeU32LE(cell, OFF_VERSION, CELL_VERSION);
  cell.set(typeHashBytes, OFF_TYPE_HASH);
  cell.set(WALLET_OWNER_ID, OFF_OWNER_ID);                  // wallet id, not device
  writeU64LE(cell, OFF_TIMESTAMP, PROVISIONING_TIMESTAMP_MS);
  if (payload.length > PAYLOAD_SIZE) throw new Error('payload too big');
  cell.set(payload, OFF_PAYLOAD);
  writeU32LE(cell, OFF_PAYLOAD_TOTAL, payload.length);
  const payloadRegion = cell.subarray(OFF_PAYLOAD, OFF_PAYLOAD + PAYLOAD_SIZE);
  cell.set(sha256(payloadRegion), OFF_DOMAIN_PAYLOAD_ROOT);
  return cell;
}

// ── Sign (wallet-side, off-device) ───────────────────────────────────
//
// Note: @bsv/sdk's PrivateKey.sign(msg) internally does
//   hash = SHA256(msg); ecdsa.sign(hash, priv)
// which matches the device's cm_sig_hash_cell + cm_sig_sign(hash)
// pipeline. We pass the full 1024-byte cell; both sides compute the
// same SHA256, both verify against the wallet's pubkey.
function signCell(cell: Uint8Array): Uint8Array {
  const sig = WALLET_KEY.sign(Array.from(cell));
  // Raw r||s, 32+32 big-endian.
  const r = (sig.r as any).toArray('be', 32);
  const s = (sig.s as any).toArray('be', 32);
  return new Uint8Array([...r, ...s]);
}

// ── Channel encoders (match cell_channel.c byte layout) ──────────────
function encodeChannelOpen(channelId: Uint8Array, peerPubkey: Uint8Array,
                            initialLocktimeMs: bigint, totalCapacity: number): Uint8Array {
  const buf = new Uint8Array(61);
  buf.set(channelId, 0);
  buf.set(peerPubkey, 16);
  writeU64LE(buf, 49, initialLocktimeMs);
  writeU32LE(buf, 57, totalCapacity);
  return buf;
}

function encodeChannelCommitment(channelId: Uint8Array, seq: number,
                                  deviceShare: number, userShare: number,
                                  expiryMs: bigint): Uint8Array {
  const buf = new Uint8Array(36);
  buf.set(channelId, 0);
  writeU32LE(buf, 16, seq);
  writeU32LE(buf, 20, deviceShare);
  writeU32LE(buf, 24, userShare);
  writeU64LE(buf, 28, expiryMs);
  return buf;
}

function encodeChannelClose(channelId: Uint8Array, finalSeq: number,
                             finalDeviceShare: number): Uint8Array {
  const buf = new Uint8Array(24);
  buf.set(channelId, 0);
  writeU32LE(buf, 16, finalSeq);
  writeU32LE(buf, 20, finalDeviceShare);
  return buf;
}

// ── Hot-swap rule encoder (matches cell_rules.h, schema v1, 139 B) ───
function encodeHotSwapRule(): Uint8Array {
  const buf = new Uint8Array(139);
  buf[0] = 0x01;                       // schema_version
  buf[1] = 0x01;                       // trigger_kind = ON_TYPE
  buf.set(HEARTBEAT_TYPE, 2);          // trigger_type_hash
  // quorum fields stay 0 (offsets 34..37)
  buf[38] = 0x01;                      // effect_kind = BLINK
  writeU16LE(buf, 39, 100);            // blink.duration_ms
  // emit fields stay 0 (offsets 41..138)
  return buf;
}

// ── BIP-143 sighash (BSV/BCH FORKID variant) ─────────────────────────
//
// Mirrors core/cell-engine/src/sighash.zig:computeSigHash so the
// preimage the engine reconstructs on-device matches what we sign here.
//
// Layout: nVersion | hashPrevouts | hashSequence | outpoint | scriptCode |
//          value | nSequence | hashOutputs | nLockTime | nHashType
//          (each "hash" is dsha256 of the relevant concat)
function dsha256(bytes: Uint8Array): Uint8Array {
  return sha256(sha256(bytes));
}

interface TxInputView  { prevTxid: Uint8Array; prevVout: number; sequence: number; }
interface TxOutputView { value: bigint; script: Uint8Array; }

function bip143Sighash(
  txVersion: number,
  inputs: TxInputView[],
  outputs: TxOutputView[],
  locktime: number,
  inputIdx: number,
  scriptCode: Uint8Array,
  inputValue: bigint,
  sighashType: number,
): Uint8Array {
  // hashPrevouts
  const op = new Uint8Array(36 * inputs.length);
  for (let i = 0; i < inputs.length; i++) {
    op.set(inputs[i].prevTxid, 36 * i);
    writeU32LE(op, 36 * i + 32, inputs[i].prevVout);
  }
  const hashPrevouts = dsha256(op);
  // hashSequence
  const sb = new Uint8Array(4 * inputs.length);
  for (let i = 0; i < inputs.length; i++) writeU32LE(sb, 4 * i, inputs[i].sequence);
  const hashSequence = dsha256(sb);
  // hashOutputs
  const outBytes: number[] = [];
  for (const o of outputs) {
    const vbuf = new Uint8Array(8); writeU64LE(vbuf, 0, o.value);
    outBytes.push(...vbuf, o.script.length, ...o.script);   // varint(len) — assume <0xFD
  }
  const hashOutputs = dsha256(new Uint8Array(outBytes));
  // assemble preimage
  const out: number[] = [];
  const ver = new Uint8Array(4); writeU32LE(ver, 0, txVersion);            out.push(...ver);
  out.push(...hashPrevouts);
  out.push(...hashSequence);
  out.push(...inputs[inputIdx].prevTxid);
  const voutBuf = new Uint8Array(4); writeU32LE(voutBuf, 0, inputs[inputIdx].prevVout);
                                                                            out.push(...voutBuf);
  // scriptCode varint length — assume small
  out.push(scriptCode.length);
  out.push(...scriptCode);
  const valBuf = new Uint8Array(8); writeU64LE(valBuf, 0, inputValue);     out.push(...valBuf);
  const seqBuf = new Uint8Array(4); writeU32LE(seqBuf, 0, inputs[inputIdx].sequence);
                                                                            out.push(...seqBuf);
  out.push(...hashOutputs);
  const ltBuf = new Uint8Array(4); writeU32LE(ltBuf, 0, locktime);          out.push(...ltBuf);
  const htBuf = new Uint8Array(4); writeU32LE(htBuf, 0, sighashType);       out.push(...htBuf);
  return dsha256(new Uint8Array(out));
}

// Encode an ECDSA Signature object (r, s) as DER.
function ecdsaDer(sig: { r: any; s: any }): Uint8Array {
  const r = (sig.r as any).toArray('be');
  const s = (sig.s as any).toArray('be');
  // DER requires INTEGER values to be positive — if the high bit is set,
  // prepend a 0x00 byte.
  const rDer = r[0] & 0x80 ? [0, ...r] : r;
  const sDer = s[0] & 0x80 ? [0, ...s] : s;
  const body = [0x02, rDer.length, ...rDer, 0x02, sDer.length, ...sDer];
  return new Uint8Array([0x30, body.length, ...body]);
}

// ── Entry builder ────────────────────────────────────────────────────
function buildEntry(deviceMac: number[], kind: number, cell: Uint8Array, sig: Uint8Array): Uint8Array {
  const e = new Uint8Array(ENTRY_SIZE);
  e.set(deviceMac, 0);
  e[6] = kind;
  e[7] = 0;
  e.set(cell, ENTRY_PREFIX);
  e.set(sig, ENTRY_PREFIX + CELL_SIZE);
  return e;
}

// ── Lightbulb-channel demo schedule ──────────────────────────────────
// Device A is the wallet's voice on the mesh. Device C is the lightbulb.
// All cells are signed by the wallet (off-device). Timing is RELATIVE
// to the channel_open's receipt — the device captures its own monotonic
// clock at that moment and compares subsequent expiry_ms values to
// (now - channel_base). The wallet doesn't need wall-clock alignment
// with the device.
//
// Schedule (relative ms, transmitted by device A on its main loop):
//
//   t=0      channel_open  (LED still off — state OPEN, no commitment yet)
//   t=1000   commitment seq=1, device_share=1, expiry=16000  (LED on — ACTIVE)
//   t=2000   commitment seq=2, device_share=2
//   ...
//   t=8000   commitment seq=8, device_share=8  (paid 8 sats; LED still on)
//   <wallet stops paying — Tier-0 vault exhausted>
//   t~9300   DEVICE-SIDE METER EXHAUSTS: consumed (~1.2 sat/s) overruns the
//            last paid device_share (8) + tolerance → device cuts LED off.
//            This is the prepaid drain reaching empty, decided on-device —
//            NOT a commitment expiry. Expiry grace is deliberately long
//            (15s) so the *meter*, not liveness, is the cut-off cause.
//   t=13000  channel_close  (state ACTIVE → CLOSED, telemetry tidy-up)
const CHANNEL_COMMITMENT_COUNT = 8;
const CHANNEL_INITIAL_LOCKTIME_MS = 60_000n;
const CHANNEL_TOTAL_CAPACITY      = 1000;
// Fixed demo channel_id — 16 bytes; first 4 = "LBLB", rest = wallet tag.
const CHANNEL_ID = (() => {
  const id = new Uint8Array(16);
  id.set(new TextEncoder().encode('LBLB'), 0);
  id.set(WALLET_OWNER_ID.subarray(0, 12), 4);
  return id;
})();
// Device C's MAC, padded to 33 bytes to fit the peer_pubkey slot. (In
// production this would be the device's manufacturer-cert pubkey; for
// v0 the device is identified by its MAC, padded.)
const DEVICE_C_PEER_PUBKEY = (() => {
  const p = new Uint8Array(33);
  p[0] = 0x02;  // compressed-pubkey prefix shape; not a real curve point
  p.set(DEVICE_MACS[2].mac, 1);  // device C MAC at bytes 1..6
  // bytes 7..32 stay zero
  return p;
})();

function appendChannelCells(entries: Uint8Array[]) {
  const macA = DEVICE_MACS[0].mac;

  // channel_open
  {
    const payload = encodeChannelOpen(CHANNEL_ID, DEVICE_C_PEER_PUBKEY,
                                       CHANNEL_INITIAL_LOCKTIME_MS,
                                       CHANNEL_TOTAL_CAPACITY);
    const cell = mintCell(CHANNEL_OPEN_TYPE, payload);
    entries.push(buildEntry(macA, KIND_CHANNEL_OPEN, cell, signCell(cell)));
  }

  // N commitments. expiry_ms in DEVICE-RELATIVE time (the device captures
  // its own clock at channel_open receipt as t=0). Expiry grace is long
  // (15s) on purpose: liveness is NOT the cut-off in this demo — the
  // device-side draining meter is. The meter accrues consumed value at the
  // device's pro-rata rate and cuts the actuator off when consumption
  // overruns the paid device_share, well before any commitment expires.
  for (let i = 1; i <= CHANNEL_COMMITMENT_COUNT; i++) {
    const sentAt = BigInt(i) * 1000n;       // t = i seconds
    const expiry = sentAt + 15000n;         // 15s grace (meter, not expiry, cuts off)
    const payload = encodeChannelCommitment(CHANNEL_ID, i,
                                             /* device_share */ i,
                                             /* user_share   */ CHANNEL_TOTAL_CAPACITY - i,
                                             expiry);
    const cell = mintCell(CHANNEL_COMMITMENT_TYPE, payload);
    entries.push(buildEntry(macA, KIND_CHANNEL_COMMITMENT, cell, signCell(cell)));
  }

  // channel_close — final_seq + final_device_share must match the last
  // commitment the device accepted.
  {
    const payload = encodeChannelClose(CHANNEL_ID, CHANNEL_COMMITMENT_COUNT,
                                        /* final_device_share */ CHANNEL_COMMITMENT_COUNT);
    const cell = mintCell(CHANNEL_CLOSE_TYPE, payload);
    entries.push(buildEntry(macA, KIND_CHANNEL_CLOSE, cell, signCell(cell)));
  }
}

// ── Rentable-device cells (x402-over-cells) ──────────────────────────
//
// The wallet's lock + the tx skeleton are constants that both offer
// and activate cells share. Defined here so both builders emit the
// same bytes (lock_script must match, otherwise sighash diverges).
const RENTABLE_LOCK = (() => {
  // PUSH 33 <wallet_pubkey> OP_CHECKSIG
  const b = new Uint8Array(1 + 33 + 1);
  b[0] = 0x21;
  b.set(WALLET_PUBKEY, 1);
  b[34] = 0xAC;
  return b;
})();
const RENTABLE_TX = new Uint8Array([
  0x01, 0x00, 0x00, 0x00,                                       // version
  0x01,                                                          // input_count
  ...new Uint8Array(32),                                         // prev_txid (zeros)
  0x00, 0x00, 0x00, 0x00,                                       // prev_vout = 0
  0x00,                                                          // scriptSig len = 0
  0xFF, 0xFF, 0xFF, 0xFF,                                       // nSequence
  0x01,                                                          // output_count
  0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // value 10000
  0x01, 0x51,                                                    // scriptPubKey OP_1
  0x00, 0x00, 0x00, 0x00,                                       // locktime
]);
const RENTABLE_INPUT_VALUE = 50000n;
const RENTABLE_INPUT_IDX   = 0;
const RENTABLE_SIGHASH_TYPE = 0x41;

// 16-byte offer_id, derived from the wallet so it's stable per-build.
const RENTABLE_OFFER_ID = sha256(new TextEncoder().encode('cellmesh.rentable-device.offer.v0')).slice(0, 16);

function appendActuatorCells(entries: Uint8Array[], dev: { name: string; mac: number[] }) {
  if (dev.name === 'C') {
    // Device C broadcasts offers. Payload layout (matches
    // docs/x402-over-cells.md):
    //   u32 version, u32 cost_sats, u32 duration_ms,
    //   u16 lock_len, <lock>,
    //   u16 tx_template_len, <tx_template>,
    //   u32 input_idx, u64 input_value,
    //   16  offer_id,
    //   u32 counter
    for (let i = 0; i < OFFERS_PER_DEVICE_C; i++) {
      const head = 4 + 4 + 4;
      const lockSec = 2 + RENTABLE_LOCK.length;
      const txSec   = 2 + RENTABLE_TX.length;
      const tail    = 4 + 8 + 16 + 4;
      const payload = new Uint8Array(head + lockSec + txSec + tail);
      let off = 0;
      writeU32LE(payload, off, 1);                            off += 4;  // version
      writeU32LE(payload, off, ACTUATOR_COST_SATS);           off += 4;
      writeU32LE(payload, off, ACTUATOR_DURATION_MS);         off += 4;
      writeU16LE(payload, off, RENTABLE_LOCK.length);         off += 2;
      payload.set(RENTABLE_LOCK, off);                        off += RENTABLE_LOCK.length;
      writeU16LE(payload, off, RENTABLE_TX.length);           off += 2;
      payload.set(RENTABLE_TX, off);                          off += RENTABLE_TX.length;
      writeU32LE(payload, off, RENTABLE_INPUT_IDX);           off += 4;
      writeU64LE(payload, off, RENTABLE_INPUT_VALUE);         off += 8;
      payload.set(RENTABLE_OFFER_ID, off);                    off += 16;
      writeU32LE(payload, off, i);                            off += 4;
      const cell = mintCell(ACTUATOR_OFFER_TYPE, payload);
      entries.push(buildEntry(dev.mac, KIND_ACTUATOR_OFFER, cell, signCell(cell)));
    }
  } else if (dev.name === 'A') {
    // Device A broadcasts activations (the wallet pays). Each activation
    // is a wallet-signed BIP-143 P2PK unlock against RENTABLE_LOCK.
    // Payload layout:
    //   u16 lock_len, <lock>,
    //   u16 unlock_len, <unlock>,
    //   u16 tx_len, <tx>,
    //   u32 input_idx, u64 input_value,
    //   16  offer_id,
    //   u32 counter
    const sighash = bip143Sighash(
      1,
      [{ prevTxid: new Uint8Array(32), prevVout: 0, sequence: 0xFFFFFFFF }],
      [{ value: 10000n, script: new Uint8Array([0x51]) }],
      0,
      RENTABLE_INPUT_IDX,
      RENTABLE_LOCK,
      RENTABLE_INPUT_VALUE,
      RENTABLE_SIGHASH_TYPE,
    );
    const sigObj   = ECDSA.sign(new BigNumber(Array.from(sighash) as unknown as number[]),
                                  WALLET_KEY, true);
    const derBytes = ecdsaDer(sigObj);
    const sigPlusHashtype = new Uint8Array(derBytes.length + 1);
    sigPlusHashtype.set(derBytes, 0);
    sigPlusHashtype[derBytes.length] = RENTABLE_SIGHASH_TYPE;
    const unlock = new Uint8Array(1 + sigPlusHashtype.length);
    unlock[0] = sigPlusHashtype.length;     // PUSH N bytes
    unlock.set(sigPlusHashtype, 1);

    for (let i = 0; i < ACTIVATIONS_PER_DEVICE_A; i++) {
      const lockSec   = 2 + RENTABLE_LOCK.length;
      const unlockSec = 2 + unlock.length;
      const txSec     = 2 + RENTABLE_TX.length;
      const tail      = 4 + 8 + 16 + 4;
      const payload = new Uint8Array(lockSec + unlockSec + txSec + tail);
      let off = 0;
      writeU16LE(payload, off, RENTABLE_LOCK.length);         off += 2;
      payload.set(RENTABLE_LOCK, off);                        off += RENTABLE_LOCK.length;
      writeU16LE(payload, off, unlock.length);                off += 2;
      payload.set(unlock, off);                               off += unlock.length;
      writeU16LE(payload, off, RENTABLE_TX.length);           off += 2;
      payload.set(RENTABLE_TX, off);                          off += RENTABLE_TX.length;
      writeU32LE(payload, off, RENTABLE_INPUT_IDX);           off += 4;
      writeU64LE(payload, off, RENTABLE_INPUT_VALUE);         off += 8;
      payload.set(RENTABLE_OFFER_ID, off);                    off += 16;
      writeU32LE(payload, off, i);                            off += 4;
      const cell = mintCell(ACTUATOR_ACTIVATE_TYPE, payload);
      entries.push(buildEntry(dev.mac, KIND_ACTUATOR_ACTIVATE, cell, signCell(cell)));
    }
  }
}

// ── Deck assembly ────────────────────────────────────────────────────
function generateDeck(): Uint8Array {
  const entries: Uint8Array[] = [];
  for (const dev of DEVICE_MACS) {
    for (let i = 0; i < HEARTBEATS_PER_DEVICE; i++) {
      const payload = new Uint8Array(4);
      writeU32LE(payload, 0, i);
      const cell = mintCell(HEARTBEAT_TYPE, payload);
      entries.push(buildEntry(dev.mac, KIND_HEARTBEAT, cell, signCell(cell)));
    }
    for (let i = 0; i < TAPS_PER_DEVICE; i++) {
      const payload = new Uint8Array(4);
      writeU32LE(payload, 0, i);
      const cell = mintCell(TAP_TYPE, payload);
      entries.push(buildEntry(dev.mac, KIND_TAP, cell, signCell(cell)));
    }
    const ruleCell = mintCell(RULE_TYPE, encodeHotSwapRule());
    entries.push(buildEntry(dev.mac, KIND_HOT_SWAP_RULE, ruleCell, signCell(ruleCell)));

    // Channel cells live on device A only — append them on its pass so
    // they end up in the right per-device slice.
    if (dev.name === 'A') appendChannelCells(entries);

    // Scripted cells (BSV-script gated dispatch) — device A only.
    //
    // Payload layout (read by mesh_demo dispatch_scripted_cell):
    //   u16 LE  lock_len
    //   bytes   lock script  (BSV-script bytecode)
    //   u16 LE  unlock_len
    //   bytes   unlock script
    //   u16 LE  tx_len       (0 if no tx context needed)
    //   bytes   tx bytes     (raw BSV tx; only present when tx_len > 0)
    //   u32 LE  input_idx    (only when tx_len > 0)
    //   u64 LE  input_value  (only when tx_len > 0)
    //   u32 LE  counter      (per-cell, for cell-hash uniqueness)
    //
    // OP_CHECKSIG requires a tx context (BIP143 sighash preimage) which
    // is what `tx_len + tx_bytes + input_idx + input_value` supplies.
    if (dev.name === 'A') {
      // Wallet-signed P2PK for OP_CHECKSIG demo slot.
      //
      // Why P2PK instead of the foreign-key checksig-p2pkh.json test
      // vector: mbedTLS on ESP-IDF v5.3.1 rejects the test vector's sig.
      // @bsv/sdk's own sigs verify cleanly under that same mbedTLS (proven by every
      // cell-frame on the wire). So we have @bsv/sdk re-sign a fresh
      // BIP-143 sighash against the wallet's own pubkey — that lands
      // in the subset of ECDSA sigs mbedTLS accepts.
      //
      // Lock:   PUSH 33 <wallet_pubkey> OP_CHECKSIG  (35 bytes)
      // Unlock: PUSH 71 <DER_sig || 0x41>            (72 bytes)
      const p2pkLock = new Uint8Array(1 + 33 + 1);
      p2pkLock[0] = 0x21;                               // PUSH 33 bytes
      p2pkLock.set(WALLET_PUBKEY, 1);
      p2pkLock[34] = 0xAC;                              // OP_CHECKSIG

      // Minimal raw spending tx the engine will parse (matches the
      // pattern from cell-engine tests-bun/checksig_integration.test.ts).
      // version=1, 1 input (zero prev_txid, empty scriptSig, ffffffff),
      // 1 output (value=10000, scriptPubKey=OP_1), locktime=0.
      const PREV_TXID = new Uint8Array(32);  // all zeros
      const p2pkTx = new Uint8Array([
        0x01, 0x00, 0x00, 0x00,           // nVersion = 1
        0x01,                              // input_count = 1
        ...PREV_TXID,
        0x00, 0x00, 0x00, 0x00,           // prev_vout = 0
        0x00,                              // scriptSig length = 0 (varint)
        0xFF, 0xFF, 0xFF, 0xFF,           // nSequence
        0x01,                              // output_count = 1
        0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value = 10000
        0x01, 0x51,                        // scriptPubKey: OP_1
        0x00, 0x00, 0x00, 0x00,           // nLockTime
      ]);
      const p2pkInputValue = 50000n;
      const p2pkInputIdx   = 0;
      const SIGHASH_ALL_FORKID = 0x41;

      // Compute BIP-143 sighash matching cell-engine's computeSigHash.
      const p2pkSighash = bip143Sighash(
        1,
        [{ prevTxid: PREV_TXID, prevVout: 0, sequence: 0xFFFFFFFF }],
        [{ value: 10000n, script: new Uint8Array([0x51]) }],
        0,
        p2pkInputIdx,
        p2pkLock,
        p2pkInputValue,
        SIGHASH_ALL_FORKID,
      );

      // ECDSA.sign(msgHashBN, walletPriv, forceLowS=true).
      const sighashBN = new BigNumber(Array.from(p2pkSighash) as unknown as number[]);
      const sigObj    = ECDSA.sign(sighashBN, WALLET_KEY, true);
      const derBytes  = ecdsaDer(sigObj);
      const p2pkSig   = new Uint8Array(derBytes.length + 1);
      p2pkSig.set(derBytes, 0);
      p2pkSig[derBytes.length] = SIGHASH_ALL_FORKID;     // append sighash byte

      const p2pkUnlock = new Uint8Array(1 + p2pkSig.length);
      p2pkUnlock[0] = p2pkSig.length;                    // PUSH N bytes
      p2pkUnlock.set(p2pkSig, 1);

      console.error(`p2pk sighash: ${Buffer.from(p2pkSighash).toString('hex')}`);
      console.error(`p2pk sig len: ${p2pkSig.length} (DER ${derBytes.length} + 1 sighash byte)`);

      for (let i = 0; i < SCRIPTED_PER_DEVICE; i++) {
        const slot = i % 6;
        let lock: Uint8Array, unlock: Uint8Array;
        let tx: Uint8Array = new Uint8Array(0);
        let inputIdx = 0;
        let inputValue = 0n;

        if (slot === 0 || slot === 3) {
          // OP_TRUE — baseline ACCEPT (opcount=1)
          lock   = new Uint8Array([0x51]);
          unlock = new Uint8Array([]);
        } else if (slot === 1 || slot === 4) {
          // HASH-LOCKED correct unlock — ACCEPT (opcount=5)
          const preimage = Buffer.from('secret42', 'utf8');
          const expectedHash = sha256(sha256(preimage));
          unlock = new Uint8Array([0x08, ...preimage]);
          lock = new Uint8Array(36);
          lock[0] = 0xAA; lock[1] = 0x20;
          lock.set(expectedHash, 2);
          lock[34] = 0x88; lock[35] = 0x51;
        } else if (slot === 2 || slot === 5) {
          // HASH-LOCKED wrong unlock — REJECT (opcount=4)
          const expectedHash = sha256(sha256(Buffer.from('secret42', 'utf8')));
          unlock = new Uint8Array([0x08, ...Buffer.from('NOTRIGHT', 'utf8')]);
          lock = new Uint8Array(36);
          lock[0] = 0xAA; lock[1] = 0x20;
          lock.set(expectedHash, 2);
          lock[34] = 0x88; lock[35] = 0x51;
        } else {
          throw new Error('unreachable');
        }

        // Slot 3: wallet-signed P2PK (OP_CHECKSIG over BIP-143 sighash).
        // Overrides the second OP_TRUE; expected ACCEPT with opcount=3
        // (push sig, push pubkey, OP_CHECKSIG).
        if (i === 3) {
          lock       = p2pkLock;
          unlock     = p2pkUnlock;
          tx         = p2pkTx;
          inputIdx   = p2pkInputIdx;
          inputValue = p2pkInputValue;
        }

        const head = 2 + lock.length + 2 + unlock.length;
        const txSection = tx.length > 0 ? 2 + tx.length + 4 + 8 : 2;
        const payload = new Uint8Array(head + txSection + 4);
        let off = 0;
        writeU16LE(payload, off, lock.length);   off += 2;
        payload.set(lock, off);                  off += lock.length;
        writeU16LE(payload, off, unlock.length); off += 2;
        payload.set(unlock, off);                off += unlock.length;
        writeU16LE(payload, off, tx.length);     off += 2;
        if (tx.length > 0) {
          payload.set(tx, off);                  off += tx.length;
          writeU32LE(payload, off, inputIdx);    off += 4;
          writeU64LE(payload, off, inputValue);  off += 8;
        }
        writeU32LE(payload, off, i);             off += 4;

        const cell = mintCell(SCRIPTED_TYPE, payload);
        entries.push(buildEntry(dev.mac, KIND_SCRIPTED, cell, signCell(cell)));
      }
    }

    // Pre-signed confirmed_tap cells — rule engine pops these instead
    // of minting + signing on-device.
    // Payload: 'A','C','K',0x01,<counter LE> (matches install_demo_rules
    // legacy mint but with a per-cell counter so each one is unique →
    // distinct cell hash → not deduped by the ring).
    for (let i = 0; i < CONFIRMED_TAPS_PER_DEVICE; i++) {
      const payload = new Uint8Array(8);
      payload[0] = 0x41; // 'A'
      payload[1] = 0x43; // 'C'
      payload[2] = 0x4B; // 'K'
      payload[3] = 0x01;
      writeU32LE(payload, 4, i);
      const cell = mintCell(CONFIRMED_TAP_TYPE, payload);
      entries.push(buildEntry(dev.mac, KIND_CONFIRMED_TAP, cell, signCell(cell)));
    }

    // x402-over-cells rentable-device demo (see docs/x402-over-cells.md).
    // Device C is the rentable LED — broadcasts actuator_offer.v0 cells
    // advertising the lock + price + duration. Device A is the wallet —
    // broadcasts actuator_activate.v0 cells paying for the LED to come
    // on. The wallet uses the same P2PK lock (`<wallet_pubkey> OP_CHECKSIG`)
    // as the wallet-signed P2PK demo in #530.
    if (dev.name === 'A' || dev.name === 'C') {
      appendActuatorCells(entries, dev);
    }
  }

  const headerSize = 16;
  const out = new Uint8Array(headerSize + entries.length * ENTRY_SIZE);
  writeU32LE(out, 0, DECK_MAGIC);
  writeU32LE(out, 4, DECK_VERSION);
  writeU32LE(out, 8, entries.length);
  writeU32LE(out, 12, 0);
  let off = headerSize;
  for (const e of entries) {
    out.set(e, off);
    off += ENTRY_SIZE;
  }
  return out;
}

// ── Main ─────────────────────────────────────────────────────────────
const outPath = process.argv[2] ?? 'examples/mesh_demo/main/embed/cell_deck.bin';
const deck = generateDeck();
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, deck);

console.error(`wrote ${deck.length} bytes to ${outPath}`);
console.error(`entries: ${(deck.length - 16) / ENTRY_SIZE}`);
console.error(`wallet pubkey (compressed, 66-hex):  ${WALLET_PUBKEY_COMP_HEX}`);
console.error(`wallet owner_id (16-byte hex):       ${Buffer.from(WALLET_OWNER_ID).toString('hex')}`);
console.error(`provisioning timestamp_ms:           ${PROVISIONING_TIMESTAMP_MS}`);
