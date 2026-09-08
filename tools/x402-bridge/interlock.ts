/**
 * interlock.ts — SCADA *interlock* as a BSV script (not just a log).
 *
 * A real SCADA interlock GATES the action: the actuator must not energize
 * unless a permissive condition is satisfied. Here the permissive + the
 * operator authorization are the on-device script the cell-engine enforces:
 *
 *     OP_HASH160 <H160(permissive)> OP_EQUALVERIFY <operatorPk> OP_CHECKSIG
 *
 * To actuate, the unlock must reveal the permissive preimage AND carry the
 * operator's signature. Reveal the right permissive → the engine ACCEPTs →
 * the device energizes. Withhold it (safety controller hasn't cleared the
 * interlock) → OP_EQUALVERIFY fails → the engine REJECTs → the actuator
 * stays off. The script is the interlock; the device enforces it.
 */

import { PrivateKey, ECDSA, BigNumber, Hash } from '@bsv/sdk';
import { DOMAIN } from '../domains.js';
import {
  bip143Sighash, ecdsaDer, mintCell, signCell,
  writeU16LE, writeU32LE, writeU64LE, ACTUATOR_ACTIVATE_TYPE,
} from './cell-codec.js';
import { SIGHASH_ALL_FORKID, SIGHASH_SINGLE_ACP_FORKID } from './sighash.js';

/** OP_HASH160 <h160(permissive)> OP_EQUALVERIFY <operatorPk(33)> OP_CHECKSIG */
export function interlockLock(permissive: Uint8Array, operatorPubHex: string): Uint8Array {
  const h160 = Hash.hash160(Array.from(permissive)); // RIPEMD160(SHA256(x)), 20 bytes
  const pk = Buffer.from(operatorPubHex, 'hex');
  return new Uint8Array([0xa9, 0x14, ...h160, 0x88, 0x21, ...pk, 0xac]);
}

// ── Capability-gated interlock: only the Plexus hat's BRC-42-edge key clears it ──

/** Interlock lock = PUSH(capabilityPubkey 33) OP_CHECKSIG. Cleared only by a
 *  signature from the capability key (the hat, BRC-42-edge-derived). */
export function interlockCheckSigLock(capPubkeyHex: string): Uint8Array {
  const pk = Buffer.from(capPubkeyHex, 'hex');
  return new Uint8Array([0x21, ...pk, 0xac]);
}

/**
 * The BIP-143 sighash the capability key must sign to clear the interlock.
 *
 * Default: SIGHASH_SINGLE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID (BRC-115).
 * Pass a different sighashType explicitly to override (e.g. for testing with
 * SIGHASH_ALL_FORKID on a non-identity-linked lock).
 */
export function interlockSighash(lock: Uint8Array, inputIdx: number, inputValue: bigint, sighashType = SIGHASH_SINGLE_ACP_FORKID): Uint8Array {
  return bip143Sighash(
    1,
    [{ prevTxid: new Uint8Array(32), prevVout: inputIdx, sequence: 0xffffffff }],
    [{ value: 10000n, script: new Uint8Array([0x51]) }],
    0, inputIdx, lock, inputValue, sighashType,
  );
}

/**
 * Build an actuator gated by a capability CHECKSIG interlock. `sigDer` is the
 * DER signature over interlockSighash(lock,…) — produced by the capability
 * holder (clears) or by anyone without the capability (CHECKSIG fails →
 * device REJECT, the interlock holds).
 */
export function buildCapabilityInterlockActuator(opts: {
  walletKey: PrivateKey; ownerId: Uint8Array; offerId: Uint8Array;
  capPubkeyHex: string; sigDer: Uint8Array;
  txTemplate: Uint8Array; inputIdx: number; inputValue: bigint;
  timestampMs: bigint; counter: number;
  /** Override sighash type; defaults to SIGHASH_SINGLE_ACP_FORKID (BRC-115). */
  sighashType?: number;
}): InterlockActuator {
  // Capability-gated = identity-linked transfer → BRC-115 mandates SINGLE|ACP|FORKID.
  const sighashType = opts.sighashType ?? SIGHASH_SINGLE_ACP_FORKID;
  const lock = interlockCheckSigLock(opts.capPubkeyHex);
  const sigPlusHt = new Uint8Array(opts.sigDer.length + 1);
  sigPlusHt.set(opts.sigDer, 0); sigPlusHt[opts.sigDer.length] = sighashType;
  const unlock = new Uint8Array(1 + sigPlusHt.length);
  unlock[0] = sigPlusHt.length; unlock.set(sigPlusHt, 1);

  const lockSec = 2 + lock.length;
  const unlockSec = 2 + unlock.length;
  const txSec = 2 + opts.txTemplate.length;
  const tail = 4 + 8 + 16 + 4;
  const payload = new Uint8Array(lockSec + unlockSec + txSec + tail);
  let off = 0;
  writeU16LE(payload, off, lock.length); off += 2; payload.set(lock, off); off += lock.length;
  writeU16LE(payload, off, unlock.length); off += 2; payload.set(unlock, off); off += unlock.length;
  writeU16LE(payload, off, opts.txTemplate.length); off += 2; payload.set(opts.txTemplate, off); off += opts.txTemplate.length;
  writeU32LE(payload, off, opts.inputIdx); off += 4;
  writeU64LE(payload, off, opts.inputValue); off += 8;
  payload.set(opts.offerId, off); off += 16;
  writeU32LE(payload, off, opts.counter); off += 4;

  const cell = mintCell(ACTUATOR_ACTIVATE_TYPE, payload, opts.ownerId, opts.timestampMs, DOMAIN.meshControl);
  return { payload, cell, sig: signCell(cell, opts.walletKey) };
}

export interface InterlockActuator { payload: Uint8Array; cell: Uint8Array; sig: Uint8Array; }

/**
 * Build an actuator_activate gated by the interlock. `reveal` is what the
 * unlock presents: pass the real permissive to satisfy the interlock, or
 * any other bytes to model the permissive being withheld (→ device REJECT).
 */
export function buildInterlockActuator(opts: {
  walletKey: PrivateKey;
  ownerId: Uint8Array;
  offerId: Uint8Array;
  permissive: Uint8Array;   // what the lock commits (H160 of this)
  reveal: Uint8Array;       // what the unlock reveals (== permissive to satisfy)
  txTemplate: Uint8Array;
  inputIdx: number;
  inputValue: bigint;
  timestampMs: bigint;
  counter: number;
  /** Override sighash type; defaults to SIGHASH_ALL_FORKID (plain permissive reveal,
   *  not identity-linked — commits to all inputs and outputs). */
  sighashType?: number;
}): InterlockActuator {
  // Plain hash-preimage interlock, not identity-linked → SIGHASH_ALL|FORKID.
  const sighashType = opts.sighashType ?? SIGHASH_ALL_FORKID;
  const lock = interlockLock(opts.permissive, opts.walletKey.toPublicKey().toString());

  const sighash = bip143Sighash(
    1,
    [{ prevTxid: new Uint8Array(32), prevVout: opts.inputIdx, sequence: 0xffffffff }],
    [{ value: 10000n, script: new Uint8Array([0x51]) }],
    0, opts.inputIdx, lock, opts.inputValue, sighashType,
  );
  const sigObj = ECDSA.sign(new BigNumber(Array.from(sighash) as unknown as number[]), opts.walletKey, true);
  const der = ecdsaDer(sigObj as unknown as { r: unknown; s: unknown });
  const sigPlusHt = new Uint8Array(der.length + 1);
  sigPlusHt.set(der, 0);
  sigPlusHt[der.length] = sighashType;

  // unlock: PUSH(sig||hashtype) PUSH(reveal)  → stack [sig, reveal] (reveal on top)
  const unlock = new Uint8Array(1 + sigPlusHt.length + 1 + opts.reveal.length);
  let u = 0;
  unlock[u++] = sigPlusHt.length; unlock.set(sigPlusHt, u); u += sigPlusHt.length;
  unlock[u++] = opts.reveal.length; unlock.set(opts.reveal, u);

  // payload: same layout as actuator_activate.v0
  const lockSec = 2 + lock.length;
  const unlockSec = 2 + unlock.length;
  const txSec = 2 + opts.txTemplate.length;
  const tail = 4 + 8 + 16 + 4;
  const payload = new Uint8Array(lockSec + unlockSec + txSec + tail);
  let off = 0;
  writeU16LE(payload, off, lock.length); off += 2; payload.set(lock, off); off += lock.length;
  writeU16LE(payload, off, unlock.length); off += 2; payload.set(unlock, off); off += unlock.length;
  writeU16LE(payload, off, opts.txTemplate.length); off += 2; payload.set(opts.txTemplate, off); off += opts.txTemplate.length;
  writeU32LE(payload, off, opts.inputIdx); off += 4;
  writeU64LE(payload, off, opts.inputValue); off += 8;
  payload.set(opts.offerId, off); off += 16;
  writeU32LE(payload, off, opts.counter); off += 4;

  const cell = mintCell(ACTUATOR_ACTIVATE_TYPE, payload, opts.ownerId, opts.timestampMs, DOMAIN.meshControl);
  return { payload, cell, sig: signCell(cell, opts.walletKey) };
}
