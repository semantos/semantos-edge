/**
 * channel-anchor.ts — BSV payment-channel lifecycle for the c6 cell-mesh.
 *
 * Opens a real on-chain channel: funds a P2PKH output via Metanet Desktop
 * (BRC-42), derives a 16-byte channel_id from the funding txid, pre-signs
 * a refund tx with nLockTime (BSV has no CLTV), and on
 * settlement threshold builds + broadcasts a spending tx that records
 * accumulated device_share vs remaining user_share on chain.
 *
 * channel_id derivation (canonical, matches the Zig cell_channel ABI hook):
 *   channelId = Buffer.from(fundingTxid, 'hex').subarray(0, 16)
 *   (first 16 bytes of the txid in conventional display/hex order)
 *
 * Settlement model for this demo (no keys on device):
 *   • device_share output → wallet key (device has no BSV signing key)
 *   • user_share output  → wallet key
 *   Track 2 (BRC-42 edge keys) replaces the device output with a
 *   per-channel relay key derived from the hat.
 */

import { PrivateKey, ECDSA, BigNumber, Hash, Transaction } from '@bsv/sdk';
import { bip143Sighash, ecdsaDer, writeU64LE } from './cell-codec.js';
import { createAction, rawTxHexFromCreateAction } from './metanet.js';
import { broadcastTxHex, type ArcOptions } from './arc.js';

export const CHANNEL_FUNDING_SATS    = 10_000;  // 10k sats, ~1¢ — enough for demo
export const SETTLE_THRESHOLD_SATS   = 50;      // trigger settlement after 50 sats accumulated
export const REFUND_LOCKTIME_OFFSET  = 86_400;  // 24h as unix-timestamp nLockTime delta

export interface ChannelState {
  txid:             string;        // funding txid (mainnet, display/hex order)
  vout:             number;        // output index in funding tx
  fundingSats:      number;
  channelId:        Uint8Array;    // 16 bytes = txid_bytes[0..16]
  fundingLockHex:   string;        // P2PKH locking script of the funding output
  refundTxHex:      string;        // pre-signed; NOT broadcast — stored for recovery
  openedAtMs:       number;
  deviceShareAccum: number;        // sats earned by relay devices so far
  userShareAccum:   number;        // sats returned toward user
  finalSeq:         number;        // last committed seq at settlement
  settled:          boolean;
  settleTxid?:      string;
}

// ── Script builders ───────────────────────────────────────────────────

/** P2PKH locking script from a compressed pubkey hex. */
function p2pkhLock(pubkeyHex: string): Uint8Array {
  const pk = Buffer.from(pubkeyHex, 'hex');
  const h160 = Array.from(Hash.hash160(Array.from(pk)) as number[]);
  return new Uint8Array([0x76, 0xa9, 0x14, ...h160, 0x88, 0xac]);
}

// ── Raw-tx helpers ────────────────────────────────────────────────────

function varint(n: number): number[] {
  if (n < 0xfd) return [n];
  if (n <= 0xffff) return [0xfd, n & 0xff, (n >> 8) & 0xff];
  return [0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
}

interface TxIn  { txid: string; vout: number; sequence: number; }
interface TxOut { sats: bigint; lockHex: string; }

/** Serialise a raw BSV transaction (version=1). */
function serialiseTx(
  inputs:     TxIn[],
  outputs:    TxOut[],
  locktime:   number,
  scriptsigs: Uint8Array[],
): string {
  const b: number[] = [1, 0, 0, 0]; // version LE
  b.push(...varint(inputs.length));
  for (let i = 0; i < inputs.length; i++) {
    // prevTxid in raw (little-endian) order
    const txidBuf = Buffer.from(inputs[i].txid, 'hex');
    b.push(...Buffer.from(txidBuf).reverse());
    const v = inputs[i].vout;
    b.push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff);
    const ss = scriptsigs[i] ?? new Uint8Array(0);
    b.push(...varint(ss.length), ...ss);
    const s = inputs[i].sequence;
    b.push(s & 0xff, (s >> 8) & 0xff, (s >> 16) & 0xff, (s >> 24) & 0xff);
  }
  b.push(...varint(outputs.length));
  for (const out of outputs) {
    const val = new Uint8Array(8); writeU64LE(val, 0, out.sats); b.push(...val);
    const sc = Buffer.from(out.lockHex, 'hex');
    b.push(...varint(sc.length), ...sc);
  }
  b.push(locktime & 0xff, (locktime >> 8) & 0xff, (locktime >> 16) & 0xff, (locktime >> 24) & 0xff);
  return Buffer.from(b).toString('hex');
}

/**
 * BIP-143 (BSV FORKID) sign a P2PKH input. Returns the scriptsig bytes
 * (PUSH(sig||hashtype) PUSH(pubkey)).
 */
function signP2PKH(
  inputs:     TxIn[],
  outputs:    TxOut[],
  locktime:   number,
  inputIdx:   number,
  inputValue: bigint,
  lockScript: Uint8Array,
  key:        PrivateKey,
  sighashType = 0x41,
): Uint8Array {
  const iViews = inputs.map((inp) => ({
    prevTxid: new Uint8Array(Buffer.from(Buffer.from(inp.txid, 'hex')).reverse()),
    prevVout: inp.vout,
    sequence: inp.sequence,
  }));
  const oViews = outputs.map((out) => ({
    value:  out.sats,
    script: new Uint8Array(Buffer.from(out.lockHex, 'hex')),
  }));
  const sighash = bip143Sighash(1, iViews, oViews, locktime, inputIdx, lockScript, inputValue, sighashType);
  const sigObj  = ECDSA.sign(new BigNumber(Array.from(sighash) as unknown as number[]), key, true);
  const der     = ecdsaDer(sigObj as unknown as { r: unknown; s: unknown });
  const sigPlusHt = new Uint8Array([...der, sighashType]);
  const pub = Buffer.from(key.toPublicKey().toString(), 'hex');
  const ss = new Uint8Array(1 + sigPlusHt.length + 1 + pub.length);
  let o = 0;
  ss[o++] = sigPlusHt.length; ss.set(sigPlusHt, o); o += sigPlusHt.length;
  ss[o++] = pub.length;       ss.set(pub, o);
  return ss;
}

// ── Channel open ──────────────────────────────────────────────────────

/**
 * Open a payment channel on BSV mainnet:
 *   1. Fund a P2PKH UTXO locked to walletKey via Metanet Desktop.
 *   2. Broadcast the funding tx via ARC.
 *   3. Derive channelId = txid_bytes[0..16].
 *   4. Pre-sign a refund tx (nLockTime = now + 24h) but don't broadcast it.
 *
 * @param walletKey  Demo private key — signs both open and refund.
 * @param opts       Optional: fundingSats, metanetBase, metanet origin, arcOpts.
 */
export async function openChannel(
  walletKey: PrivateKey,
  opts: {
    fundingSats?:  number;
    metanetBase?:  string;
    origin?:       string;
    arcOpts?:      ArcOptions;
  } = {},
): Promise<ChannelState> {
  const fundingSats = opts.fundingSats ?? CHANNEL_FUNDING_SATS;
  const pubHex      = walletKey.toPublicKey().toString();
  const lockScript  = p2pkhLock(pubHex);
  const lockHex     = Buffer.from(lockScript).toString('hex');

  // 1. Fund via Metanet Desktop
  const ca = await createAction(
    [{ lockingScript: lockHex, satoshis: fundingSats, outputDescription: 'cellmesh channel funding' }],
    'open cellmesh payment channel',
    opts.metanetBase,
    opts.origin,
  );
  const rawTx = rawTxHexFromCreateAction(ca);
  if (!rawTx) throw new Error('openChannel: createAction returned no tx');

  // 2. Broadcast and extract on-chain txid
  const bcast = await broadcastTxHex(rawTx, opts.arcOpts ?? {});
  if (!bcast.ok) throw new Error(`openChannel: ARC broadcast failed: ${bcast.reason}`);
  const txid = bcast.txid;

  // 3. Find the vout of our output (scan parsed tx — MD may add change outputs)
  let vout = 0;
  try {
    let parsed: Transaction;
    try { parsed = Transaction.fromHexBEEF(rawTx); } catch { parsed = Transaction.fromHex(rawTx); }
    for (let i = 0; i < (parsed.outputs?.length ?? 0); i++) {
      if ((parsed.outputs[i].lockingScript as { toHex?: () => string })?.toHex?.() === lockHex) {
        vout = i; break;
      }
    }
  } catch { /* keep vout=0 if parse fails */ }

  // channelId = first 16 bytes of txid (display order)
  const channelId = new Uint8Array(Buffer.from(txid, 'hex').subarray(0, 16));

  // 4. Pre-sign refund tx (nLockTime = unix_now + 24h, input seq 0xfffffffe enables it)
  // BSV uses timestamp-mode nLockTime when value >= 500_000_000 (unix seconds).
  const refundLocktime = Math.floor(Date.now() / 1000) + REFUND_LOCKTIME_OFFSET;
  const refundFee   = 200n;
  const refundIns:  TxIn[]  = [{ txid, vout, sequence: 0xfffffffe }];
  const refundOuts: TxOut[] = [{ sats: BigInt(fundingSats) - refundFee, lockHex }];
  const refundSig  = signP2PKH(refundIns, refundOuts, refundLocktime, 0, BigInt(fundingSats), lockScript, walletKey);
  const refundTxHex = serialiseTx(refundIns, refundOuts, refundLocktime, [refundSig]);

  return {
    txid, vout, fundingSats,
    channelId, fundingLockHex: lockHex,
    refundTxHex,
    openedAtMs:       Date.now(),
    deviceShareAccum: 0,
    userShareAccum:   0,
    finalSeq:         0,
    settled:          false,
  };
}

// ── Accumulate + settle ───────────────────────────────────────────────

/**
 * Record a forwarding hop's payment. Returns true if the settlement
 * threshold has been crossed and the caller should trigger settlement.
 */
export function accumulateHop(
  state:       ChannelState,
  deviceShare: number,
  userShare:   number,
  seq:         number,
): boolean {
  if (state.settled) return false;
  state.deviceShareAccum += deviceShare;
  state.userShareAccum   += userShare;
  state.finalSeq          = Math.max(state.finalSeq, seq);
  return state.deviceShareAccum >= SETTLE_THRESHOLD_SATS;
}

/**
 * Build, sign, and broadcast a settlement transaction that spends the
 * funding UTXO. The settlement tx has two outputs:
 *   [0] deviceShare sats  → wallet key (demo; Track 2 replaces with relay edge key)
 *   [1] remaining - fee   → wallet key
 *
 * Returns the on-chain settlement txid.
 */
export async function settleChannel(
  state:     ChannelState,
  walletKey: PrivateKey,
  arcOpts:   ArcOptions = {},
): Promise<string> {
  if (state.settled) throw new Error('channel already settled');

  const fee        = 200n;
  const deviceSats = BigInt(state.deviceShareAccum);
  const remaining  = BigInt(state.fundingSats) - deviceSats - fee;
  if (remaining < 546n) throw new Error(`settleChannel: remaining (${remaining}) below dust limit after fee`);

  const lockHex   = state.fundingLockHex;
  const lockSc    = new Uint8Array(Buffer.from(lockHex, 'hex'));

  const settleIns:  TxIn[]  = [{ txid: state.txid, vout: state.vout, sequence: 0xffffffff }];
  const settleOuts: TxOut[] = [
    { sats: deviceSats, lockHex },   // device share (demo: → wallet; Track 2 → relay key)
    { sats: remaining,  lockHex },   // user remainder
  ];

  const settleSig = signP2PKH(settleIns, settleOuts, 0, 0, BigInt(state.fundingSats), lockSc, walletKey);
  const settleTxHex = serialiseTx(settleIns, settleOuts, 0, [settleSig]);

  const bcast = await broadcastTxHex(settleTxHex, arcOpts);
  if (!bcast.ok) throw new Error(`settleChannel: ARC broadcast failed: ${bcast.reason}`);

  state.settled    = true;
  state.settleTxid = bcast.txid;
  return bcast.txid;
}

// ── Utility ───────────────────────────────────────────────────────────

/**
 * Derive the 16-byte channelId that the firmware's cm_channel_validate_utxo_ref
 * function checks: first 16 bytes of the funding txid in display (hex) order.
 */
export function channelIdFromTxid(txid: string): Uint8Array {
  return new Uint8Array(Buffer.from(txid, 'hex').subarray(0, 16));
}
