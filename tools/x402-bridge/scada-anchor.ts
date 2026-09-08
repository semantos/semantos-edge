/**
 * scada-anchor.ts — SCADA "data acquisition" as an on-chain log layer.
 *
 * Unlike x402 (which broadcasts a *payment* tx), a SCADA event is committed
 * on chain as the FULL canonical 1024-byte cell, carried in a PushDrop
 * output — the same recipe that anchors the MNCA snapshot cell on mainnet:
 *
 *     OP_PUSHDATA2 <cell[1024]> OP_DROP <leafPk(33)> OP_CHECKSIG
 *
 * The cell IS the log entry: tamper-evident, ordered by the chain, and the
 * txid is the audit receipt. The 1-sat output is spendable by leafPk
 * (recoverable), so it can later be swept / superseded. Metanet Desktop
 * funds + signs the tx (createAction with an arbitrary lockingScript); ARC
 * broadcasts it.
 */

import { mintCell, typeHash, writeU32LE, writeU64LE } from './cell-codec.js';
import { DOMAIN } from '../domains.js';
import { createAction, rawTxHexFromCreateAction, getPublicKey, type CreateActionResult } from './metanet.js';
import { broadcastTxHex } from './arc.js';

export const SCADA_EVENT_TYPE = typeHash('scada.event.v0');

export const SCADA_ACTION = { ACTUATE: 1, SETPOINT: 2, ALARM: 3, READING: 4 } as const;

export interface ScadaEvent {
  tag: string;      // the controlled point, e.g. "actuator-C" (<=16 bytes)
  action: number;   // SCADA_ACTION
  value: number;    // command value (e.g. duration_ms / setpoint)
  reading: number;  // acquired telemetry (e.g. load in centi-watts)
}

/**
 * Encode a SCADA event as a canonical cell (scada.event.v0). Payload:
 *   tag(16, utf8) | action(u8) | value(u32 LE) | reading(u32 LE) | ts(u64 LE)
 */
export function encodeScadaCell(ev: ScadaEvent, ownerId: Uint8Array, tsMs: number): Uint8Array {
  const p = new Uint8Array(16 + 1 + 4 + 4 + 8);
  p.set(new TextEncoder().encode(ev.tag).subarray(0, 16), 0);
  p[16] = ev.action & 0xff;
  writeU32LE(p, 17, ev.value >>> 0);
  writeU32LE(p, 21, ev.reading >>> 0);
  writeU64LE(p, 25, BigInt(tsMs));
  return mintCell(SCADA_EVENT_TYPE, p, ownerId, BigInt(tsMs), DOMAIN.meshTelemetry);
}

/** PushDrop locking script (hex): PUSHDATA2(cell) OP_DROP PUSH(leafPk) OP_CHECKSIG. */
export function pushdropLockHex(cell: Uint8Array, leafPkHex: string): string {
  const pk = Buffer.from(leafPkHex, 'hex');
  const out: number[] = [0x4d, cell.length & 0xff, (cell.length >> 8) & 0xff]; // OP_PUSHDATA2 + u16 LE len
  for (const b of cell) out.push(b);
  out.push(0x75);                       // OP_DROP
  out.push(pk.length);                  // PUSH(33)
  for (const b of pk) out.push(b);
  out.push(0xac);                       // OP_CHECKSIG
  return Buffer.from(out).toString('hex');
}

export interface AnchorResult { txid: string; cellHex: string; outputBytes: number }

/**
 * Anchor a canonical SCADA cell on chain via a PushDrop output.
 * `leafPkHex` is the recoverable owner (a Metanet-Desktop-derived key).
 */
export async function anchorScadaCell(
  cell: Uint8Array,
  leafPkHex: string,
  opts: { metanetBase?: string; origin?: string; satoshis?: number } = {},
): Promise<AnchorResult> {
  const lock = pushdropLockHex(cell, leafPkHex);
  const ca: CreateActionResult = await createAction(
    [{ lockingScript: lock, satoshis: opts.satoshis ?? 1, outputDescription: 'scada event (pushdrop cell)' }],
    'scada event anchor',
    opts.metanetBase,
    opts.origin,
  );
  const rawTx = rawTxHexFromCreateAction(ca);
  if (!rawTx) throw new Error('createAction returned no tx for the anchor');
  const b = await broadcastTxHex(rawTx);
  if (!b.ok) throw new Error(`anchor broadcast: ${b.reason}`);
  return { txid: b.txid, cellHex: Buffer.from(cell).toString('hex'), outputBytes: lock.length / 2 };
}

/** Derive a recoverable PushDrop-owner pubkey from Metanet Desktop (BRC-42). */
export async function deriveScadaLeaf(metanetBase?: string, origin?: string): Promise<string> {
  return getPublicKey({ protocolID: [2, 'mnca scada anchor'], keyID: 'scada-log', counterparty: 'self' }, metanetBase, origin);
}
