/**
 * metanet.ts — minimal client for Metanet Desktop's BRC-100 HTTP wallet on
 * localhost:3321. Mirrors how wallet.html funds the on-chain MNCA anchor:
 * Metanet Desktop holds the keys (and does BRC-42 derivation + recovery),
 * supplies a recoverable receive pubkey, and funds+signs payments.
 *
 *   POST /getPublicKey  { identityKey:true | protocolID,keyID,counterparty }
 *                       → { publicKey: <33B hex> }
 *   POST /createAction  { description, outputs:[{ lockingScript, satoshis }] }
 *                       → { txid?, rawTx?|tx?|beef?, ... }   (funded+signed)
 */

import { PublicKey, P2PKH } from '@bsv/sdk';

export const METANET_BASE = 'http://localhost:3321';
// Metanet Desktop's BRC-100 HTTP API scopes permission grants per Origin and
// rejects requests without one (browsers send it automatically; a CLI must
// set it). This identifies the bridge app in the MD permission dialog — keep
// it stable so the grant sticks across runs.
export const DEFAULT_ORIGIN = 'http://localhost:4021';

export interface CreateActionOutput {
  lockingScript: string; // hex
  satoshis: number;
  outputDescription?: string;
}

export interface CreateActionResult {
  txid?: string;
  rawTx?: string;
  tx?: number[];
  beef?: string | number[];
}

async function post(base: string, path: string, body: unknown, origin: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: origin },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`metanet ${path} ${res.status}: ${(await res.text()).slice(0, 160)}`);
  return (await res.json()) as Record<string, unknown>;
}

/** Get a (BRC-42-derived, recoverable) receive pubkey from Metanet Desktop. */
export async function getPublicKey(
  args: { identityKey: true } | { protocolID: [number, string]; keyID: string; counterparty: string },
  base = METANET_BASE,
  origin = DEFAULT_ORIGIN,
): Promise<string> {
  const r = await post(base, '/getPublicKey', args, origin);
  const pk = r.publicKey;
  if (typeof pk !== 'string') throw new Error('getPublicKey: no publicKey in response');
  return pk;
}

/** Build a mainnet P2PKH locking-script hex from a compressed pubkey hex. */
export function p2pkhScriptHexFromPubkey(pubkeyHex: string): string {
  return new P2PKH().lock(PublicKey.fromString(pubkeyHex).toAddress()).toHex();
}

/**
 * Sign under a BRC-42/43 derived key (protocolID + keyID + counterparty —
 * the "edge"). `hashToDirectlySign` signs a 32-byte digest as-is (for an
 * OP_CHECKSIG sighash). Returns the DER signature bytes.
 */
export async function createSignature(
  args: { protocolID: [number, string]; keyID: string; counterparty: string; data?: number[]; hashToDirectlySign?: number[] },
  base = METANET_BASE,
  origin = DEFAULT_ORIGIN,
): Promise<number[]> {
  const r = await post(base, '/createSignature', args, origin);
  const sig = (r as { signature?: unknown }).signature;
  if (!Array.isArray(sig)) throw new Error('createSignature: no signature in response');
  return sig as number[];
}

/** Fund + sign (Metanet Desktop) a tx paying the given outputs. */
export async function createAction(
  outputs: CreateActionOutput[],
  description: string,
  base = METANET_BASE,
  origin = DEFAULT_ORIGIN,
): Promise<CreateActionResult> {
  return (await post(base, '/createAction', { description, outputs }, origin)) as CreateActionResult;
}

/** Normalize createAction's several tx encodings to a raw-tx hex string. */
export function rawTxHexFromCreateAction(r: CreateActionResult): string | null {
  if (typeof r.rawTx === 'string') return r.rawTx;
  if (Array.isArray(r.tx)) return Buffer.from(r.tx).toString('hex');
  if (typeof r.beef === 'string') return r.beef; // BEEF; ARC accepts BEEF too
  if (Array.isArray(r.beef)) return Buffer.from(r.beef).toString('hex');
  return null;
}
