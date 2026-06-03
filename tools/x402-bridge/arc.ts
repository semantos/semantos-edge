/**
 * arc.ts — broadcast a BSV tx (raw or BEEF hex) to chain via ARC.
 *
 * Uses @bsv/sdk's ARC broadcaster, which parses the BEEF (input ancestry),
 * builds the extended format ARC expects, and POSTs it correctly. A
 * hand-rolled `{rawTx: <BEEF hex>}` POST is rejected by gorillapool ARC
 * with 400 — the SDK path is the one that works.
 *
 * MAINNET. Broadcasting moves real value — callers gate this behind an
 * explicit flag + a sats cap.
 */

import { ARC, Transaction } from '@bsv/sdk';

export interface ArcOptions {
  arcUrl?: string;
  apiKey?: string;
}

export const DEFAULT_ARC_URL = 'https://arc.gorillapool.io';

export type BroadcastResult = { ok: true; txid: string } | { ok: false; reason: string };

/** Broadcast a tx given as raw-hex or BEEF-hex. Returns the network txid. */
export async function broadcastTxHex(txHex: string, opts: ArcOptions = {}): Promise<BroadcastResult> {
  let tx: Transaction;
  try {
    tx = Transaction.fromHexBEEF(txHex);
  } catch {
    try {
      tx = Transaction.fromHex(txHex);
    } catch {
      return { ok: false, reason: 'unparseable tx (not raw-tx or BEEF hex)' };
    }
  }
  const arc = new ARC(opts.arcUrl ?? DEFAULT_ARC_URL, opts.apiKey ? { apiKey: opts.apiKey } : undefined);
  try {
    const r = (await tx.broadcast(arc)) as { status?: string; txid?: string; description?: string; message?: string; code?: string };
    if (r.txid) return { ok: true, txid: r.txid };
    return { ok: false, reason: r.description ?? r.message ?? r.code ?? 'ARC rejected (no txid)' };
  } catch (e) {
    // BroadcastFailure is sometimes thrown rather than returned.
    const f = e as { description?: string; message?: string };
    return { ok: false, reason: f.description ?? f.message ?? String(e) };
  }
}
