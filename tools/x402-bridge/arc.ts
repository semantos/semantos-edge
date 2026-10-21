/**
 * arc.ts — broadcast a BSV tx (raw or BEEF hex) through ARCADE.
 *
 * ARCADE is the project's own broadcast rail. Its contract, held by
 * __tests__/arcade.test.ts:
 *
 *   • Transport: the transaction in extended format (BRC-30 EF) as raw bytes,
 *     `POST <base>/tx`, `Content-Type: application/octet-stream`. EF carries
 *     each input's source output, which is why a BEEF input (ancestry
 *     included) is the normal case. Raw hex with no ancestry is sent as given
 *     and ARCADE refuses it, naming the missing input scripts.
 *   • Verdict: the body's `txStatus`, not the HTTP status. `202` with
 *     `RECEIVED` / `SEEN_ON_NETWORK` is an acceptance; any body with a
 *     non-empty `error`, or `txStatus: "REJECTED"`, is a refusal. The reason
 *     for a refusal is in `detail` (sometimes `reason`); `error` alone is the
 *     generic "transaction failed validation".
 *   • The rail's fee floor is 100 sat/KB (GET <base>/policy says so).
 *
 * MAINNET. Broadcasting moves real value — callers gate this behind an
 * explicit flag + a sats cap.
 */

import { Transaction } from '@bsv/sdk';

export interface ArcOptions {
  /** ARCADE base URL; a trailing slash is fine. */
  arcUrl?: string;
  /** Sent as `Authorization: Bearer <apiKey>` when set. */
  apiKey?: string;
}

export const DEFAULT_ARCADE_URL = 'https://arcade.gorillapool.io';

export type BroadcastResult = { ok: true; txid: string } | { ok: false; reason: string };

interface ArcadeReply {
  txid?: string;
  txStatus?: string;
  status?: number | string;
  error?: string;
  detail?: string;
  reason?: string;
  extraInfo?: string;
}

/** Parse BEEF hex, else raw hex. */
function parseTx(txHex: string): Transaction | null {
  try {
    return Transaction.fromHexBEEF(txHex);
  } catch {
    try {
      return Transaction.fromHex(txHex);
    } catch {
      return null;
    }
  }
}

/** EF when every input knows its source output; otherwise the bytes as given. */
function wireBytes(tx: Transaction, txHex: string): Uint8Array {
  try {
    return Uint8Array.from(tx.toEF());
  } catch {
    return Uint8Array.from(Buffer.from(txHex, 'hex'));
  }
}

/** Broadcast a tx given as raw-hex or BEEF-hex. Returns the network txid. */
export async function broadcastTxHex(txHex: string, opts: ArcOptions = {}): Promise<BroadcastResult> {
  const tx = parseTx(txHex);
  if (!tx) return { ok: false, reason: 'unparseable tx (not raw-tx or BEEF hex)' };

  const base = (opts.arcUrl ?? DEFAULT_ARCADE_URL).replace(/\/+$/, '');
  const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' };
  if (opts.apiKey) headers['Authorization'] = `Bearer ${opts.apiKey}`;

  let res: Response;
  try {
    res = await fetch(`${base}/tx`, { method: 'POST', headers, body: wireBytes(tx, txHex) });
  } catch (e) {
    return { ok: false, reason: `arcade unreachable: ${(e as Error).message ?? String(e)}` };
  }

  let text: string;
  try {
    text = await res.text();
  } catch {
    return { ok: false, reason: `arcade HTTP ${res.status}: unreadable response` };
  }
  let r: ArcadeReply;
  try {
    r = JSON.parse(text) as ArcadeReply;
  } catch {
    return { ok: false, reason: `arcade HTTP ${res.status}: ${text.slice(0, 160)}` };
  }

  // The verdict is txStatus, never the HTTP status.
  const refused = Boolean(r.error) || r.txStatus === 'REJECTED' || !r.txid;
  if (refused) {
    const why = [r.detail, r.reason, r.extraInfo, r.error].filter(Boolean).join(' — ') || r.txStatus || `HTTP ${res.status}`;
    return { ok: false, reason: `arcade rejected: ${why}` };
  }
  return { ok: true, txid: r.txid! };
}
