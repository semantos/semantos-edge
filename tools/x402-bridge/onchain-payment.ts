/**
 * onchain-payment.ts — REAL BSV mainnet payment verification.
 *
 * The fake DefaultPaymentVerifier only checked "some output ≥ N exists".
 * Brc29OnchainVerifier checks the actual signed tx pays *the bridge's*
 * receive script ≥ the price, within a mainnet safety cap, and derives the
 * real txid from the tx itself. Parsing uses @bsv/sdk so it handles both
 * raw-tx and BEEF encodings (Metanet Desktop createAction returns either).
 */

import { Transaction } from '@bsv/sdk';
import type { Brc29Payment, PaymentVerifier, VerifyResult } from './x402.js';

export interface OnchainVerifierOptions {
  /** Hard upper bound on accepted payment value — mainnet guardrail. */
  maxSats?: number;
}

/** Parse a tx from raw-hex or BEEF-hex; return null if neither parses. */
export function parseTx(hex: string): Transaction | null {
  try {
    return Transaction.fromHexBEEF(hex);
  } catch {
    /* not BEEF */
  }
  try {
    return Transaction.fromHex(hex);
  } catch {
    return null;
  }
}

export class Brc29OnchainVerifier implements PaymentVerifier {
  private readonly maxSats: number;

  constructor(
    private readonly receiveScriptHex: string,
    opts: OnchainVerifierOptions = {},
  ) {
    this.maxSats = opts.maxSats ?? 100_000; // ~mainnet guardrail; raise deliberately
    if (!/^[0-9a-fA-F]+$/.test(receiveScriptHex) || receiveScriptHex.length === 0) {
      throw new Error('Brc29OnchainVerifier: receiveScriptHex must be non-empty hex');
    }
  }

  verify(payment: Brc29Payment, required: number): VerifyResult {
    if (required > this.maxSats) {
      return { ok: false, reason: `price ${required} exceeds safety cap ${this.maxSats}` };
    }
    if (typeof payment.transaction !== 'string' || payment.transaction.length === 0) {
      return { ok: false, reason: 'payment missing transaction' };
    }
    const tx = parseTx(payment.transaction);
    if (!tx) return { ok: false, reason: 'unparseable transaction (not raw-tx or BEEF hex)' };

    const want = this.receiveScriptHex.toLowerCase();
    let paid = 0;
    for (const out of tx.outputs) {
      if (out.lockingScript.toHex().toLowerCase() === want) {
        paid += Number(out.satoshis ?? 0);
      }
    }
    if (paid === 0) return { ok: false, reason: 'no output pays the bridge receive script' };
    if (paid < required) return { ok: false, reason: `underpaid: ${paid} < required ${required}` };
    if (paid > this.maxSats) return { ok: false, reason: `paid ${paid} exceeds safety cap ${this.maxSats}` };

    return { ok: true, satoshisPaid: paid, txid: tx.id('hex') };
  }
}
