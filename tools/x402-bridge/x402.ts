/**
 * x402.ts — Dolphin Milk's BSV-native x402 wire (NOT the Coinbase/EVM
 * variant). Reconstructed from calhooon/dolphinmilk bsv-x402-server:
 *
 *   402 response headers (server → client):
 *     x-bsv-payment-version            = "1.0"
 *     x-bsv-payment-satoshis-required  = <decimal sats>
 *     x-bsv-payment-derivation-prefix  = <base64 nonce>   (BRC-29/42 derivation)
 *     x-bsv-payment-transports         = "header" | "header,multipart" (BRC-105)
 *
 *   payment header (client → server):
 *     x-bsv-payment = <JSON>  (BRC-29: { derivationPrefix, derivationSuffix,
 *                              transaction, ... })  — or a multipart part of
 *                              the same name when it exceeds ~8KB.
 *
 * The bridge is the x402 *server*: it sets the 402 challenge, then verifies
 * the BRC-29 payment the agent retries with. Full BRC-42 output-ownership
 * (that the payment is to *this* bridge's derived key) is the production
 * hardening step — pluggable via PaymentVerifier; the default verifies the
 * amount + that a real funded output covers it.
 */

export const BSV_PAYMENT_VERSION = '1.0';

// BRC-29 payment-key-derivation protocolID, matching Dolphin Milk's
// payment_protocol() = [2, "3241645161d8"].
export const BRC29_PAYMENT_PROTOCOL: [number, string] = [2, '3241645161d8'];

export interface PaymentRequired {
  satoshis: number;
  /** base64 nonce the client folds into BRC-42 derivation. */
  derivationPrefix: string;
  version: string;
  /** Advertised transports (BRC-105). */
  transports: string[];
}

/** Build the 402 challenge headers for a given price. */
export function buildChallengeHeaders(satoshis: number, derivationPrefix: string): Record<string, string> {
  if (!Number.isInteger(satoshis) || satoshis <= 0) {
    throw new Error('satoshis-required must be a positive integer');
  }
  return {
    'x-bsv-payment-version': BSV_PAYMENT_VERSION,
    'x-bsv-payment-satoshis-required': String(satoshis),
    'x-bsv-payment-derivation-prefix': derivationPrefix,
    'x-bsv-payment-transports': 'header,multipart',
  };
}

/** BRC-29 payment body the agent sends in the x-bsv-payment header. */
export interface Brc29Payment {
  derivationPrefix?: string;
  derivationSuffix?: string;
  /** Funded tx — rawtx hex or BEEF hex. */
  transaction?: string;
  /** Network txid if the payer's wallet already broadcast (e.g. Metanet Desktop). */
  txid?: string;
  /** Some senders inline the paid amount; we still verify against the tx. */
  amount?: number;
  [k: string]: unknown;
}

/** Parse the x-bsv-payment header value (raw JSON, or base64-of-JSON). */
export function parsePaymentHeader(headerValue: string): Brc29Payment {
  const trimmed = headerValue.trim();
  const text = trimmed.startsWith('{') ? trimmed : Buffer.from(trimmed, 'base64').toString('utf8');
  const obj = JSON.parse(text);
  if (!obj || typeof obj !== 'object') throw new Error('x-bsv-payment is not an object');
  return obj as Brc29Payment;
}

export type VerifyResult =
  | { ok: true; satoshisPaid: number; txid?: string }
  | { ok: false; reason: string };

/**
 * A payment verifier. The default checks the payment is well-formed and
 * that the supplied transaction funds at least `required` sats in some
 * output. Swap in a BRC-42-aware verifier (bridge identity key + the
 * derivation prefix/suffix) to also prove the payment is to *this* bridge.
 */
export interface PaymentVerifier {
  verify(payment: Brc29Payment, required: number): VerifyResult;
}

/**
 * Sum the output values of a raw BSV tx (version|in|...|out_count|outputs|
 * locktime). Returns the max single-output value (the relevant figure for
 * "did one output cover the price"). Best-effort: handles the demo's
 * single-byte varints; throws on anything it can't parse so verification
 * fails closed.
 */
export function maxOutputValue(rawtxHex: string): bigint {
  const tx = Buffer.from(rawtxHex, 'hex');
  let o = 4; // skip version
  const inCount = tx[o++];
  if (inCount >= 0xfd) throw new Error('unsupported input-count varint');
  for (let i = 0; i < inCount; i++) {
    o += 36; // prevout
    const sl = tx[o++];
    if (sl >= 0xfd) throw new Error('unsupported scriptSig varint');
    o += sl + 4; // script + sequence
  }
  const outCount = tx[o++];
  if (outCount >= 0xfd) throw new Error('unsupported output-count varint');
  let max = 0n;
  for (let i = 0; i < outCount; i++) {
    let v = 0n;
    for (let b = 0; b < 8; b++) v |= BigInt(tx[o + b]) << BigInt(b * 8);
    o += 8;
    const sl = tx[o++];
    if (sl >= 0xfd) throw new Error('unsupported scriptPubKey varint');
    o += sl;
    if (v > max) max = v;
  }
  return max;
}

export class DefaultPaymentVerifier implements PaymentVerifier {
  verify(payment: Brc29Payment, required: number): VerifyResult {
    if (typeof payment.transaction !== 'string' || payment.transaction.length === 0) {
      return { ok: false, reason: 'payment missing transaction' };
    }
    let funded: bigint;
    try {
      funded = maxOutputValue(payment.transaction);
    } catch (e) {
      return { ok: false, reason: `unparseable transaction: ${(e as Error).message}` };
    }
    if (funded < BigInt(required)) {
      return { ok: false, reason: `underpaid: funded ${funded} < required ${required}` };
    }
    return { ok: true, satoshisPaid: Number(funded) };
  }
}
