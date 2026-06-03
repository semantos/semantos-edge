#!/usr/bin/env bun
/**
 * pay-demo.ts — the AGENT side of the real x402 flow (the Dolphin Milk role).
 *
 *   bun pay-demo.ts [--bridge http://localhost:4021] [--metanet http://localhost:3321]
 *
 * 1. GET the bridge's discovery → the pay-to script + price.
 * 2. Fund + sign a real BSV tx paying that script via Metanet Desktop
 *    (:3321 createAction) — the same wallet/funding path as the MNCA anchor.
 * 3. POST it as x-bsv-payment; the bridge verifies it pays the bridge,
 *    broadcasts via ARC, actuates the C6, and returns the real txid.
 *
 * MAINNET: this moves real value (the offer price, ~100 sats). Run only
 * against a Metanet Desktop you control + a bridge started with --real-payment.
 */

import { createAction, rawTxHexFromCreateAction, METANET_BASE, DEFAULT_ORIGIN } from './metanet.js';

const arg = (name: string, def?: string): string | undefined => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : def;
};
const bridgeUrl = arg('--bridge', 'http://localhost:4021')!;
const metanetBase = arg('--metanet', METANET_BASE)!;
const metanetOrigin = arg('--metanet-origin', DEFAULT_ORIGIN)!;

// 1. Discover the pay-to script + price.
const disc = (await (await fetch(`${bridgeUrl}/.well-known/x402-info`)).json()) as {
  offer: { costSats: number; durationMs: number };
  payTo?: { scriptHex: string; satoshis: number };
};
if (!disc.payTo) throw new Error('bridge is not in --real-payment mode (no payTo in discovery)');
const { scriptHex, satoshis } = disc.payTo;
console.log(`bridge wants ${satoshis} sats → script ${scriptHex.slice(0, 16)}…  (lights C6 for ${disc.offer.durationMs} ms)`);

// 2. Fund + sign via Metanet Desktop (real mainnet tx).
console.log(`funding via Metanet Desktop at ${metanetBase} …`);
const ca = await createAction(
  [{ lockingScript: scriptHex, satoshis, outputDescription: 'x402 actuator activation' }],
  'x402 actuator activation',
  metanetBase,
  metanetOrigin,
);
const rawTx = rawTxHexFromCreateAction(ca);
if (!rawTx) throw new Error(`createAction returned no usable tx: ${JSON.stringify(ca).slice(0, 200)}`);
console.log(`funded tx ${rawTx.length / 2} bytes${ca.txid ? ` (md txid ${ca.txid})` : ''}`);

// 3. Pay the bridge. The bridge broadcasts the signed tx itself, so we hand
//    over the tx (not a txid — MD's createAction does NOT broadcast).
const res = await fetch(`${bridgeUrl}/actuator/activate`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-bsv-payment': JSON.stringify({ transaction: rawTx }) },
  body: '{}',
});
const body = await res.json();
console.log(`\nHTTP ${res.status}`);
console.log(`x-bsv-payment-txid: ${res.headers.get('x-bsv-payment-txid') ?? '(none)'}`);
console.log(JSON.stringify(body, null, 2));

// 4. Self-verify: a 200 only means the bridge claims success — confirm the
//    tx is actually on-chain (WhatsOnChain) before declaring victory.
if (res.status === 200) {
  const txid = (body as { txid?: string }).txid;
  if (!txid) { console.log('\n⚠ 200 but no txid returned.'); process.exit(1); }
  process.stdout.write(`\nconfirming ${txid} on-chain`);
  let found = false;
  for (let i = 0; i < 8 && !found; i++) {
    process.stdout.write('.');
    const r = await fetch(`https://api.whatsonchain.com/v1/bsv/main/tx/hash/${txid}`);
    if (r.status === 200) found = true;
    else await new Promise((s) => setTimeout(s, 1500));
  }
  console.log(found
    ? `\n✓ CONFIRMED on mainnet + actuated → https://whatsonchain.com/tx/${txid}`
    : `\n⚠ bridge returned 200 but ${txid} is NOT on WhatsOnChain — payment did not settle.`);
}
