import { describe, it, expect } from 'bun:test';
import { PrivateKey, P2PKH, Transaction } from '@bsv/sdk';
import { Brc29OnchainVerifier, parseTx } from '../onchain-payment.js';
import { p2pkhScriptHexFromPubkey, rawTxHexFromCreateAction } from '../metanet.js';
import { X402CellBridge, type MeshPort } from '../bridge.js';
import { type ActuatorOffer, sha256 } from '../cell-codec.js';

// ── fixtures ─────────────────────────────────────────────────────────
const BRIDGE_KEY = PrivateKey.fromRandom();
const RECEIVE_ADDR = BRIDGE_KEY.toPublicKey().toAddress();
const RECEIVE_SCRIPT = new P2PKH().lock(RECEIVE_ADDR).toHex();

const WALLET = new PrivateKey('0000000000000000000000000000000000000000000000000000000000000042', 16);
const WP = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex'));
const LOCK = (() => { const b = new Uint8Array(35); b[0]=0x21; b.set(WP,1); b[34]=0xac; return b; })();
const OFFER: ActuatorOffer = {
  version: 1, costSats: 100, durationMs: 5000, lockScript: LOCK,
  txTemplate: new Uint8Array([1,0,0,0,0,0,0,0,0,0]), inputIdx: 0, inputValue: 50000n,
  offerId: sha256(new TextEncoder().encode('cellmesh.rentable-device.offer.v0')).slice(0, 16),
};

function mockMesh(): MeshPort {
  return { async broadcast() {}, async awaitActivation() { return true; } };
}

// ── onchain verifier ─────────────────────────────────────────────────

describe('Brc29OnchainVerifier — real tx, pays the bridge', () => {
  it('accepts a tx that pays the receive script ≥ price and reports the real txid', () => {
    const tx = new Transaction();
    tx.addOutput({ lockingScript: new P2PKH().lock(RECEIVE_ADDR), satoshis: 100 });
    const raw = tx.toHex();
    const v = new Brc29OnchainVerifier(RECEIVE_SCRIPT);
    const r = v.verify({ transaction: raw }, 100);
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error('unreachable');
    expect(r.satoshisPaid).toBe(100);
    expect(r.txid).toBe(Transaction.fromHex(raw).id('hex'));
  });

  it('rejects when no output pays the bridge', () => {
    const other = PrivateKey.fromRandom().toPublicKey().toAddress();
    const tx = new Transaction();
    tx.addOutput({ lockingScript: new P2PKH().lock(other), satoshis: 100 });
    const r = new Brc29OnchainVerifier(RECEIVE_SCRIPT).verify({ transaction: tx.toHex() }, 100);
    expect(r).toMatchObject({ ok: false });
    if (r.ok) throw new Error('unreachable');
    expect(r.reason).toContain('no output pays');
  });

  it('rejects underpayment, garbage, and over-cap; enforces the price cap', () => {
    const tx = new Transaction();
    tx.addOutput({ lockingScript: new P2PKH().lock(RECEIVE_ADDR), satoshis: 50 });
    const v = new Brc29OnchainVerifier(RECEIVE_SCRIPT, { maxSats: 1000 });
    expect(v.verify({ transaction: tx.toHex() }, 100)).toMatchObject({ ok: false }); // underpaid 50<100
    expect(v.verify({ transaction: 'zz' }, 100)).toMatchObject({ ok: false }); // garbage
    expect(v.verify({ transaction: tx.toHex() }, 5000)).toMatchObject({ ok: false }); // price>cap
    const big = new Transaction();
    big.addOutput({ lockingScript: new P2PKH().lock(RECEIVE_ADDR), satoshis: 2000 });
    expect(v.verify({ transaction: big.toHex() }, 100)).toMatchObject({ ok: false }); // paid>cap
  });

  it('sums multiple outputs to the bridge (payment + may include change elsewhere)', () => {
    const other = PrivateKey.fromRandom().toPublicKey().toAddress();
    const tx = new Transaction();
    tx.addOutput({ lockingScript: new P2PKH().lock(RECEIVE_ADDR), satoshis: 60 });
    tx.addOutput({ lockingScript: new P2PKH().lock(other), satoshis: 999 }); // change to payer
    tx.addOutput({ lockingScript: new P2PKH().lock(RECEIVE_ADDR), satoshis: 40 });
    const r = new Brc29OnchainVerifier(RECEIVE_SCRIPT).verify({ transaction: tx.toHex() }, 100);
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error('unreachable');
    expect(r.satoshisPaid).toBe(100);
  });
});

// ── metanet helpers ──────────────────────────────────────────────────

describe('metanet helpers', () => {
  it('p2pkhScriptHexFromPubkey matches @bsv/sdk P2PKH', () => {
    expect(p2pkhScriptHexFromPubkey(WALLET.toPublicKey().toString()))
      .toBe(new P2PKH().lock(WALLET.toPublicKey().toAddress()).toHex());
  });

  it('rawTxHexFromCreateAction normalizes rawTx / tx[] / beef', () => {
    expect(rawTxHexFromCreateAction({ rawTx: 'abcd' })).toBe('abcd');
    expect(rawTxHexFromCreateAction({ tx: [0xab, 0xcd] })).toBe('abcd');
    expect(rawTxHexFromCreateAction({ beef: 'ef01' })).toBe('ef01');
    expect(rawTxHexFromCreateAction({})).toBeNull();
  });
});

// ── bridge real-payment mode (no network: broadcastOnVerify=false) ───

describe('X402CellBridge — real-payment mode', () => {
  it('advertises payTo in discovery + 402', async () => {
    const bridge = new X402CellBridge({ offer: OFFER, walletKey: WALLET, mesh: mockMesh(), receiveScriptHex: RECEIVE_SCRIPT });
    const disc = bridge.discover().body as { payTo?: { scriptHex: string } };
    expect(disc.payTo?.scriptHex).toBe(RECEIVE_SCRIPT);
    const challenge = await bridge.activate(null);
    expect(challenge.status).toBe(402);
    expect((challenge.body as { payToScriptHex?: string }).payToScriptHex).toBe(RECEIVE_SCRIPT);
  });

  it('verifies a real payment to the bridge, actuates, returns the txid', async () => {
    const tx = new Transaction();
    tx.addOutput({ lockingScript: new P2PKH().lock(RECEIVE_ADDR), satoshis: 100 });
    const raw = tx.toHex();
    const bridge = new X402CellBridge({
      offer: OFFER, walletKey: WALLET, mesh: mockMesh(),
      receiveScriptHex: RECEIVE_SCRIPT,
      verifier: new Brc29OnchainVerifier(RECEIVE_SCRIPT),
      // broadcastOnVerify stays false → use the verifier-derived txid (no network)
    });
    const r = await bridge.activate(JSON.stringify({ transaction: raw }));
    expect(r.status).toBe(200);
    expect(r.headers['x-bsv-payment-txid']).toBe(Transaction.fromHex(raw).id('hex'));
    const body = r.body as { activated: boolean; txid: string; satoshisPaid: number };
    expect(body.activated).toBe(true);
    expect(body.txid).toBe(Transaction.fromHex(raw).id('hex'));
    expect(body.satoshisPaid).toBe(100);
  });

  it('rejects a payment that does not pay the bridge (402, no actuation)', async () => {
    const other = PrivateKey.fromRandom().toPublicKey().toAddress();
    const tx = new Transaction();
    tx.addOutput({ lockingScript: new P2PKH().lock(other), satoshis: 100 });
    let broadcast = 0;
    const mesh: MeshPort = { async broadcast() { broadcast++; }, async awaitActivation() { return true; } };
    const bridge = new X402CellBridge({
      offer: OFFER, walletKey: WALLET, mesh,
      receiveScriptHex: RECEIVE_SCRIPT, verifier: new Brc29OnchainVerifier(RECEIVE_SCRIPT),
    });
    const r = await bridge.activate(JSON.stringify({ transaction: tx.toHex() }));
    expect(r.status).toBe(402);
    expect(broadcast).toBe(0);
  });
});

// parseTx is exercised indirectly via the verifier; keep the import live.
void parseTx;
