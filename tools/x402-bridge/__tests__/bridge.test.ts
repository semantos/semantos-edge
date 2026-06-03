import { describe, it, expect } from 'bun:test';
import { PrivateKey } from '@bsv/sdk';
import {
  type ActuatorOffer,
  buildActuatorActivate,
  decodeActuatorActivate,
  ACTUATOR_ACTIVATE_TYPE,
  sha256,
  writeU16LE,
  writeU32LE,
  writeU64LE,
  readU32LE,
} from '../cell-codec.js';
import {
  buildChallengeHeaders,
  parsePaymentHeader,
  maxOutputValue,
  DefaultPaymentVerifier,
} from '../x402.js';
import { X402CellBridge, type MeshPort } from '../bridge.js';

// ── Fixtures: the demo wallet + the rentable offer (matches sign-cell-deck) ──

const WALLET = new PrivateKey('0000000000000000000000000000000000000000000000000000000000000042', 16);
const WALLET_PUB = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex'));

const RENTABLE_LOCK = (() => {
  const b = new Uint8Array(35);
  b[0] = 0x21;
  b.set(WALLET_PUB, 1);
  b[34] = 0xac;
  return b;
})();
const RENTABLE_TX = new Uint8Array([
  0x01, 0x00, 0x00, 0x00, 0x01, ...new Uint8Array(32), 0x00, 0x00, 0x00, 0x00, 0x00,
  0xff, 0xff, 0xff, 0xff, 0x01, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x51,
  0x00, 0x00, 0x00, 0x00,
]);
const OFFER: ActuatorOffer = {
  version: 1,
  costSats: 100,
  durationMs: 5000,
  lockScript: RENTABLE_LOCK,
  txTemplate: RENTABLE_TX,
  inputIdx: 0,
  inputValue: 50000n,
  offerId: sha256(new TextEncoder().encode('cellmesh.rentable-device.offer.v0')).slice(0, 16),
};

/** Build a minimal raw BSV tx with a single output of `value` sats. */
function rawTxWithOutput(value: bigint): string {
  const out = new Uint8Array(8 + 1 + 1);
  writeU64LE(out, 0, value);
  out[8] = 0x01; // scriptPubKey len
  out[9] = 0x51; // OP_1
  const tx = new Uint8Array(4 + 1 + 36 + 1 + 4 + 1 + out.length + 4);
  let o = 0;
  writeU32LE(tx, o, 1); o += 4; // version
  tx[o++] = 0x01; // in count
  o += 32; // prev txid
  writeU32LE(tx, o, 0); o += 4; // vout
  tx[o++] = 0x00; // scriptSig len
  writeU32LE(tx, o, 0xffffffff); o += 4; // sequence
  tx[o++] = 0x01; // out count
  tx.set(out, o); o += out.length;
  writeU32LE(tx, o, 0); o += 4; // locktime
  return Buffer.from(tx).toString('hex');
}

/** A mock mesh that records broadcasts and ACKs by policy. */
function mockMesh(ackPolicy: 'ack' | 'timeout' = 'ack') {
  const broadcasts: Array<{ cell: Uint8Array; sig: Uint8Array }> = [];
  const mesh: MeshPort = {
    async broadcast(cell, sig) { broadcasts.push({ cell, sig }); },
    async awaitActivation() { return ackPolicy === 'ack'; },
  };
  return { mesh, broadcasts };
}

// ── cell-codec ───────────────────────────────────────────────────────

describe('cell-codec — actuator_activate.v0', () => {
  it('builds a well-formed cell + payload that round-trips', () => {
    const { payload, cell, sig } = buildActuatorActivate(OFFER, WALLET, WALLET_PUB.subarray(0, 16), 1779000000000n, 7);
    expect(cell.length).toBe(1024);
    expect(sig.length).toBe(64);
    // type hash at offset 30
    expect(Array.from(cell.subarray(30, 62))).toEqual(Array.from(ACTUATOR_ACTIVATE_TYPE));
    // payload_total at offset 90 == payload length
    expect(readU32LE(cell, 90)).toBe(payload.length);

    const dec = decodeActuatorActivate(payload);
    expect(Array.from(dec.lockScript)).toEqual(Array.from(RENTABLE_LOCK));
    expect(Array.from(dec.offerId)).toEqual(Array.from(OFFER.offerId));
    expect(dec.inputValue).toBe(50000n);
    expect(dec.counter).toBe(7);
    // unlock is PUSH(N) of (DER sig || sighash byte 0x41)
    expect(dec.unlockScript[0]).toBe(dec.unlockScript.length - 1);
    expect(dec.unlockScript[dec.unlockScript.length - 1]).toBe(0x41);
    expect(dec.unlockScript[1]).toBe(0x30); // DER SEQUENCE
  });

  it('per-call counter gives distinct cells (dedup-friendly)', () => {
    const a = buildActuatorActivate(OFFER, WALLET, WALLET_PUB.subarray(0, 16), 1n, 1);
    const b = buildActuatorActivate(OFFER, WALLET, WALLET_PUB.subarray(0, 16), 1n, 2);
    expect(decodeActuatorActivate(a.payload).counter).toBe(1);
    expect(decodeActuatorActivate(b.payload).counter).toBe(2);
    expect(Buffer.from(a.cell).equals(Buffer.from(b.cell))).toBe(false);
  });
});

// ── x402 protocol ────────────────────────────────────────────────────

describe('x402 — BSV-native (Dolphin Milk) dialect', () => {
  it('challenge headers carry version + sats + derivation prefix + transports', () => {
    const h = buildChallengeHeaders(100, 'abc123==');
    expect(h['x-bsv-payment-version']).toBe('1.0');
    expect(h['x-bsv-payment-satoshis-required']).toBe('100');
    expect(h['x-bsv-payment-derivation-prefix']).toBe('abc123==');
    expect(h['x-bsv-payment-transports']).toContain('multipart');
  });

  it('parses x-bsv-payment as raw JSON and base64-of-JSON', () => {
    const json = JSON.stringify({ transaction: 'deadbeef', derivationPrefix: 'p' });
    expect(parsePaymentHeader(json).transaction).toBe('deadbeef');
    expect(parsePaymentHeader(Buffer.from(json).toString('base64')).transaction).toBe('deadbeef');
  });

  it('maxOutputValue parses a raw tx output', () => {
    expect(maxOutputValue(rawTxWithOutput(100n))).toBe(100n);
    expect(maxOutputValue(rawTxWithOutput(50000n))).toBe(50000n);
  });

  it('verifier: underpaid rejected, sufficient accepted, garbage fails closed', () => {
    const v = new DefaultPaymentVerifier();
    expect(v.verify({ transaction: rawTxWithOutput(99n) }, 100)).toEqual({ ok: false, reason: 'underpaid: funded 99 < required 100' });
    expect(v.verify({ transaction: rawTxWithOutput(100n) }, 100)).toEqual({ ok: true, satoshisPaid: 100 });
    expect(v.verify({ transaction: 'zz' }, 100).ok).toBe(false);
    expect(v.verify({}, 100)).toEqual({ ok: false, reason: 'payment missing transaction' });
  });
});

// ── end-to-end: a mock Dolphin Milk agent pays the bridge ────────────

describe('X402CellBridge — full HTTP↔cell round-trip', () => {
  it('discovery advertises the offer price', () => {
    const { mesh } = mockMesh();
    const bridge = new X402CellBridge({ offer: OFFER, walletKey: WALLET, mesh });
    const r = bridge.discover();
    expect(r.status).toBe(200);
    const body = r.body as { offer: { costSats: number; offerId: string }; endpoints: unknown[] };
    expect(body.offer.costSats).toBe(100);
    expect(body.endpoints).toHaveLength(1);
  });

  it('no payment → 402 with BSV x402 challenge headers', async () => {
    const { mesh, broadcasts } = mockMesh();
    const bridge = new X402CellBridge({ offer: OFFER, walletKey: WALLET, mesh });
    const r = await bridge.activate(null);
    expect(r.status).toBe(402);
    expect(r.headers['x-bsv-payment-satoshis-required']).toBe('100');
    expect(r.headers['x-bsv-payment-version']).toBe('1.0');
    expect(broadcasts).toHaveLength(0); // nothing actuated without payment
  });

  it('valid payment → broadcasts activate cell, device ACKs, 200 + receipt', async () => {
    const { mesh, broadcasts } = mockMesh('ack');
    const bridge = new X402CellBridge({ offer: OFFER, walletKey: WALLET, mesh });

    // Mock Dolphin Milk: pays the required price in a funded tx.
    const paymentHeader = JSON.stringify({
      derivationPrefix: 'p',
      derivationSuffix: 's',
      transaction: rawTxWithOutput(100n),
    });
    const r = await bridge.activate(paymentHeader);

    expect(r.status).toBe(200);
    expect(r.headers['x-bsv-payment-satoshis-paid']).toBe('100');
    const body = r.body as { activated: boolean; durationMs: number };
    expect(body.activated).toBe(true);
    expect(body.durationMs).toBe(5000);

    // The bridge broadcast exactly one well-formed actuator_activate cell.
    expect(broadcasts).toHaveLength(1);
    expect(broadcasts[0].cell.length).toBe(1024);
    expect(broadcasts[0].sig.length).toBe(64);
    const dec = decodeActuatorActivate(broadcasts[0].cell.subarray(256, 256 + readU32LE(broadcasts[0].cell, 90)));
    expect(Array.from(dec.offerId)).toEqual(Array.from(OFFER.offerId));
  });

  it('underpayment → 402 rejected, nothing broadcast', async () => {
    const { mesh, broadcasts } = mockMesh('ack');
    const bridge = new X402CellBridge({ offer: OFFER, walletKey: WALLET, mesh });
    const r = await bridge.activate(JSON.stringify({ transaction: rawTxWithOutput(50n) }));
    expect(r.status).toBe(402);
    expect((r.body as { error: string }).error).toContain('underpaid');
    expect(broadcasts).toHaveLength(0);
  });

  it('paid but device never ACKs → 504 (agent refund path)', async () => {
    const { mesh, broadcasts } = mockMesh('timeout');
    const bridge = new X402CellBridge({ offer: OFFER, walletKey: WALLET, mesh, activationTimeoutMs: 10 });
    const r = await bridge.activate(JSON.stringify({ transaction: rawTxWithOutput(100n) }));
    expect(r.status).toBe(504);
    expect(broadcasts).toHaveLength(1); // it did broadcast; device just didn't confirm
  });
});

// silence unused-import lint for writeU16LE (kept for codec symmetry in fixtures)
void writeU16LE;
