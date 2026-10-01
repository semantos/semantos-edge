import { describe, it, expect } from 'bun:test';
import { PrivateKey, P2PKH, Transaction, LockingScript } from '@bsv/sdk';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { typeHash, readU32LE, sha256, type ActuatorOffer } from '../cell-codec.js';
import { ChannelMeter } from '../meter.js';
import { X402CellBridge, type MeshPort } from '../bridge.js';
import { Brc29OnchainVerifier } from '../onchain-payment.js';
import { makeLightHandler } from '../light.js';

const KEY = new PrivateKey('0000000000000000000000000000000000000000000000000000000000000042', 16);
const OPEN = Buffer.from(typeHash('cellmesh.channel_open.v0')).toString('hex');
const COMMIT = Buffer.from(typeHash('cellmesh.channel_commitment.v0')).toString('hex');
const CLOSE = Buffer.from(typeHash('cellmesh.channel_close.v0')).toString('hex');

type Sent = { kind: 'open' | 'commit' | 'close' | 'other'; id: string; seq?: number; share?: number };
/** Decode what the meter put on the mesh: type hash @30, payload @256. */
function decode(cell: Uint8Array): Sent {
  const t = Buffer.from(cell.subarray(30, 62)).toString('hex');
  const p = cell.subarray(256);
  const id = Buffer.from(p.subarray(0, 16)).toString('hex');
  if (t === OPEN) return { kind: 'open', id };
  if (t === COMMIT) return { kind: 'commit', id, seq: readU32LE(p, 16), share: readU32LE(p, 20) };
  if (t === CLOSE) return { kind: 'close', id, seq: readU32LE(p, 16), share: readU32LE(p, 20) };
  return { kind: 'other', id };
}

function fakeMesh(ack = true) {
  const sent: Sent[] = [];
  const mesh: MeshPort = {
    async broadcast(cell) { sent.push(decode(cell)); },
    async awaitActivation() { return ack; },
  };
  return { mesh, sent };
}

function clock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance: (ms: number) => { t += ms; } };
}

describe('ChannelMeter — the chip meters, the bridge keeps the books', () => {
  it('opens one channel and commits cumulative device_share while lit', async () => {
    const m = fakeMesh();
    const c = clock();
    const meter = new ChannelMeter({ mesh: m.mesh, key: KEY, now: c.now });
    await meter.start();
    expect(m.sent).toEqual([{ kind: 'open', id: meter.channelIdHex }]);

    const r1 = await meter.addSats(12);
    expect(r1.ok).toBe(true);
    expect(r1.secondsAdded).toBe(10);
    c.advance(5_000);
    const r2 = await meter.addSats(12);
    expect(r2.ok).toBe(true);
    const commits = m.sent.filter((s) => s.kind === 'commit');
    expect(commits).toEqual([
      { kind: 'commit', id: meter.channelIdHex, seq: 1, share: 12 },
      { kind: 'commit', id: meter.channelIdHex, seq: 2, share: 24 },
    ]);
    // 24 sats paid, 5 s (6 sats) consumed → 15 s left.
    expect(meter.status().secondsLeft).toBeCloseTo(15, 0);
    expect(meter.status().satsPaid).toBe(24);
  });

  it('after the light has gone dark, the next payment starts a fresh channel', async () => {
    const m = fakeMesh();
    const c = clock();
    const meter = new ChannelMeter({ mesh: m.mesh, key: KEY, now: c.now });
    await meter.start();
    const first = meter.channelIdHex;
    await meter.addSats(12);
    c.advance(60_000); // dark; the chip's meter kept draining
    expect(meter.status().secondsLeft).toBe(0);
    const r = await meter.addSats(12);
    expect(r.ok).toBe(true);
    expect(meter.channelIdHex).not.toBe(first);
    // Re-send the last commitment (a board that missed it catches up), close
    // the old channel (needs every board on the same seq/share), open a new one.
    expect(m.sent).toEqual([
      { kind: 'open', id: first },
      { kind: 'commit', id: first, seq: 1, share: 12 },
      { kind: 'commit', id: first, seq: 1, share: 12 },
      { kind: 'close', id: first, seq: 1, share: 12 },
      { kind: 'open', id: meter.channelIdHex },
      { kind: 'commit', id: meter.channelIdHex, seq: 1, share: 12 },
    ]);
    expect(meter.status().secondsLeft).toBeCloseTo(10, 0);
    expect(meter.status().satsPaid).toBe(24);
  });

  it('a payment that lands just after the light went out still buys its full seconds (catch-up)', async () => {
    const m = fakeMesh();
    const c = clock();
    const meter = new ChannelMeter({ mesh: m.mesh, key: KEY, now: c.now, inFlightMs: 2_600 });
    await meter.start();
    await meter.addSats(12); // 10 s
    c.advance(9_000); // 1 s left now, but the commitment lands 2.6 s later
    await meter.addSats(12);
    const last = m.sent.filter((s) => s.kind === 'commit').at(-1)!;
    // consumed at landing ≈ 1.2 × 11.6 = 13.92 → 14; + 12
    expect(last.share).toBe(26);
  });

  it('a commitment the injector never broadcast does not advance the books', async () => {
    const m = fakeMesh(false);
    const meter = new ChannelMeter({ mesh: m.mesh, key: KEY, now: clock().now });
    const r = await meter.addSats(12);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/broadcast/);
    expect(meter.status().satsPaid).toBe(0);
    expect(meter.status().seq).toBe(0);
  });

  it('after a bridge restart, closes the remembered channel and opens a fresh one', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'meter-'));
    const statePath = join(dir, 'channel.json');
    const c = clock();
    const m1 = fakeMesh();
    const a = new ChannelMeter({ mesh: m1.mesh, key: KEY, now: c.now, statePath });
    await a.start();
    await a.addSats(12);
    const m2 = fakeMesh();
    const b = new ChannelMeter({ mesh: m2.mesh, key: KEY, now: c.now, statePath });
    await b.start();
    await b.addSats(12);
    const old = a.channelIdHex;
    expect(b.channelIdHex).not.toBe(old);
    expect(m2.sent).toEqual([
      { kind: 'commit', id: old, seq: 1, share: 12 },
      { kind: 'close', id: old, seq: 1, share: 12 },
      { kind: 'open', id: b.channelIdHex },
      { kind: 'commit', id: b.channelIdHex, seq: 1, share: 12 },
    ]);
  });
});

// ── the bridge in metered mode ───────────────────────────────────────
const RECEIVE_SCRIPT = new P2PKH().lock(PrivateKey.fromRandom().toPublicKey().toAddress()).toHex();
const OFFER: ActuatorOffer = {
  version: 1, costSats: 100, durationMs: 5000, lockScript: new Uint8Array(35),
  txTemplate: new Uint8Array(10), inputIdx: 0, inputValue: 50000n,
  offerId: sha256(new TextEncoder().encode('cellmesh.rentable-device.offer.v0')).slice(0, 16),
};
function pay(sats: number, n: number): string {
  const tx = new Transaction();
  tx.addOutput({ lockingScript: LockingScript.fromHex(RECEIVE_SCRIPT), satoshis: sats });
  tx.lockTime = n;
  return JSON.stringify({ transaction: tx.toHex() });
}

function meteredSetup() {
  const m = fakeMesh();
  const meter = new ChannelMeter({ mesh: m.mesh, key: KEY, now: clock().now });
  const bridge = new X402CellBridge({
    offer: OFFER, walletKey: KEY, mesh: m.mesh,
    verifier: new Brc29OnchainVerifier(RECEIVE_SCRIPT, { maxSats: 100 }),
    receiveScriptHex: RECEIVE_SCRIPT,
    meter, meterOptions: [12, 36, 72],
  });
  const handler = makeLightHandler(bridge, { clientJs: async () => '' });
  const call = (path: string, init: RequestInit = {}) => handler(new Request(`http://bridge.test${path}`, init));
  return { m, meter, call };
}

describe('light server --metered', () => {
  it('the 402 price is the amount the phone chose', async () => {
    const { call } = meteredSetup();
    const r = await call('/actuator/activate?sats=36', { method: 'POST' });
    expect(r.status).toBe(402);
    expect(r.headers.get('x-bsv-payment-satoshis-required')).toBe('36');
  });

  it('refuses an amount above --max-sats or below the smallest option', async () => {
    const { call } = meteredSetup();
    expect((await call('/actuator/activate?sats=500', { method: 'POST' })).status).toBe(400);
    expect((await call('/actuator/activate?sats=3', { method: 'POST' })).status).toBe(400);
  });

  it('a verified payment adds that many sats as one commitment and says how many seconds', async () => {
    const { call, m } = meteredSetup();
    const r = await call('/actuator/activate?sats=36', { method: 'POST', headers: { 'x-bsv-payment': pay(36, 1) } });
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body.secondsAdded).toBe(30);
    expect(body.message).toMatch(/30 s of light added/);
    const commits = m.sent.filter((s) => s.kind === 'commit');
    expect(commits.map((s) => s.share)).toEqual([36]);
    const meterNow = await (await call('/meter')).json();
    expect(meterNow.metered).toBe(true);
    expect(meterNow.secondsLeft).toBeCloseTo(30, 0);
    expect(meterNow.satsPaid).toBe(36);
  });

  it('underpaying the chosen amount is refused; a replay is still 409', async () => {
    const { call } = meteredSetup();
    const under = await call('/actuator/activate?sats=36', { method: 'POST', headers: { 'x-bsv-payment': pay(12, 2) } });
    expect(under.status).toBe(402);
    const p = pay(12, 3);
    expect((await call('/actuator/activate?sats=12', { method: 'POST', headers: { 'x-bsv-payment': p } })).status).toBe(200);
    expect((await call('/actuator/activate?sats=12', { method: 'POST', headers: { 'x-bsv-payment': p } })).status).toBe(409);
  });

  it('the page offers the amounts with their seconds', async () => {
    const { call } = meteredSetup();
    const html = await (await call('/')).text();
    for (const s of ['12 sats', '36 sats', '72 sats', '10 s', '30 s', '60 s']) expect(html).toContain(s);
    expect(html).toContain('data-sats="36"');
  });
});
