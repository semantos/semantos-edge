import { describe, it, expect } from 'bun:test';
import { PrivateKey, P2PKH, Transaction } from '@bsv/sdk';
import { Brc29OnchainVerifier } from '../onchain-payment.js';
import { X402CellBridge, type MeshPort } from '../bridge.js';
import { type ActuatorOffer, sha256 } from '../cell-codec.js';
import { makeLightHandler } from '../light.js';

// ── fixtures ─────────────────────────────────────────────────────────
const RECEIVE_ADDR = PrivateKey.fromRandom().toPublicKey().toAddress();
const RECEIVE_SCRIPT = new P2PKH().lock(RECEIVE_ADDR).toHex();
const WALLET = new PrivateKey('0000000000000000000000000000000000000000000000000000000000000042', 16);
const WP = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex'));
const LOCK = (() => { const b = new Uint8Array(35); b[0] = 0x21; b.set(WP, 1); b[34] = 0xac; return b; })();
const OFFER: ActuatorOffer = {
  version: 1, costSats: 100, durationMs: 5000, lockScript: LOCK,
  txTemplate: new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]), inputIdx: 0, inputValue: 50000n,
  offerId: sha256(new TextEncoder().encode('cellmesh.rentable-device.offer.v0')).slice(0, 16),
};

/** A distinct raw tx paying the bridge 100 sats (lockTime makes each unique). */
function paymentTx(n: number): { hex: string; txid: string } {
  const tx = new Transaction();
  tx.addOutput({ lockingScript: new P2PKH().lock(RECEIVE_ADDR), satoshis: 100 });
  tx.lockTime = n;
  return { hex: tx.toHex(), txid: tx.id('hex') };
}
const payHeader = (hex: string) => JSON.stringify({ transaction: hex });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * A mesh that records the order of events and acks each broadcast after
 * `ackDelayMs`. It counts how many activations overlap, so a test can prove
 * the queue never lets two run at once.
 */
function recordingMesh(ackDelayMs = 30) {
  const events: string[] = [];
  let n = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  const mesh: MeshPort = {
    async broadcast() {
      n++;
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      events.push(`broadcast${n}`);
    },
    async awaitActivation() {
      await sleep(ackDelayMs);
      events.push(`ack${n}`);
      inFlight--;
      return true;
    },
  };
  return { mesh, events, get broadcasts() { return n; }, get maxInFlight() { return maxInFlight; } };
}

function setup(mesh: MeshPort, extra: Partial<ConstructorParameters<typeof X402CellBridge>[0]> = {}) {
  const bridge = new X402CellBridge({
    offer: OFFER,
    walletKey: WALLET,
    mesh,
    verifier: new Brc29OnchainVerifier(RECEIVE_SCRIPT, { maxSats: 500 }),
    receiveScriptHex: RECEIVE_SCRIPT,
    holdMs: 0,
    ...extra,
  });
  const handler = makeLightHandler(bridge, { clientJs: async () => 'console.log("light")' });
  const call = (path: string, init: RequestInit = {}) => handler(new Request(`http://bridge.test${path}`, init));
  const activate = (hex: string, query = '') =>
    call(`/actuator/activate${query}`, { method: 'POST', headers: { 'x-bsv-payment': payHeader(hex) } });
  return { bridge, call, activate };
}

// ── the queue ────────────────────────────────────────────────────────

describe('light queue — one at a time, each waiter gets its own ack', () => {
  it('two concurrent paid requests light twice, in order, never overlapping', async () => {
    const m = recordingMesh();
    const { activate } = setup(m.mesh);
    const a = paymentTx(1);
    const b = paymentTx(2);
    const [ra, rb] = await Promise.all([activate(a.hex), activate(b.hex)]);
    expect(ra.status).toBe(200);
    expect(rb.status).toBe(200);
    expect((await ra.json()).txid).toBe(a.txid);
    expect((await rb.json()).txid).toBe(b.txid);
    expect(m.events).toEqual(['broadcast1', 'ack1', 'broadcast2', 'ack2']);
    expect(m.maxInFlight).toBe(1);
  });

  it('async mode answers 202 with a ticket and position, then GET /queue reports lit', async () => {
    const m = recordingMesh(60);
    const { activate, call } = setup(m.mesh);
    const a = paymentTx(11);
    const b = paymentTx(12);
    const ra = await activate(a.hex, '?async=1');
    const rb = await activate(b.hex, '?async=1');
    expect(ra.status).toBe(202);
    expect(rb.status).toBe(202);
    const ja = await ra.json();
    const jb = await rb.json();
    expect(ja.ticket).toBe(a.txid);
    expect(ja.ahead).toBe(0);
    expect(jb.ahead).toBe(1);

    const q1 = await (await call(`/queue?ticket=${b.txid}`)).json();
    expect(['queued', 'lighting']).toContain(q1.state);

    for (let i = 0; i < 50; i++) {
      const q = await (await call(`/queue?ticket=${b.txid}`)).json();
      if (q.state === 'lit') break;
      await sleep(20);
    }
    const qa = await (await call(`/queue?ticket=${a.txid}`)).json();
    const qb = await (await call(`/queue?ticket=${b.txid}`)).json();
    expect(qa.state).toBe('lit');
    expect(qb.state).toBe('lit');
    expect(typeof qb.litAt).toBe('string');
    expect(m.events).toEqual(['broadcast1', 'ack1', 'broadcast2', 'ack2']);

    const unknown = await (await call('/queue?ticket=nope')).json();
    expect(unknown.state).toBe('unknown');
  });

  it('a device that never answers gives an error, not a hang, and the queue moves on', async () => {
    let calls = 0;
    const mesh: MeshPort = {
      async broadcast() { calls++; if (calls === 1) await new Promise(() => {}); },
      async awaitActivation() { return true; },
    };
    const { activate } = setup(mesh, { activationTimeoutMs: 50, queueTimeoutMs: 100 });
    const [ra, rb] = await Promise.all([activate(paymentTx(21).hex), activate(paymentTx(22).hex)]);
    expect(ra.status).toBe(504);
    expect((await ra.json()).error).toMatch(/did not/);
    expect(rb.status).toBe(200);
  });

  it('a device that does not ack answers 504 and marks the ticket failed', async () => {
    const mesh: MeshPort = { async broadcast() {}, async awaitActivation() { return false; } };
    const { activate, call } = setup(mesh);
    const a = paymentTx(31);
    const r = await activate(a.hex);
    expect(r.status).toBe(504);
    const q = await (await call(`/queue?ticket=${a.txid}`)).json();
    expect(q.state).toBe('failed');
    expect(q.error).toMatch(/did not acknowledge/);
  });
});

// ── replay ───────────────────────────────────────────────────────────

describe('light dedupe — a payment lights once', () => {
  it('a replayed tx is refused with 409 and never re-lights', async () => {
    const m = recordingMesh(5);
    const { activate } = setup(m.mesh);
    const a = paymentTx(41);
    expect((await activate(a.hex)).status).toBe(200);
    const again = await activate(a.hex);
    expect(again.status).toBe(409);
    expect((await again.json()).error).toMatch(/already used/);
    expect(m.broadcasts).toBe(1);
  });

  it('the same tx sent twice at once lights once', async () => {
    const m = recordingMesh(5);
    const { activate } = setup(m.mesh);
    const a = paymentTx(42);
    const rs = await Promise.all([activate(a.hex), activate(a.hex)]);
    expect(rs.map((r) => r.status).sort()).toEqual([200, 409]);
    expect(m.broadcasts).toBe(1);
  });

  it('dedupes in dry-run too (default verifier, no txid from the verifier)', async () => {
    const m = recordingMesh(5);
    const bridge = new X402CellBridge({ offer: OFFER, walletKey: WALLET, mesh: m.mesh, holdMs: 0 });
    const a = paymentTx(43);
    expect((await bridge.activate(payHeader(a.hex))).status).toBe(200);
    expect((await bridge.activate(payHeader(a.hex))).status).toBe(409);
    expect(m.broadcasts).toBe(1);
  });
});

// ── HTTP surface ─────────────────────────────────────────────────────

describe('light HTTP — CORS, page, body payment', () => {
  it('OPTIONS answers 204 with CORS headers that allow x-bsv-payment', async () => {
    const { call } = setup(recordingMesh().mesh);
    const r = await call('/actuator/activate', { method: 'OPTIONS' });
    expect(r.status).toBe(204);
    expect(r.headers.get('access-control-allow-origin')).toBe('*');
    expect(r.headers.get('access-control-allow-headers')!.toLowerCase()).toContain('x-bsv-payment');
    expect(r.headers.get('access-control-allow-methods')).toContain('POST');
  });

  it('the 402 challenge exposes the x-bsv-payment-* headers cross-origin', async () => {
    const { call } = setup(recordingMesh().mesh);
    const r = await call('/actuator/activate', { method: 'POST' });
    expect(r.status).toBe(402);
    expect(r.headers.get('access-control-allow-origin')).toBe('*');
    const exposed = r.headers.get('access-control-expose-headers')!.toLowerCase();
    expect(exposed).toContain('x-bsv-payment-satoshis-required');
    expect(exposed).toContain('x-bsv-payment-derivation-prefix');
    expect(exposed).toContain('x-bsv-payment-txid');
  });

  it('GET / and GET /light serve the phone page with the button', async () => {
    const { call } = setup(recordingMesh().mesh);
    for (const p of ['/', '/light']) {
      const r = await call(p);
      expect(r.status).toBe(200);
      expect(r.headers.get('content-type')).toContain('text/html');
      const html = await r.text();
      expect(html).toContain('Turn the light on');
      expect(html).toContain('100 sats');
      expect(html).toContain('/light.js');
      expect(html).toContain('width=device-width');
    }
  });

  it('GET /light.js serves the client script', async () => {
    const { call } = setup(recordingMesh().mesh);
    const r = await call('/light.js');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('javascript');
    expect(await r.text()).toContain('light');
  });

  it('GET /light.js is gzipped for a client that accepts it', async () => {
    const { call } = setup(recordingMesh().mesh);
    const r = await call('/light.js', { headers: { 'accept-encoding': 'gzip, deflate, br' } });
    expect(r.status).toBe(200);
    expect(r.headers.get('content-encoding')).toBe('gzip');
    const raw = new Uint8Array(await r.arrayBuffer());
    expect(new TextDecoder().decode(Bun.gunzipSync(raw))).toBe('console.log("light")');
  });

  it('accepts the payment in a JSON body when the header would be too big', async () => {
    const m = recordingMesh(5);
    const { call } = setup(m.mesh);
    const a = paymentTx(51);
    const r = await call('/actuator/activate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ transaction: a.hex }),
    });
    expect(r.status).toBe(200);
    expect(m.broadcasts).toBe(1);
  });

  it('GET /.well-known/x402-info still answers, with CORS', async () => {
    const { call } = setup(recordingMesh().mesh);
    const r = await call('/.well-known/x402-info');
    expect(r.status).toBe(200);
    expect(r.headers.get('access-control-allow-origin')).toBe('*');
    expect((await r.json()).payTo.scriptHex).toBe(RECEIVE_SCRIPT);
  });
});

describe('light client bundle', () => {
  it('bundles the browser client with @bsv/sdk', async () => {
    const { buildLightClient } = await import('../light.js');
    const js = await buildLightClient();
    expect(js.length).toBeGreaterThan(10_000);
    expect(js).toContain('/actuator/activate');
  }, 30_000);
});
