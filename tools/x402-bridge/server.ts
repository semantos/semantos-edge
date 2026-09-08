#!/usr/bin/env bun
/**
 * server.ts — runs the x402↔cell bridge as an HTTP server.
 *
 *   bun server.ts [--port 4021]
 *                 [--inject-port /dev/cu.usbmodemXXX --ack-port /dev/cu.usbmodemYYY]
 *
 * A Dolphin Milk-style agent pays this endpoint over BSV-native x402; the
 * bridge actuates a rentable cell-mesh device. See README.md.
 *
 * Mesh transport:
 *   default (no serial flags): dry-run — logs the actuator_activate cell
 *     and auto-acknowledges, so the HTTP x402 flow is exercisable sans HW.
 *   --inject-port + --ack-port: live mesh. Frames the cell to the injector
 *     C6 over USB-CDC (firmware serial_inject_task broadcasts it) and reads
 *     the rentable C6's "*** ACTUATOR ACTIVATED ***" line for the ACK.
 *     Inject via a NON-actuator device (e.g. B) so the ack is unambiguous.
 */

import { PrivateKey } from '@bsv/sdk';
import { startSigner } from './signer.js';
import {
  type ActuatorOffer,
  sha256,
} from './cell-codec.js';
import { X402CellBridge, type MeshPort, type BridgeConfig } from './bridge.js';
import { SerialMeshPort } from './serial-mesh.js';
import { getPublicKey, p2pkhScriptHexFromPubkey, METANET_BASE, DEFAULT_ORIGIN } from './metanet.js';
import { Brc29OnchainVerifier } from './onchain-payment.js';

// ── Provisioned offer (matches sign-cell-deck.ts RENTABLE_* constants) ──
// Cell authority. The device verifies every signed cell against the trust
// anchor in its firmware, so this must BE that anchor — it is the fleet
// operator root by default. Nothing here spends on-chain, so there is no
// second key to keep apart.
const WALLET = startSigner().key;
const WALLET_PUB = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex'));
const RENTABLE_LOCK = (() => {
  const b = new Uint8Array(35);
  b[0] = 0x21; b.set(WALLET_PUB, 1); b[34] = 0xac;
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

// ── Mesh transports ──────────────────────────────────────────────────

/** Dry-run mesh: log the cell, auto-ACK. Lets the HTTP flow run sans HW. */
const dryRunMesh: MeshPort = {
  async broadcast(cell, sig) {
    const hex = Buffer.from(cell).toString('hex');
    console.log(`[mesh:dry-run] would broadcast actuator_activate cell (1024B) + sig(${sig.length}B)`);
    console.log(`[mesh:dry-run] cell[0:64]=${hex.slice(0, 128)}…`);
  },
  async awaitActivation() {
    console.log('[mesh:dry-run] auto-ACK (no device)');
    return true;
  },
};

// ── CLI ──────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const port = flag('--port') ? Number(flag('--port')) : 4021;
const injectPort = flag('--inject-port');
const ackPort = flag('--ack-port');
// Optional: require the actuator's ack to name the injector's MAC, so it
// can't false-match the deck's own (device-A) activations on the mesh.
const ackFromMac = flag('--ack-from-mac');

let mesh: MeshPort = dryRunMesh;
let meshLabel = 'dry-run (auto-ACK)';
if (injectPort && ackPort) {
  const ackMatch = ackFromMac
    ? `*** ACTUATOR ACTIVATED *** from=[${ackFromMac}]`
    : undefined;
  mesh = new SerialMeshPort({ injectPort, ackPort, ackMatch });
  meshLabel = `serial — inject ${injectPort}, ack ${ackPort}${ackFromMac ? ` (from=${ackFromMac})` : ''}`;
}

// ── Real-payment mode (MAINNET) ───────────────────────────────────────
// --real-payment derives a recoverable receive key from Metanet Desktop
// (:3321, the same wallet that funds the MNCA anchor), advertises it, and
// verifies the agent's tx actually pays it (≤ --max-sats cap) before
// broadcasting via ARC and actuating. Without the flag the bridge runs the
// simulated verifier (no real money).
const realPayment = args.includes('--real-payment');
const metanetBase = flag('--metanet') ?? METANET_BASE;
const metanetOrigin = flag('--metanet-origin') ?? DEFAULT_ORIGIN;
const maxSats = flag('--max-sats') ? Number(flag('--max-sats')) : 1000;
let payLabel = 'simulated (no real tx)';

const bridgeCfg: BridgeConfig = { offer: OFFER, walletKey: WALLET, mesh };
if (realPayment) {
  const offerIdHex = Buffer.from(OFFER.offerId).toString('hex');
  const receivePk = await getPublicKey(
    { protocolID: [2, 'x402 actuator payment'], keyID: offerIdHex, counterparty: 'self' },
    metanetBase,
    metanetOrigin,
  );
  const receiveScriptHex = p2pkhScriptHexFromPubkey(receivePk);
  // Metanet Desktop's createAction returns a SIGNED but un-broadcast tx, so
  // the bridge broadcasts to settle on-chain (default). --no-bridge-broadcast
  // is for wallets that pre-broadcast and hand over the txid.
  const bridgeBroadcast = !args.includes('--no-bridge-broadcast');
  bridgeCfg.receiveScriptHex = receiveScriptHex;
  bridgeCfg.verifier = new Brc29OnchainVerifier(receiveScriptHex, { maxSats });
  bridgeCfg.broadcastOnVerify = bridgeBroadcast;
  bridgeCfg.arc = {};
  payLabel = `MAINNET — pay-to ${receiveScriptHex.slice(0, 12)}… (cap ${maxSats} sats), ${bridgeBroadcast ? 'bridge broadcasts via ARC (SDK)' : 'payer-broadcast, bridge verifies'}`;
}

const bridge = new X402CellBridge(bridgeCfg);

function send(r: { status: number; headers: Record<string, string>; body: unknown }): Response {
  return new Response(JSON.stringify(r.body), { status: r.status, headers: r.headers });
}

const server = Bun.serve({
  port,
  // activate() may broadcast (with best-effort retries) + wait for the
  // device ack — longer than Bun's 10s default request timeout.
  idleTimeout: 30,
  async fetch(req) {
    const url = new URL(req.url);
    if (req.method === 'GET' && url.pathname === '/.well-known/x402-info') {
      return send(bridge.discover());
    }
    if (req.method === 'POST' && url.pathname === '/actuator/activate') {
      return send(await bridge.activate(req.headers.get('x-bsv-payment')));
    }
    return new Response(JSON.stringify({ error: 'not found' }), { status: 404, headers: { 'content-type': 'application/json' } });
  },
});

console.log(`x402↔cell bridge listening on http://localhost:${server.port}`);
console.log(`  GET  /.well-known/x402-info     — free discovery (price=${OFFER.costSats} sats)`);
console.log(`  POST /actuator/activate          — 402 challenge → pay via x-bsv-payment → actuate`);
console.log(`  mesh:    ${meshLabel}`);
console.log(`  payment: ${payLabel}`);
