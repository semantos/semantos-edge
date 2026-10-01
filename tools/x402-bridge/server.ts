#!/usr/bin/env bun
/**
 * server.ts — runs the x402↔cell bridge as an HTTP server.
 *
 *   bun server.ts [--port 4021]
 *                 [--inject-port /dev/cu.usbmodemXXX --ack-port /dev/cu.usbmodemYYY]
 *                 [--ack-from-mac aa:bb:.. | --ack-match "<log substring>"]
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
import { makeLightHandler, buildLightClient } from './light.js';

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

// Optional: override the ack line outright. With only ONE mesh_demo board on
// the bench there is no second board to actuate; `--ack-port <same as inject>
// --ack-match "CELL INJECTED"` acks on the injector's own ack-blink instead.
const ackMatchFlag = flag('--ack-match');

let mesh: MeshPort = dryRunMesh;
let meshLabel = 'dry-run (auto-ACK)';
let serialMesh: SerialMeshPort | undefined;
if (injectPort && ackPort) {
  const ackMatch = ackMatchFlag
    ?? (ackFromMac ? `*** ACTUATOR ACTIVATED *** from=[${ackFromMac}]` : undefined);
  serialMesh = new SerialMeshPort({ injectPort, ackPort, ackMatch });
  mesh = serialMesh;
  meshLabel = `serial — inject ${injectPort}, ack ${ackPort} on "${ackMatch ?? '*** ACTUATOR ACTIVATED ***'}"`;
}
// Release the serial port on exit: the ack reader is a `cat` child that
// would otherwise outlive the server and hold the tty.
for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => { serialMesh?.dispose(); process.exit(0); });
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

// Bundle the phone page's client now, so a build failure shows at start
// rather than on the first phone.
try {
  const js = await buildLightClient();
  console.log(`[light] phone client bundled (${Math.round(js.length / 1024)} KB)`);
} catch (e) {
  console.error(`[light] phone client build FAILED: ${(e as Error).message}`);
}

const server = Bun.serve({
  port,
  // A blocking (non-async) activate waits its turn in the queue + the device
  // ack. The phone page uses ?async=1 and polls, so this only matters to agents.
  idleTimeout: 255,
  fetch: makeLightHandler(bridge),
});

console.log(`x402↔cell bridge listening on http://localhost:${server.port}`);
console.log(`  GET  /.well-known/x402-info     — free discovery (price=${OFFER.costSats} sats)`);
console.log(`  POST /actuator/activate          — 402 challenge → pay via x-bsv-payment → queued actuation`);
console.log(`  GET  /  (/light)                 — phone page: "turn the light on"`);
console.log(`  GET  /queue?ticket=<txid>        — place in the queue / lit / failed`);
console.log(`  mesh:    ${meshLabel}`);
console.log(`  payment: ${payLabel}`);
