#!/usr/bin/env bun
/**
 * mesh-control.ts — a browser control plane for the C6 cell-mesh.
 *
 * The bare XIAOs are headless (no buttons), so the "buttons" live in a
 * browser: a page of clickable controls that POST to this bun server,
 * which signs + injects cells into the mesh through a connected C6 (the
 * #558 serial-injection path) — next to a live feed of tailed device
 * serial. Click a button, watch the swarm react.
 *
 *   bun mesh-control.ts [--http-port 4040] [--inject-port /dev/cu.usbmodemB] \
 *                       [--tail /dev/cu.usbmodemA,/dev/cu.usbmodemC] [--baud 115200]
 *
 *   GET  /            → the control panel (web/control.html)
 *   GET  /events      → SSE stream of tailed device serial
 *   POST /inject      → { kind:'rule'|'tap'|'heartbeat'|'scripted',
 *                         trigger?, blinkMs?, quorum?{n,windowMs} } → inject
 */

import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { startSigner } from './signer.js';
import { openSync, writeSync, closeSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrivateKey, ECDSA, BigNumber } from '@bsv/sdk';
import { mintCell, signCell, typeHash, writeU16LE, writeU32LE, sha256, ecdsaDer, buildActuatorActivate, type ActuatorOffer } from './cell-codec.js';
import { frameCell } from './serial-mesh.js';
import { domainForType } from './cell-domains.js';
import { getPublicKey, createSignature, createAction, rawTxHexFromCreateAction, p2pkhScriptHexFromPubkey, DEFAULT_ORIGIN, METANET_BASE } from './metanet.js';
import { broadcastTxHex } from './arc.js';
import { encodeScadaCell, anchorScadaCell, deriveScadaLeaf, SCADA_ACTION } from './scada-anchor.js';
import { buildCapabilityInterlockActuator, interlockCheckSigLock, interlockSighash } from './interlock.js';
import { openChannel, accumulateHop, settleChannel, channelIdFromTxid,
         type ChannelState, CHANNEL_FUNDING_SATS, SETTLE_THRESHOLD_SATS } from './channel-anchor.js';
import { deriveChannelRelayKey, buildCapabilityCertCell, CAPABILITY_V0_TYPE, CAP_ROUTE_FWD_V1 } from './capability-cert.js';
import { validateMncaTransition, type ValidateRequest } from './mnca-oracle.js';

const flag = (n: string, d?: string) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const httpPort = Number(flag('--http-port', '4040'));
const injectPort = flag('--inject-port', '/dev/cu.usbmodem21201')!;
// Forward cells must be injected from a port != segments[0] device: a board
// broadcasts over ESP-NOW and never receives its own broadcast, so injecting a
// forward cell into the very board it is addressed to means nobody processes it.
//
// segments[0] is MAC_B, so this must NOT be MAC_B's port. The default said
// MAC_A in the comment and named MAC_B's port (…21301) in the code — the
// comment was right and the value was wrong, and the result was a forward cell
// that every board correctly ignored. Verified on hardware: with …21201 the
// cell reaches MAC_B and relays; with …21301 it goes nowhere.
const fwdInjectPort = flag('--forward-inject-port', '/dev/cu.usbmodem21201')!;
const tailPorts = (flag('--tail', '/dev/cu.usbmodem21301,/dev/cu.usbmodem21401')!).split(',').filter(Boolean);
const baud = flag('--baud', '115200')!;
const WEB = join(dirname(fileURLToPath(import.meta.url)), 'web', 'control.html');

// ── Two keys, two jobs. Do not merge them. ──────────────────────────────────
//
// WALLET signs CELLS. A device checks every signed cell against the trust
// anchor compiled into its firmware, so this must equal that anchor — the
// fleet operator root by default. See signer.ts.
const WALLET = startSigner().key;

// CHAIN_WALLET funds and settles ON-CHAIN. openChannel() locks real sats to
// its pubkey and settleChannel() spends them, so it must stay wherever the
// money already is — moving it with the signing key would strand any balance
// at the old address. It is deliberately the original demo key, and it is only
// reachable behind --real-payment.
const CHAIN_WALLET = new PrivateKey(
  process.env.MESH_CHAIN_KEY_HEX?.trim()
    ?? '0000000000000000000000000000000000000000000000000000000000000042',
  16,
);
const WALLET_PUB = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex'));
const OWNER = WALLET_PUB.subarray(0, 16);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ── x402 mainnet pay+actuate (opt-in via --real-payment) ─────────────
const realPayment = process.argv.includes('--real-payment');
const metanetBase = flag('--metanet', METANET_BASE)!;
const metanetOrigin = flag('--metanet-origin', DEFAULT_ORIGIN)!;
const maxSats = Number(flag('--max-sats', '1000'));
const RENTABLE_LOCK = (() => { const b = new Uint8Array(35); b[0] = 0x21; b.set(WALLET_PUB, 1); b[34] = 0xac; return b; })();
const RENTABLE_TX = new Uint8Array([1,0,0,0,1,...new Uint8Array(32),0,0,0,0,0,255,255,255,255,1,0x10,0x27,0,0,0,0,0,0,1,0x51,0,0,0,0]);
const OFFER: ActuatorOffer = {
  version: 1, costSats: 100, durationMs: 5000, lockScript: RENTABLE_LOCK, txTemplate: RENTABLE_TX,
  inputIdx: 0, inputValue: 50000n, offerId: sha256(new TextEncoder().encode('cellmesh.rentable-device.offer.v0')).slice(0, 16),
};
let actuatorCounter = 0;

// The SCADA permissive is no longer a constant — it's a capability the Plexus
// "hat" holds: a BRC-42-edge-derived key (protocolID names the capability,
// counterparty='self' is the edge). Clearing the interlock requires a
// signature from THAT key (Metanet Desktop, the hat). The operator (wallet)
// can request actuation but cannot clear the safety interlock.
// BRC-43 protocol names: letters, numbers, spaces only (no dots/dashes).
const CAP_PROTOCOL: [number, string] = [2, 'plexus cap scada permissive'];
const CAP_KEYID = 'actuator C';
let capPubkey = ''; // derived from MD on first use

// Clear (or attempt to clear) the interlock + actuate. With the capability,
// the hat signs the interlock sighash → device ACCEPT. Without it, the
// operator wallet signs → CHECKSIG vs the capability key fails → device REJECT.
async function clearInterlock(withCapability: boolean): Promise<void> {
  if (!capPubkey) capPubkey = await getPublicKey({ protocolID: CAP_PROTOCOL, keyID: CAP_KEYID, counterparty: 'self' }, metanetBase, metanetOrigin);
  const lock = interlockCheckSigLock(capPubkey);
  const sighash = interlockSighash(lock, OFFER.inputIdx, OFFER.inputValue);
  let sigDer: Uint8Array;
  if (withCapability) {
    // The hat (Plexus capability holder) signs under the capability edge.
    sigDer = new Uint8Array(await createSignature({ protocolID: CAP_PROTOCOL, keyID: CAP_KEYID, counterparty: 'self', hashToDirectlySign: Array.from(sighash) }, metanetBase, metanetOrigin));
  } else {
    // Operator override attempt — sign with the plain wallet key (not the
    // capability). CHECKSIG against the capability pubkey will fail.
    sigDer = ecdsaDer(ECDSA.sign(new BigNumber(Array.from(sighash) as unknown as number[]), WALLET, true) as unknown as { r: unknown; s: unknown });
  }
  const { cell, sig } = buildCapabilityInterlockActuator({
    walletKey: WALLET, ownerId: OWNER, offerId: OFFER.offerId, capPubkeyHex: capPubkey, sigDer,
    txTemplate: OFFER.txTemplate, inputIdx: OFFER.inputIdx, inputValue: OFFER.inputValue,
    timestampMs: BigInt(Date.now()), counter: actuatorCounter++,
  });
  await injectCellSig(cell, sig);
  broadcast(`[ctl] interlock: ${withCapability ? `hat capability "${CAP_PROTOCOL[1]}" SIGNED` : 'operator override (no capability)'} → device ${withCapability ? 'should ACCEPT + energize' : 'should REJECT (interlock holds)'}`);
}
// ── SRv6-style forward-cell MACs (must match main.c MAC_A/B/C constants) ──
// A=originator (21301), B=relay (21201), C=destination (21401)
const MAC_B = new Uint8Array([0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0x54]);
const MAC_C = new Uint8Array([0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0xf8]);

// ── forward.v1 channel state tracking ───────────────────────────────
// Each relay/destination has a pre-opened channel (channel_id=0x00..00)
// with the source wallet.  The source increments seq + device_share on
// each injection.  In-memory only — reset when the control plane restarts.
const FWD_V1_HOP_COST = 10;  // sats credited per hop (matches firmware FWD_V1_HOP_COST_SATS)
const fwdV1Ch: Record<'B'|'C', { seq: number; share: number }> = {
  B: { seq: 0, share: 0 },
  C: { seq: 0, share: 0 },
};

const TYPES: Record<string, Uint8Array> = {
  heartbeat:      typeHash('cellmesh.heartbeat.v0'),
  tap:            typeHash('cellmesh.tap.v0'),
  scripted:       typeHash('cellmesh.scripted.v0'),
  rule:           typeHash('cellmesh.rule.v0'),
  forward:        typeHash('cellmesh.forward.v0'),
  forwardV1:      typeHash('cellmesh.forward.v1'),
  forwardV2:      typeHash('cellmesh.forward.v2'),
  routingContV0:  typeHash('cellmesh.routing.cont.v0'),
  capabilityV0:   CAPABILITY_V0_TYPE,
  channelSettle:  typeHash('cellmesh.channel_settle.v0'),
};

// ── forward.v2 channel state tracking ───────────────────────────────
// Mirrors fwdV1Ch but for the 2-cell burst (Cell A + Cell B).
// Per-hop costs and channel binding are identical to v1.
const fwdV2Ch: Record<'B'|'C', { seq: number; share: number }> = {
  B: { seq: 0, share: 0 },
  C: { seq: 0, share: 0 },
};

// ── Active on-chain channel (null until POST /open-channel) ──────────
let activeChannel: ChannelState | null = null;

/** Build cellmesh.channel_settle.v0 payload:
 *  channel_id[16] | final_seq u32 LE | device_share u32 LE | settle_txid[32]  */
function buildSettlePayload(ch: ChannelState, settleTxid: string): Uint8Array {
  const p = new Uint8Array(16 + 4 + 4 + 32);
  p.set(ch.channelId, 0);
  writeU32LE(p, 16, ch.finalSeq);
  writeU32LE(p, 20, ch.deviceShareAccum);
  p.set(Buffer.from(settleTxid, 'hex'), 24);
  return p;
}

// ── BRC-42 per-channel relay key cache ───────────────────────────────────────
// Relay keys are derived lazily per-channel: HMAC(master_sk, label + channelIdHex).
// This keeps private key material out of the static init path and supports
// channel rotation via POST /open-channel.
const DEMO_CHANNEL_ID = new Uint8Array(16);  // all-zeros demo sentinel
const DEMO_CHANNEL_ID_HEX = '0'.repeat(32);

// Active channel — updated by POST /open-channel.
let s_currentChannelId    = DEMO_CHANNEL_ID;
let s_currentChannelIdHex = DEMO_CHANNEL_ID_HEX;

// Relay key cache: channelIdHex → { sk, pk }.  One entry per channel.
const s_relayKeys = new Map<string, ReturnType<typeof deriveChannelRelayKey>>();
function getRelayKey(channelIdHex: string) {
  let k = s_relayKeys.get(channelIdHex);
  if (!k) { k = deriveChannelRelayKey(WALLET, channelIdHex); s_relayKeys.set(channelIdHex, k); }
  return k;
}

// BRC-108 cert hash cache: channelIdHex → SHA-256(capability cert payload[66]).
// Populated when injectCapabilityCert runs; cleared when /open-channel resets state.
const s_certHashes = new Map<string, Uint8Array>();

let s_capCertInjected = false;  // true once a cert has been injected for the active channel
let counter = 1;

function encodeRule(triggerType: Uint8Array, blinkMs: number, quorum?: { n: number; windowMs: number }): Uint8Array {
  const buf = new Uint8Array(139);
  buf[0] = 0x01;
  buf[1] = quorum ? 0x02 : 0x01;
  buf.set(triggerType, 2);
  if (quorum) { buf[34] = quorum.n & 0xff; writeU16LE(buf, 35, quorum.windowMs); buf[37] = quorum.n & 0xff; }
  buf[38] = 0x01;
  writeU16LE(buf, 39, blinkMs);
  return buf;
}

// Build the payload region (header + inner) for a cellmesh.forward.v0 cell.
// Wire layout (matches cell_forward.h):
//   0-15   flow_id         — 16 bytes derived from timestamp
//   16     hop_index       — 0 (source always starts at 0)
//   17     total_hops      — segmentMacs.length
//   18     segments_remaining — segmentMacs.length
//   19     hop_verb        — CM_HOP_VERB_NONE=0 | EVAL_RULES=1 | INSTALL_RULE=2
//   20-23  inner_payload_len — LE u32
//   24-47  segments[4][6]  — next-hop MACs; unused slots zeroed
//   48+    inner_payload   — opaque (rule bytes for INSTALL_RULE, empty for EVAL_RULES)
function buildForwardPayload(
  hopVerb: number,
  segmentMacs: Uint8Array[],
  innerPayload: Uint8Array,
): Uint8Array {
  const HEADER = 48;
  const buf = new Uint8Array(HEADER + innerPayload.length);
  // flow_id: deterministic but unique — sha256 of timestamp LE bytes
  const seed = new Uint8Array(8);
  const now = BigInt(Date.now());
  for (let i = 0; i < 8; i++) seed[i] = Number((now >> BigInt(i * 8)) & 0xffn);
  buf.set(sha256(seed).subarray(0, 16), 0);
  buf[16] = 0;                       // hop_index
  buf[17] = segmentMacs.length;      // total_hops
  buf[18] = segmentMacs.length;      // segments_remaining
  buf[19] = hopVerb;
  writeU32LE(buf, 20, innerPayload.length);
  for (let i = 0; i < Math.min(segmentMacs.length, 4); i++) {
    buf.set(segmentMacs[i].subarray(0, 6), 24 + i * 6);
  }
  if (innerPayload.length > 0) buf.set(innerPayload, HEADER);
  return buf;
}

// Build the payload region for a cellmesh.forward.v1 cell (channel-gated).
// Extends buildForwardPayload: inserts 272 bytes of per-hop commitment slots
// (4 × 68 bytes, matching cm_channel_commitment_t wire layout) between the
// segment table (offset 24) and inner_payload (offset 320).
//
// commitments[i] is the pre-signed commitment for the device at hop i.
// Each commitment (68 bytes on wire):
//   [0..15]  channelId[16]
//   [16..19] seq (LE u32)
//   [20..23] device_share (LE u32)
//   [24..27] user_share (LE u32)
//   [28..35] expiry_ms (LE u64)
//   [36..67] cert_hash[32] — SHA-256(cap cert payload), BRC-108 binding
// Unused slots are zeroed.
function buildForwardV1Payload(
  hopVerb: number,
  segmentMacs: Uint8Array[],
  commitments: Array<{ channelId: Uint8Array; seq: number; share: number; expiryMs: bigint; certHash?: Uint8Array }>,
  innerPayload: Uint8Array,
): Uint8Array {
  const COMMIT_SLOT = 68;      // CM_CHANNEL_COMMITMENT_PAYLOAD_BYTES (was 36, +32 cert_hash)
  const V1_HEADER   = 320;     // 48 (v0 base) + 4*68 (commitments) (was 192)
  const buf = new Uint8Array(V1_HEADER + innerPayload.length);

  // v0-compatible base header (bytes 0-47) — flow_id, hop_index, total_hops,
  // segments_remaining, hop_verb, inner_payload_len, segments[4][6]
  const seed = new Uint8Array(8);
  const now = BigInt(Date.now());
  for (let i = 0; i < 8; i++) seed[i] = Number((now >> BigInt(i * 8)) & 0xffn);
  buf.set(sha256(seed).subarray(0, 16), 0);   // flow_id
  buf[16] = 0;                                 // hop_index
  buf[17] = segmentMacs.length;                // total_hops
  buf[18] = segmentMacs.length;                // segments_remaining
  buf[19] = hopVerb;
  writeU32LE(buf, 20, innerPayload.length);    // inner_payload_len
  for (let i = 0; i < Math.min(segmentMacs.length, 4); i++) {
    buf.set(segmentMacs[i].subarray(0, 6), 24 + i * 6);
  }

  // Commitment array (bytes 48-319): 4 slots × 68 bytes each
  for (let i = 0; i < Math.min(commitments.length, 4); i++) {
    const c = commitments[i];
    const off = 48 + i * COMMIT_SLOT;
    buf.set(c.channelId.subarray(0, 16), off);       // channel_id [0..15]
    writeU32LE(buf, off + 16, c.seq);                // seq
    writeU32LE(buf, off + 20, c.share);              // device_share
    writeU32LE(buf, off + 24, Math.max(0, 100000 - c.share));  // user_share
    // expiry_ms: LE u64 — write as two u32s
    const exp = c.expiryMs;
    writeU32LE(buf, off + 28, Number(exp & 0xffffffffn));
    writeU32LE(buf, off + 32, Number((exp >> 32n) & 0xffffffffn));
    // cert_hash[32] at offset 36 — BRC-108 binding (zeros if not provided)
    if (c.certHash && c.certHash.length === 32) {
      buf.set(c.certHash, off + 36);
    }
  }

  if (innerPayload.length > 0) buf.set(innerPayload, V1_HEADER);
  return buf;
}

// ── forward.v2 Cell A + Cell B payload builders ──────────────────────
//
// Cell A wire layout (offsets in the 768-byte payload region):
//   0-15  flow_id[16]         — correlates with Cell B (same bytes)
//   16    hop_index           = 0
//   17    total_hops          = segmentMacs.length
//   18    hop_verb
//   19    flags               = 0x01  (CM_FWD_V2_FLAG_ROUTING_CONT)
//   20-23 inner_payload_len   (LE u32; ≤744)
//   24+   inner_payload       (≤744 bytes)
//
// Cell B wire layout:
//   0-15  flow_id[16]         — MUST match Cell A
//   16    hop_index           = 0
//   17    segments_remaining  = segmentMacs.length
//   18-23 reserved[6]        = zeros
//   24-47 segments[4][6]     — next-hop MACs
//   48-319 hop_commitments[4][68] — same layout as v1 per-hop slots
//   (320-767 unused)
function buildForwardV2PayloadA(
  flowId: Uint8Array,       // 16 bytes
  hopVerb: number,
  segmentCount: number,     // total_hops = segments_remaining at source
  innerPayload: Uint8Array, // ≤712 bytes
  routingDigest: Uint8Array,// SHA-256 of the whole 1024-byte Cell B
): Uint8Array {
  // 24 + 32. Cell A is signed and Cell B is not, and Cell B carries the route
  // and the payment commitments — so Cell A commits to Cell B's exact bytes and
  // the origin's signature covers the route transitively. Cell B must therefore
  // be minted BEFORE Cell A.
  const V2_HEADER = 56;
  if (routingDigest.length !== 32) throw new Error('routingDigest must be 32 bytes');
  const buf = new Uint8Array(V2_HEADER + innerPayload.length);
  buf.set(flowId.subarray(0, 16), 0);               // flow_id
  buf[16] = 0;                                       // hop_index
  buf[17] = segmentCount;                            // total_hops
  buf[18] = hopVerb;
  buf[19] = 0x01;                                    // CM_FWD_V2_FLAG_ROUTING_CONT
  writeU32LE(buf, 20, innerPayload.length);          // inner_payload_len
  buf.set(routingDigest, 24);                        // routing_digest
  if (innerPayload.length > 0) buf.set(innerPayload, V2_HEADER);
  return buf;
}

function buildForwardV2PayloadB(
  flowId: Uint8Array,       // 16 bytes — same as Cell A's flow_id
  segmentMacs: Uint8Array[], // next-hop MACs (≤4)
  commitments: Array<{ channelId: Uint8Array; seq: number; share: number; expiryMs: bigint; certHash?: Uint8Array }>,
): Uint8Array {
  const COMMIT_SLOT = 68;
  const B_USED = 320;      // CM_ROUTING_CONT_USED_BYTES
  const buf = new Uint8Array(B_USED);
  buf.set(flowId.subarray(0, 16), 0);               // flow_id
  buf[16] = 0;                                       // hop_index
  buf[17] = segmentMacs.length;                      // segments_remaining
  // reserved[6] at 18-23 stays zero
  for (let i = 0; i < Math.min(segmentMacs.length, 4); i++) {
    buf.set(segmentMacs[i].subarray(0, 6), 24 + i * 6); // segments[i]
  }
  // Commitment slots at offsets 48…319 — same per-slot layout as v1
  for (let i = 0; i < Math.min(commitments.length, 4); i++) {
    const c   = commitments[i];
    const off = 48 + i * COMMIT_SLOT;
    buf.set(c.channelId.subarray(0, 16), off);
    writeU32LE(buf, off + 16, c.seq);
    writeU32LE(buf, off + 20, c.share);
    writeU32LE(buf, off + 24, Math.max(0, 100000 - c.share)); // user_share
    const exp = c.expiryMs;
    writeU32LE(buf, off + 28, Number(exp & 0xffffffffn));
    writeU32LE(buf, off + 32, Number((exp >> 32n) & 0xffffffffn));
    if (c.certHash && c.certHash.length === 32) buf.set(c.certHash, off + 36);
  }
  return buf;
}

// Serialize all serial-port writes — rapid button clicks must NOT open the
// inject port concurrently (that throws / corrupts and can take the server
// down). Each inject queues behind the previous, regardless of outcome.
let injectChain: Promise<unknown> = Promise.resolve();
function serialize<T>(fn: () => Promise<T>): Promise<T> {
  const run = injectChain.then(fn, fn);
  injectChain = run.catch(() => {});
  return run;
}
async function injectCellSig(cell: Uint8Array, sig: Uint8Array, port = injectPort): Promise<void> {
  const frame = Buffer.from(frameCell(cell, sig));
  await serialize(async () => {
    for (let r = 0; r < 2; r++) {
      const fd = openSync(port, 'w');
      try { for (let o = 0; o < frame.length; o += 256) { writeSync(fd, frame, o, Math.min(256, frame.length - o)); await sleep(2); } }
      finally { closeSync(fd); }
      await sleep(250);
    }
  });
}
async function inject(typeHashBytes: Uint8Array, payload: Uint8Array, port = injectPort): Promise<void> {
  const cell = mintCell(typeHashBytes, payload, OWNER, BigInt(Date.now()), domainForType(typeHashBytes));
  await injectCellSig(cell, signCell(cell, WALLET), port);
}

/** Inject a cell signed with an explicit key (for capability-gated relay keys). */
async function injectWithKey(typeHashBytes: Uint8Array, payload: Uint8Array, signingKey: PrivateKey, port = injectPort): Promise<void> {
  const cell = mintCell(typeHashBytes, payload, OWNER, BigInt(Date.now()), domainForType(typeHashBytes));
  await injectCellSig(cell, signCell(cell, signingKey), port);
}

/** Inject a capability cert cell (signed by master key) for the given channel. */
async function injectCapabilityCert(channelId: Uint8Array, channelIdHex: string, port = fwdInjectPort): Promise<void> {
  const relayKey    = getRelayKey(channelIdHex);
  // F3: UINT64_MAX sentinel — device firmware uses ms-since-boot, not UTC.
  // Using a real UTC expiry would cause instant rejection on reboot.  The
  // no-expiry sentinel (0xffffffffffffffff) is the correct value until the
  // device gains RTC/NTP and can compare against wall-clock time.
  const expiryMs    = BigInt('0xffffffffffffffff');
  const validFromMs = BigInt(Date.now());
  const { cell, sig, payloadHash } = buildCapabilityCertCell(channelId, relayKey, WALLET, expiryMs, validFromMs);
  // Cache the BRC-108 cert_hash for this channel so commitments can bind to it.
  s_certHashes.set(channelIdHex, payloadHash);
  await injectCellSig(cell, sig, port);
  broadcast(`[ctl] → CAP cert: ch=${channelIdHex.slice(0,8)}... edge=${Buffer.from(relayKey.pk).toString('hex').slice(0,8)}... hash=${Buffer.from(payloadHash).toString('hex').slice(0,8)}... expiry=UINT64_MAX`);
}

// Full x402 mainnet flow: derive a recoverable receive key from Metanet
// Desktop, fund + sign a payment to it (createAction), broadcast via ARC,
// then inject the wallet-signed actuator_activate cell so a device lights.
// Returns the network txid (confirm on WhatsOnChain).
async function payAndActuate(): Promise<{ txid: string }> {
  if (OFFER.costSats > maxSats) throw new Error(`price ${OFFER.costSats} > cap ${maxSats}`);
  const offerIdHex = Buffer.from(OFFER.offerId).toString('hex');
  const receivePk = await getPublicKey({ protocolID: [2, 'x402 actuator payment'], keyID: offerIdHex, counterparty: 'self' }, metanetBase, metanetOrigin);
  const receiveScript = p2pkhScriptHexFromPubkey(receivePk);
  broadcast(`[ctl] funding ${OFFER.costSats} sats → ${receiveScript.slice(0, 14)}… via Metanet Desktop`);
  const ca = await createAction([{ lockingScript: receiveScript, satoshis: OFFER.costSats, outputDescription: 'x402 actuator activation' }], 'x402 actuator activation', metanetBase, metanetOrigin);
  const rawTx = rawTxHexFromCreateAction(ca);
  if (!rawTx) throw new Error('createAction returned no tx');
  const b = await broadcastTxHex(rawTx);
  if (!b.ok) throw new Error(`ARC broadcast: ${b.reason}`);
  broadcast(`[ctl] payment ON-CHAIN → ${b.txid}`);
  const { cell, sig } = buildActuatorActivate(OFFER, WALLET, OWNER, BigInt(Date.now()), actuatorCounter++);
  await injectCellSig(cell, sig);
  broadcast(`[ctl] injected actuator_activate → device should light ${OFFER.durationMs}ms`);
  return { txid: b.txid };
}

// SCADA: control the thing (actuate) AND commit the event as a canonical
// cell on chain via PushDrop — the chain as the tamper-evident historian.
// Unlike pay-actuate, the on-chain artifact is the full 1024-byte cell, not
// a payment.
let scadaLeaf = '';
async function scadaControlAndLog(tag: string, durationMs: number): Promise<{ txid: string; outputBytes: number }> {
  if (!scadaLeaf) scadaLeaf = await deriveScadaLeaf(metanetBase, metanetOrigin);
  // 1) CONTROL — actuate the device on the mesh.
  const { cell: actCell, sig } = buildActuatorActivate({ ...OFFER, durationMs }, WALLET, OWNER, BigInt(Date.now()), actuatorCounter++);
  await injectCellSig(actCell, sig);
  broadcast(`[ctl] SCADA control: actuate ${tag} for ${durationMs}ms`);
  // 2) DATA ACQUISITION + LOG — encode the event as a canonical cell, anchor on chain.
  const reading = 1000 + Math.floor(Math.random() * 60); // synthetic load, centi-watts (~10.x W)
  const evCell = encodeScadaCell({ tag, action: SCADA_ACTION.ACTUATE, value: durationMs, reading }, OWNER, Date.now());
  broadcast(`[ctl] SCADA log: anchoring scada.event.v0 cell (load ${(reading / 100).toFixed(2)}W) on chain…`);
  const r = await anchorScadaCell(evCell, scadaLeaf, { metanetBase, origin: metanetOrigin });
  broadcast(`[ctl] SCADA cell ON-CHAIN → ${r.txid} (PushDrop, ${r.outputBytes}B output)`);
  return { txid: r.txid, outputBytes: r.outputBytes };
}

// ── per-device status (liveness + inferred LED) ──────────────────────
// Port suffix → known forward-demo role (fixed MAC assignment).
const ROLE: Record<string, string> = { '21301': 'A·originator', '21201': 'B·relay', '21401': 'C·destination' };
interface DevState { lastSeen: number; ledUntil: number; rx: number; }
const devices = new Map<string, DevState>();
function trackDevice(label: string, ln: string): void {
  let d = devices.get(label);
  if (!d) { d = { lastSeen: 0, ledUntil: 0, rx: 0 }; devices.set(label, d); }
  d.lastSeen = Date.now();
  const rxm = ln.match(/rx_total=(\d+)/); if (rxm) d.rx = Number(rxm[1]);
  // Infer LED-on from logged blink/actuator durations (sub-1s blinks are
  // unlogged by the firmware, so this catches >=1s blinks + actuations).
  const bm = ln.match(/BLINK (\d+) ms/); if (bm) d.ledUntil = Date.now() + Number(bm[1]);
  const am = ln.match(/ms_remaining=(\d+)/); if (am) d.ledUntil = Date.now() + Number(am[1]);
}

// ── SSE fan-out of tailed device serial ──────────────────────────────
const clients = new Set<ReadableStreamDefaultController<Uint8Array>>();
const recent: string[] = [];
const enc = new TextEncoder();
function broadcast(line: string) {
  if (recent.push(line) > 200) recent.shift();
  const chunk = enc.encode(`data: ${JSON.stringify(line)}\n\n`);
  for (const c of clients) { try { c.enqueue(chunk); } catch { clients.delete(c); /* client gone */ } }
}
const readers: ChildProcessWithoutNullStreams[] = [];
for (const port of tailPorts) {
  spawnSync('stty', ['-f', port, baud, 'raw', '-echo'], { stdio: 'ignore' });
  const label = port.split('modem')[1] ?? port;
  const c = spawn('cat', [port]) as ChildProcessWithoutNullStreams;
  let buf = '';
  c.stdout.on('data', (d: Buffer) => {
    buf += d.toString();
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      const ln = buf.slice(0, i).replace(/\x1b\[[0-9;]*m/g, '').trim();
      buf = buf.slice(i + 1);
      if (ln) { trackDevice(label, ln); broadcast(`[${label}] ${ln}`); }
    }
  });
  readers.push(c);
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

const server = Bun.serve({
  port: httpPort,
  idleTimeout: 60, // pay-actuate / scada wait on Metanet Desktop + ARC
  async fetch(req) {
    const url = new URL(req.url);
    if (req.method === 'GET' && url.pathname === '/') {
      return new Response(readFileSync(WEB, 'utf8'), { headers: { 'content-type': 'text/html' } });
    }
    if (req.method === 'GET' && url.pathname === '/events') {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          for (const l of recent.slice(-50)) controller.enqueue(enc.encode(`data: ${JSON.stringify(l)}\n\n`));
          clients.add(controller);
        },
        cancel() { /* client gone; pruned on next enqueue error */ },
      });
      return new Response(stream, { headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' } });
    }
    if (req.method === 'GET' && url.pathname === '/status') {
      const now = Date.now();
      const list = tailPorts.map((p) => {
        const label = p.split('modem')[1] ?? p;
        const d = devices.get(label);
        return {
          label, role: ROLE[label] ?? '?',
          online: d ? now - d.lastSeen < 12000 : false,
          lastSeenMs: d ? now - d.lastSeen : null,
          ledOn: d ? now < d.ledUntil : false,
          ledRemainMs: d && now < d.ledUntil ? d.ledUntil - now : 0,
          rx: d?.rx ?? 0,
        };
      });
      return json({ devices: list, injector: injectPort.split('modem')[1] ?? injectPort });
    }
    if (req.method === 'GET' && url.pathname === '/config') {
      return json({ injectPort, fwdInjectPort, tailPorts, realPayment, costSats: OFFER.costSats, note: 'inject from one device; a device never sees its own broadcast' });
    }
    if (req.method === 'POST' && url.pathname === '/interlock') {
      const b = (await req.json().catch(() => ({}))) as { satisfy?: boolean };
      const withCapability = b.satisfy !== false;
      try {
        await clearInterlock(withCapability);
        return json({ ok: true, withCapability, capProtocol: CAP_PROTOCOL[1] });
      } catch (e) {
        broadcast(`[ctl] interlock ERROR: ${(e as Error).message}`);
        return json({ ok: false, error: (e as Error).message }, 502);
      }
    }
    if (req.method === 'POST' && url.pathname === '/scada') {
      if (!realPayment) return json({ ok: false, error: 'SCADA anchoring needs on-chain — start with --real-payment' }, 400);
      const b = (await req.json().catch(() => ({}))) as { tag?: string; durationMs?: number };
      try {
        const r = await scadaControlAndLog((b.tag ?? 'actuator-C').slice(0, 16), Number(b.durationMs ?? 5000));
        return json({ ok: true, txid: r.txid, outputBytes: r.outputBytes, woc: `https://whatsonchain.com/tx/${r.txid}` });
      } catch (e) {
        broadcast(`[ctl] SCADA ERROR: ${(e as Error).message}`);
        return json({ ok: false, error: (e as Error).message }, 502);
      }
    }
    if (req.method === 'POST' && url.pathname === '/pay-actuate') {
      if (!realPayment) return json({ ok: false, error: 'real payment disabled — start with --real-payment' }, 400);
      try {
        const r = await payAndActuate();
        return json({ ok: true, txid: r.txid, woc: `https://whatsonchain.com/tx/${r.txid}` });
      } catch (e) {
        broadcast(`[ctl] pay+actuate ERROR: ${(e as Error).message}`);
        return json({ ok: false, error: (e as Error).message }, 502);
      }
    }
    if (req.method === 'POST' && url.pathname === '/inject') {
      const b = (await req.json().catch(() => ({}))) as { kind?: string; trigger?: string; blinkMs?: number; quorum?: { n: number; windowMs: number } };
      try {
        if (b.kind === 'rule') {
          const trig = TYPES[b.trigger ?? 'tap']; const ms = Number(b.blinkMs ?? 2000);
          if (!trig) return json({ ok: false, error: 'bad trigger' }, 400);
          await inject(TYPES.rule, encodeRule(trig, ms, b.quorum));
          broadcast(`[ctl] injected rule: on ${b.trigger ?? 'tap'} → blink ${ms}ms${b.quorum ? ` (quorum ${b.quorum.n})` : ''}`);
          return json({ ok: true });
        }
        if (b.kind === 'tap' || b.kind === 'heartbeat' || b.kind === 'scripted') {
          const p = new Uint8Array(8); writeU32LE(p, 0, counter++); writeU32LE(p, 4, Date.now() & 0xffffffff);
          await inject(TYPES[b.kind], p);
          broadcast(`[ctl] injected ${b.kind} #${counter - 1}`);
          return json({ ok: true });
        }
        return json({ ok: false, error: 'unknown kind' }, 400);
      } catch (e) {
        return json({ ok: false, error: (e as Error).message }, 500);
      }
    }
    // ── SRv6 forward-cell injection ─────────────────────────────────────
    // Two modes:
    //   hop_verb=1 (EVAL_RULES): fire local tap rules at each hop → blink wave.
    //     No inner payload; each device evaluates its currently-installed rule.
    //   hop_verb=2 (INSTALL_RULE): deliver encodeRule(trigger,blinkMs) to every
    //     hop → reprogram B and C in one broadcast. Must inject via fwdInjectPort
    //     (MAC_A by default) because the injecting device broadcasts via ESP-NOW
    //     and a device never receives its own broadcast. segments=[B,C] so the
    //     cell routes A→B→C.
    if (req.method === 'POST' && url.pathname === '/inject-forward') {
      const b = (await req.json().catch(() => ({}))) as {
        hopVerb?: number;   // 1=EVAL_RULES, 2=INSTALL_RULE (default)
        trigger?: string;   // for INSTALL_RULE: which trigger type to install
        blinkMs?: number;   // for INSTALL_RULE: blink duration
      };
      try {
        const hopVerb = Number(b.hopVerb ?? 2);
        if (hopVerb < 1 || hopVerb > 2) return json({ ok: false, error: 'hopVerb must be 1 or 2' }, 400);
        let innerPayload = new Uint8Array(0);
        let desc = '';
        if (hopVerb === 2) {
          // INSTALL_RULE: carry the encoded rule in inner_payload
          const trig = TYPES[b.trigger ?? 'tap'];
          if (!trig) return json({ ok: false, error: 'bad trigger' }, 400);
          const ms = Number(b.blinkMs ?? 2000);
          innerPayload = encodeRule(trig, ms);
          desc = `INSTALL_RULE on ${b.trigger ?? 'tap'} → blink ${ms}ms`;
        } else {
          // EVAL_RULES: fire existing rules at each hop (inner_payload empty)
          desc = 'EVAL_RULES (blink wave)';
        }
        const fwdPayload = buildForwardPayload(hopVerb, [MAC_B, MAC_C], innerPayload);
        await inject(TYPES.forward, fwdPayload, fwdInjectPort);
        const via = fwdInjectPort.split('/').pop();
        broadcast(`[ctl] → SRv6 forward cell: verb=${hopVerb} (${desc}) ` +
                  `segments=[B→C] via ${via} · B applies+relays → C applies+delivers`);
        return json({ ok: true, hopVerb, desc });
      } catch (e) {
        broadcast(`[ctl] forward inject ERROR: ${(e as Error).message}`);
        return json({ ok: false, error: (e as Error).message }, 500);
      }
    }
    // ── forward.v1: channel-gated SRv6 forwarding ─────────────────────
    // Same routing as v0 (segments=[B→C], inject via MAC_A) but each hop
    // verifies a pre-signed payment commitment before relaying.
    // The source pre-increments seq + device_share for B and C; each
    // relay's cm_channel_apply_commitment enforces linearity (seq↑, share↑).
    if (req.method === 'POST' && url.pathname === '/inject-forward-v1') {
      const b = (await req.json().catch(() => ({}))) as { hopVerb?: number; trigger?: string; blinkMs?: number };
      try {
        const hopVerb = Number(b.hopVerb ?? 0);  // 0=NONE, 1=EVAL_RULES, 2=INSTALL_RULE
        const chId    = s_currentChannelId;
        const chHex   = s_currentChannelIdHex;
        // ── Auto-inject capability cert before the first forward.v1 ─────
        if (!s_capCertInjected) {
          await injectCapabilityCert(chId, chHex, fwdInjectPort);
          s_capCertInjected = true;
          // 3000 ms, not 300. Measured on two C6s against a freshly-reset board:
          //
          //    300 ms  -> the cert never arrives at all. The board logs only
          //               "forward.v1: no cert for channel … — DROP", so the
          //               symptom points at the capability table and the cause
          //               is two cells too close together.
          //   1500 ms  -> same failure.
          //   3000 ms  -> cert verified + installed, then forward.v1 CAP-verified,
          //               channel OK, relayed onward. Reproducible.
          //
          // Why it needs seconds: cm_sig_verify is ~267 ms on this chip
          // (main.c's own boot bench prints 267749 us/verify), the receive path
          // runs in the WiFi task, and injectCellSig sends each cell TWICE — so
          // a cert costs two verifies plus an install, during which the radio
          // callback is blocked and the next cell's ESP-NOW frames are dropped.
          // Reassembly has a 1000 ms TTL, so a single lost frame loses the cell.
          //
          // This is the mesh's real ceiling, not a fudge: roughly one signed
          // cell per second, which is the same ~270 ms/verify budget that keeps
          // telemetry unsigned on the hot path.
          await sleep(3000);
        }
        // Advance channel state for B (hop 0) and C (hop 1)
        fwdV1Ch.B.seq++; fwdV1Ch.B.share += FWD_V1_HOP_COST;
        fwdV1Ch.C.seq++; fwdV1Ch.C.share += FWD_V1_HOP_COST;
        // F5d: include cert_hash in each commitment slot for BRC-108 binding.
        // cert_hash = SHA-256(capability cert payload[66]) stored when cert was injected.
        const certHashBytes = s_certHashes.get(chHex);
        const expiry = BigInt('0x7fffffffffffffff');  // far future (matches firmware)
        const commitments = [
          { channelId: chId, seq: fwdV1Ch.B.seq, share: fwdV1Ch.B.share, expiryMs: expiry, certHash: certHashBytes },
          { channelId: chId, seq: fwdV1Ch.C.seq, share: fwdV1Ch.C.share, expiryMs: expiry, certHash: certHashBytes },
        ];
        let innerPayload = new Uint8Array(0);
        let desc = `NONE (pure routing, seq_B=${fwdV1Ch.B.seq} seq_C=${fwdV1Ch.C.seq})`;
        if (hopVerb === 2) {
          const trig = TYPES[b.trigger ?? 'tap'];
          if (!trig) return json({ ok: false, error: 'bad trigger' }, 400);
          innerPayload = encodeRule(trig, Number(b.blinkMs ?? 2000));
          desc = `INSTALL_RULE on ${b.trigger ?? 'tap'} → blink ${b.blinkMs ?? 2000}ms`;
        } else if (hopVerb === 1) {
          desc = 'EVAL_RULES (blink wave)';
        }
        const fwdPayload = buildForwardV1Payload(hopVerb, [MAC_B, MAC_C], commitments, innerPayload);
        // ── Sign forward.v1 with the BRC-42-derived relay key ────────────
        // The edge key was authorized by the capability cert above.
        // Firmware verifies against cert's edge_pubkey, not master wallet key.
        const relayKey    = getRelayKey(chHex);
        const relayWallet = new PrivateKey(Buffer.from(relayKey.sk).toString('hex'), 16);
        await injectWithKey(TYPES.forwardV1, fwdPayload, relayWallet, fwdInjectPort);
        const certHashHex = certHashBytes ? Buffer.from(certHashBytes).toString('hex').slice(0, 8) + '...' : 'none';
        broadcast(`[ctl] → forward.v1 (CAP-gated relay key): ${desc} ` +
                  `B_share=${fwdV1Ch.B.share} C_share=${fwdV1Ch.C.share} sats cert_hash=${certHashHex}`);

        // ── On-chain settlement trigger ──────────────────────────────
        // If an on-chain channel is open, accumulate the per-hop costs
        // for B + C.  Fire settlement once the threshold is crossed.
        if (activeChannel && !activeChannel.settled) {
          const crossed = accumulateHop(activeChannel, FWD_V1_HOP_COST * 2, 0, fwdV1Ch.B.seq);
          if (crossed) {
            broadcast(`[ctl] CHANNEL THRESHOLD REACHED — settling on chain …`);
            try {
              const settleTxid = await settleChannel(activeChannel, CHAIN_WALLET);
              broadcast(`[ctl] CHANNEL SETTLED → txid ${settleTxid} (WoC: https://whatsonchain.com/tx/${settleTxid})`);
              // Emit cellmesh.channel_settle.v0 into the mesh so devices log it.
              // Retry 3× with 600ms gap to survive ESP-NOW packet loss.
              const sp = buildSettlePayload(activeChannel, settleTxid);
              for (let ri = 0; ri < 3; ri++) {
                await inject(TYPES.channelSettle, sp, fwdInjectPort);
                if (ri < 2) await sleep(600);
              }
              broadcast(`[ctl] injected channel_settle cell (3×) → devices will log settlement evidence`);
            } catch (se) {
              broadcast(`[ctl] SETTLE ERROR: ${(se as Error).message}`);
            }
          } else {
            const remaining = SETTLE_THRESHOLD_SATS - activeChannel.deviceShareAccum;
            broadcast(`[ctl] channel: ${activeChannel.deviceShareAccum} sats accumulated (${remaining} to settlement)`);
          }
        }

        return json({ ok: true, hopVerb, seqB: fwdV1Ch.B.seq, seqC: fwdV1Ch.C.seq,
                      shareB: fwdV1Ch.B.share, shareC: fwdV1Ch.C.share,
                      channelAccum: activeChannel?.deviceShareAccum ?? null,
                      settled: activeChannel?.settled ?? false,
                      relayKey: Buffer.from(relayKey.pk).toString('hex').slice(0, 16) + '...' });
      } catch (e) {
        broadcast(`[ctl] forward.v1 ERROR: ${(e as Error).message}`);
        return json({ ok: false, error: (e as Error).message }, 500);
      }
    }
    // ── POST /inject-forward-v1-bad-key — Track 2 rejection test ────────
    // Injects a forward.v1 signed with a FRESH RANDOM key that has NO
    // matching capability cert.  Firmware must log:
    //   "sig INVALID (edge key) — DROP"  (cert installed, wrong key)
    // Evidence for PR #584 Track 2 rejection requirement.
    if (req.method === 'POST' && url.pathname === '/inject-forward-v1-bad-key') {
      try {
        // Ensure a cert is installed first (so the firmware has a cert to reject against).
        if (!s_capCertInjected) {
          await injectCapabilityCert(s_currentChannelId, s_currentChannelIdHex, fwdInjectPort);
          s_capCertInjected = true;
          await sleep(400);
        }
        const chId = s_currentChannelId;
        const chHex = s_currentChannelIdHex;
        // Advance seq just like a normal inject (so commitments are fresh).
        fwdV1Ch.B.seq++; fwdV1Ch.C.seq++;
        fwdV1Ch.B.share += FWD_V1_HOP_COST; fwdV1Ch.C.share += FWD_V1_HOP_COST;
        const certHashBytes = s_certHashes.get(chHex);
        const expiry = BigInt('0x7fffffffffffffff');
        const commitments = [
          { channelId: chId, seq: fwdV1Ch.B.seq, share: fwdV1Ch.B.share, expiryMs: expiry, certHash: certHashBytes },
          { channelId: chId, seq: fwdV1Ch.C.seq, share: fwdV1Ch.C.share, expiryMs: expiry, certHash: certHashBytes },
        ];
        const fwdPayload = buildForwardV1Payload(0, [MAC_B, MAC_C], commitments, new Uint8Array(0));
        // Sign with a RANDOM key that has no cert — firmware should reject.
        const badKey = new PrivateKey();  // fresh random — NOT the certified relay key
        const badPk  = Buffer.from(badKey.toPublicKey().encode(true) as Uint8Array).toString('hex');
        await injectWithKey(TYPES.forwardV1, fwdPayload, badKey, fwdInjectPort);
        broadcast(`[ctl] → forward.v1 BAD-KEY test: signed with uncertified ${badPk.slice(0, 16)}... ` +
                  `(expect: "sig INVALID (edge key) — DROP" on devices B+C)`);
        return json({ ok: true, badPk, note: 'firmware should log: sig INVALID (edge key) — DROP' });
      } catch (e) {
        return json({ ok: false, error: (e as Error).message }, 500);
      }
    }

    // ── POST /inject-forward-v2 — 2-cell burst (Cell A + Cell B) ─────────
    // Sends cellmesh.forward.v2 (Cell A) then cellmesh.routing.cont.v0 (Cell B)
    // back-to-back.  The pair is correlated by a shared flow_id derived at
    // injection time.  Cell A carries the application inner payload; Cell B
    // carries routing segments + channel commitments.
    // Body: { hopVerb?: 0|1|2, trigger?: string, blinkMs?: number }
    if (req.method === 'POST' && url.pathname === '/inject-forward-v2') {
      const b = (await req.json().catch(() => ({}))) as { hopVerb?: number; trigger?: string; blinkMs?: number };
      try {
        const hopVerb = Number(b.hopVerb ?? 0);
        const chId    = s_currentChannelId;
        const chHex   = s_currentChannelIdHex;

        // Auto-inject capability cert before first burst (reuses shared cert state)
        if (!s_capCertInjected) {
          await injectCapabilityCert(chId, chHex, fwdInjectPort);
          s_capCertInjected = true;
          // 3000 ms for the same measured reason as the forward.v1 route: at
          // ~267 ms per cm_sig_verify, with each cell sent twice, a cert costs
          // the receiver more than a second of blocked radio callback and the
          // next cell's frames are dropped.
          await sleep(3000);
        }

        // Advance per-hop channel state
        fwdV2Ch.B.seq++; fwdV2Ch.B.share += FWD_V1_HOP_COST;
        fwdV2Ch.C.seq++; fwdV2Ch.C.share += FWD_V1_HOP_COST;

        const certHashBytes = s_certHashes.get(chHex);
        const expiry = BigInt('0x7fffffffffffffff');
        const commitments = [
          { channelId: chId, seq: fwdV2Ch.B.seq, share: fwdV2Ch.B.share, expiryMs: expiry, certHash: certHashBytes },
          { channelId: chId, seq: fwdV2Ch.C.seq, share: fwdV2Ch.C.share, expiryMs: expiry, certHash: certHashBytes },
        ];

        let innerPayload = new Uint8Array(0);
        let desc = `NONE (routing-only, seq_B=${fwdV2Ch.B.seq} seq_C=${fwdV2Ch.C.seq})`;
        if (hopVerb === 2) {
          const trig = TYPES[b.trigger ?? 'tap'];
          if (!trig) return json({ ok: false, error: 'bad trigger' }, 400);
          innerPayload = encodeRule(trig, Number(b.blinkMs ?? 2000));
          desc = `INSTALL_RULE on ${b.trigger ?? 'tap'} → blink ${b.blinkMs ?? 2000}ms`;
        } else if (hopVerb === 1) {
          desc = 'EVAL_RULES (blink wave)';
        }

        // Derive a shared flow_id from current timestamp (same 16-byte window as v1)
        const seed = new Uint8Array(8);
        const now = BigInt(Date.now());
        for (let i = 0; i < 8; i++) seed[i] = Number((now >> BigInt(i * 8)) & 0xffn);
        const flowId = sha256(seed).subarray(0, 16);

        // Build Cell A and Cell B payloads
        // Cell B FIRST. Cell A commits to Cell B's exact bytes, so B must exist
        // before A can be built — the route and the payment commitments live in
        // B, and this is what puts them under A's signature.
        const relayKey    = getRelayKey(chHex);
        const relayWallet = new PrivateKey(Buffer.from(relayKey.sk).toString('hex'), 16);
        // Both on the relay rail — the same flag the capability cert carries,
        // or cm_cap_lookup misses and the device drops them.
        const payloadB = buildForwardV2PayloadB(flowId, [MAC_B, MAC_C], commitments);
        const cellB    = mintCell(TYPES.routingContV0, payloadB, OWNER, BigInt(Date.now()), domainForType(TYPES.routingContV0));

        // The device compares this against SHA-256 of the whole 1024-byte Cell B
        // it receives, so hash the finished cell, not the payload.
        const routingDigest = sha256(cellB);

        const payloadA = buildForwardV2PayloadA(flowId, hopVerb, 2 /* B+C */, innerPayload, routingDigest);
        const cellA    = mintCell(TYPES.forwardV2, payloadA, OWNER, BigInt(Date.now()), domainForType(TYPES.forwardV2));
        const sigA     = signCell(cellA, relayWallet);
        const sigB     = new Uint8Array(64);  // Cell B carries no signature of its own

        await injectCellSig(cellA, sigA, fwdInjectPort);
        // 2500 ms, not 20. Both hop-0 boards logged "routing.cont: no matching
        // Cell A": Cell B arrived and Cell A never did, at 20 ms AND at 1500 ms.
        //
        // The cause is on the injecting board, not the air. With
        // DEMO_SCRIPT_ONLY the serial injector does not broadcast immediately —
        // it copies the cell into ONE static staging pair (s_demo_cell /
        // s_demo_sig) and schedules a broadcast DEMO_BROADCAST_DELAY_MS = 1800 ms
        // later. A second injection arriving inside that window overwrites the
        // staged cell, so only the LAST one is ever transmitted.
        //
        // forward.v1 never noticed because injectCellSig sends ONE cell twice:
        // the retry overwrites the original with an identical copy. v2 sends two
        // DIFFERENT cells, so Cell A was silently replaced by Cell B every time.
        //
        // So the gap has to clear the staging window, not just the air. The
        // burst slot has no TTL (cm_fwdv2_burst_slot_t is
        // {primary, primary_cell, primary_sig, valid}), so Cell A waits happily.
        await sleep(2500);
        await injectCellSig(cellB, sigB, fwdInjectPort);

        const certHashHex = certHashBytes ? Buffer.from(certHashBytes).toString('hex').slice(0, 8) + '...' : 'none';
        const flowHex     = Buffer.from(flowId).toString('hex').slice(0, 8) + '...';
        broadcast(`[ctl] → forward.v2 burst: ${desc} flow=${flowHex} ` +
                  `B_share=${fwdV2Ch.B.share} C_share=${fwdV2Ch.C.share} sats ` +
                  `inner=${innerPayload.length}B (+296B vs v1) cert=${certHashHex}`);

        // On-chain settlement (shared threshold with v1 — accumulates in same channel)
        if (activeChannel && !activeChannel.settled) {
          const crossed = accumulateHop(activeChannel, FWD_V1_HOP_COST * 2, 0, fwdV2Ch.B.seq);
          if (crossed) {
            broadcast(`[ctl] CHANNEL THRESHOLD REACHED (v2 burst) — settling on chain …`);
            try {
              const settleTxid = await settleChannel(activeChannel, CHAIN_WALLET);
              broadcast(`[ctl] CHANNEL SETTLED → txid ${settleTxid} (WoC: https://whatsonchain.com/tx/${settleTxid})`);
              const sp = buildSettlePayload(activeChannel, settleTxid);
              for (let ri = 0; ri < 3; ri++) {
                await inject(TYPES.channelSettle, sp, fwdInjectPort);
                if (ri < 2) await sleep(600);
              }
              broadcast(`[ctl] injected channel_settle cell (3×) → devices will log settlement evidence`);
            } catch (se) {
              broadcast(`[ctl] SETTLE ERROR: ${(se as Error).message}`);
            }
          } else {
            const remaining = SETTLE_THRESHOLD_SATS - activeChannel.deviceShareAccum;
            broadcast(`[ctl] channel: ${activeChannel.deviceShareAccum} sats accumulated (${remaining} to settlement)`);
          }
        }

        return json({ ok: true, hopVerb, flowId: Buffer.from(flowId).toString('hex'),
                      seqB: fwdV2Ch.B.seq, seqC: fwdV2Ch.C.seq,
                      shareB: fwdV2Ch.B.share, shareC: fwdV2Ch.C.share,
                      innerBytes: innerPayload.length,
                      channelAccum: activeChannel?.deviceShareAccum ?? null,
                      settled: activeChannel?.settled ?? false,
                      relayKey: Buffer.from(relayKey.pk).toString('hex').slice(0, 16) + '...' });
      } catch (e) {
        broadcast(`[ctl] forward.v2 ERROR: ${(e as Error).message}`);
        return json({ ok: false, error: (e as Error).message }, 500);
      }
    }
    // ── POST /open-channel — fund a BSV channel UTXO on mainnet ─────────
    // Requires --real-payment (Metanet Desktop must be running on :3321).
    // Returns { txid, channelId(hex), fundingSats, woc, refundLocktimeUnix }.
    if (req.method === 'POST' && url.pathname === '/open-channel') {
      if (!realPayment) return json({ ok: false, error: 'channel open needs on-chain — start with --real-payment' }, 400);
      if (activeChannel && !activeChannel.settled) {
        return json({ ok: false, error: 'channel already open', txid: activeChannel.txid }, 409);
      }
      try {
        broadcast(`[ctl] opening BSV channel: funding ${CHANNEL_FUNDING_SATS} sats via Metanet Desktop…`);
        activeChannel = await openChannel(CHAIN_WALLET, { metanetBase: metanetBase, origin: metanetOrigin });
        // Reset in-memory forward.v1/v2 counters + capability cert flag so the new
        // channel gets a fresh cert with its derived relay key.
        fwdV1Ch.B.seq = 0; fwdV1Ch.B.share = 0;
        fwdV1Ch.C.seq = 0; fwdV1Ch.C.share = 0;
        fwdV2Ch.B.seq = 0; fwdV2Ch.B.share = 0;
        fwdV2Ch.C.seq = 0; fwdV2Ch.C.share = 0;
        s_capCertInjected = false;
        const chIdHex = Buffer.from(activeChannel.channelId).toString('hex');
        // Wire new channel_id into the forward.v1 injection path so the capability
        // cert and relay key derivation pick up the real on-chain txid.
        s_currentChannelId    = activeChannel.channelId;
        s_currentChannelIdHex = chIdHex;
        broadcast(`[ctl] CHANNEL OPEN → txid ${activeChannel.txid} · channel_id ${chIdHex.slice(0, 16)}…`);
        broadcast(`[ctl] refund tx pre-signed (nLockTime +24h, NOT broadcast)`);
        return json({
          ok:      true,
          txid:    activeChannel.txid,
          channelId: chIdHex,
          fundingSats: activeChannel.fundingSats,
          woc:     `https://whatsonchain.com/tx/${activeChannel.txid}`,
          refundLocktimeUnix: Math.floor(activeChannel.openedAtMs / 1000) + 86400,
          settleThreshold: SETTLE_THRESHOLD_SATS,
        });
      } catch (e) {
        broadcast(`[ctl] open-channel ERROR: ${(e as Error).message}`);
        return json({ ok: false, error: (e as Error).message }, 502);
      }
    }
    // ── Standalone capability cert inject ─────────────────────────────────
    // POST /inject-capability-cert — inject a fresh cert for the active channel.
    // Useful to re-inject if devices rebooted and lost the cert.
    if (req.method === 'POST' && url.pathname === '/inject-capability-cert') {
      try {
        const chId  = s_currentChannelId;
        const chHex = s_currentChannelIdHex;
        await injectCapabilityCert(chId, chHex, fwdInjectPort);
        s_capCertInjected = true;
        const relayKey = getRelayKey(chHex);
        return json({ ok: true, channelId: chHex, edgePk: Buffer.from(relayKey.pk).toString('hex'),
                      certHash: Buffer.from(s_certHashes.get(chHex)!).toString('hex') });
      } catch (e) {
        return json({ ok: false, error: (e as Error).message }, 500);
      }
    }
    // ── GET /channel-state — current channel status ──────────────────────
    if (req.method === 'GET' && url.pathname === '/channel-state') {
      if (!activeChannel) return json({ ok: true, channel: null, note: 'no channel open — POST /open-channel first' });
      const chIdHex = Buffer.from(activeChannel.channelId).toString('hex');
      return json({
        ok: true,
        channel: {
          txid:          activeChannel.txid,
          channelId:     chIdHex,
          fundingSats:   activeChannel.fundingSats,
          deviceAccum:   activeChannel.deviceShareAccum,
          userAccum:     activeChannel.userShareAccum,
          finalSeq:      activeChannel.finalSeq,
          settled:       activeChannel.settled,
          settleTxid:    activeChannel.settleTxid ?? null,
          woc:           `https://whatsonchain.com/tx/${activeChannel.txid}`,
          settleWoc:     activeChannel.settleTxid ? `https://whatsonchain.com/tx/${activeChannel.settleTxid}` : null,
          settleThreshold: SETTLE_THRESHOLD_SATS,
          remaining:     SETTLE_THRESHOLD_SATS - activeChannel.deviceShareAccum,
        },
      });
    }
    // ── MNCA oracle: validate transition + sign ─────────────────────
    if (req.method === 'POST' && url.pathname === '/validate-mnca-transition') {
      try {
        const body = (await req.json()) as ValidateRequest;
        const walletHex = WALLET.toString(); // hex privkey → use as WIF stub
        const result = await validateMncaTransition(body, walletHex);
        broadcast(`[mnca-oracle] (${body.x},${body.y}) gen=${body.gen} valid=${result.valid}`);
        return json(result, result.valid ? 200 : 422);
      } catch (e) {
        return json({ error: (e as Error).message }, 500);
      }
    }

    return new Response('not found', { status: 404 });
  },
});

// Keep the control plane alive through a bad serial write / transient
// rejection — a single failed inject must not take down the whole panel.
process.on('uncaughtException', (e) => console.error('[control-plane] uncaught:', (e as Error)?.message ?? e));
process.on('unhandledRejection', (e) => console.error('[control-plane] unhandledRejection:', (e as Error)?.message ?? e));

console.log(`mesh control plane → http://localhost:${server.port}`);
console.log(`  inject via ${injectPort} · tail ${tailPorts.join(', ')}`);
console.log('  open the URL in a browser: click buttons → inject cells → watch the live feed');
process.on('SIGINT', () => { for (const c of readers) c.kill(); process.exit(0); });
