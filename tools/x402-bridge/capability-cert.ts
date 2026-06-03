/**
 * capability-cert.ts — BRC-42 edge key derivation and cellmesh.capability.v0
 * cert building for the x402 bridge.
 *
 * The "capability hat" pattern:
 *   1. At channel-open, the bridge derives a per-channel relay key from the
 *      wallet master key + channel_id label (HMAC-based self-derivation).
 *   2. It builds a `cellmesh.capability.v0` cert cell signed by the master
 *      key, granting the relay key authority to relay forward.v1 cells on
 *      that channel.
 *   3. The firmware installs the relay key in a cert table when the cert
 *      arrives.  Subsequent forward.v1 cells must be signed by the relay key
 *      (not the master key) or the firmware rejects them.
 *
 * Capability cert payload layout (66 bytes, BRC-52 aligned):
 *   Offset  Size  Field
 *   0       33    edge_pubkey (compressed secp256k1 — the relay key)
 *   33      16    channel_id
 *   49       8    expiry_ms   (u64 LE)  — UINT64_MAX = no expiry (until RTC/NTP)
 *   57       1    route_type  (CAP_ROUTE_FWD_V1 = 0x01)
 *   58       8    valid_from_ms (u64 LE) — UTC ms when cert was issued (BRC-52)
 *
 * cert_hash = SHA-256(payload[66]) — carried in every cm_channel_commitment_t
 * that uses this relay key (BRC-108 binding).
 */

import { PrivateKey } from '@bsv/sdk';
import { createHmac } from 'node:crypto';
import { mintCell, signCell, typeHash, writeU64LE, sha256 } from './cell-codec.js';

// ── Route type constants ─────────────────────────────────────────────────────
/** route_type byte for cellmesh.forward.v1 relay authority. */
export const CAP_ROUTE_FWD_V1 = 0x01;

// ── Capability cert type hash ────────────────────────────────────────────────
export const CAPABILITY_V0_TYPE = typeHash('cellmesh.capability.v0');

// ── Key derivation ───────────────────────────────────────────────────────────

/**
 * Derive a per-channel relay private key from the wallet master key.
 *
 * Derivation: HMAC-SHA256(master_sk_bytes, "cell-routing-relay/" + channel_id_hex)
 * then child_sk = (master_sk + HMAC_tweak) mod secp256k1_N.
 *
 * This is a self-directed BRC-42-style derivation (no ECDH counterparty
 * needed — the bridge is both sender and key-holder).
 *
 * Returns { sk: Uint8Array[32], pk: Uint8Array[33] }.
 */
export function deriveChannelRelayKey(
  masterWallet: PrivateKey,
  channelIdHex: string,
): { sk: Uint8Array; pk: Uint8Array } {
  const masterSkHex = masterWallet.toString();
  const masterSkBytes = Buffer.from(masterSkHex, 'hex');
  const label = `cell-routing-relay/${channelIdHex}`;

  // HMAC-SHA256(master_sk_bytes, label)
  const tweak = createHmac('sha256', masterSkBytes).update(label).digest();

  // child_sk = (master_sk + tweak) mod N
  const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  const masterN = BigInt('0x' + masterSkHex);
  const tweakN  = BigInt('0x' + tweak.toString('hex'));
  const childN  = (masterN + tweakN) % N;
  const sk = Buffer.from(childN.toString(16).padStart(64, '0'), 'hex');

  // Derive compressed pubkey from child sk via @bsv/sdk
  const edgeWallet = new PrivateKey(childN.toString(16), 16);
  const pk = new Uint8Array(Buffer.from(edgeWallet.toPublicKey().toString(), 'hex'));

  return { sk: new Uint8Array(sk), pk };
}

// ── Payload builder ──────────────────────────────────────────────────────────

/**
 * Build the 66-byte payload for a cellmesh.capability.v0 cert cell.
 *
 * Layout:
 *   [0..32]  edge_pubkey (33 bytes compressed secp256k1)
 *   [33..48] channel_id  (16 bytes)
 *   [49..56] expiry_ms   (u64 LE) — UINT64_MAX = no expiry (until RTC/NTP)
 *   [57]     route_type  (0x01 = forward.v1)
 *   [58..65] valid_from_ms (u64 LE) — UTC ms when cert was issued (BRC-52)
 */
export function buildCapabilityCertPayload(
  edgePk:      Uint8Array,   // 33-byte compressed pubkey
  channelId:   Uint8Array,   // 16-byte channel_id
  expiryMs:    bigint,
  routeType    = CAP_ROUTE_FWD_V1,
  validFromMs  = BigInt(Date.now()),
): Uint8Array {
  if (edgePk.length !== 33)    throw new Error('edgePk must be 33 bytes');
  if (channelId.length !== 16) throw new Error('channelId must be 16 bytes');

  const p = new Uint8Array(66);
  p.set(edgePk,    0);
  p.set(channelId, 33);
  writeU64LE(p, 49, expiryMs);
  p[57] = routeType;
  writeU64LE(p, 58, validFromMs);
  return p;
}

// ── Cert hash ─────────────────────────────────────────────────────────────────

/**
 * Compute the BRC-108 cert_hash for a capability cert payload.
 *
 * cert_hash = SHA-256(payload[66]) — stored in every cm_channel_commitment_t
 * that uses the relay key granted by this cert.  Binds each payment hop to
 * the specific cert that authorised the relay key.
 */
export function certHash(payload: Uint8Array): Uint8Array {
  return sha256(payload);
}

// ── Full cert cell builder ───────────────────────────────────────────────────

/**
 * Build a signed cellmesh.capability.v0 cell that grants `relayKey.pk`
 * authority to relay forward.v1 cells on `channelId`.
 *
 * The cert cell itself is signed by the master wallet key — devices verify
 * against the installed master pubkey (s_wallet_pubkey in main.c) and then
 * install the edge_pubkey from the payload into their cert table.
 *
 * @param channelId   16-byte channel_id
 * @param relayKey    { sk, pk } from deriveChannelRelayKey
 * @param masterKey   wallet master key — signs the cert cell
 * @param expiryMs    absolute expiry (UINT64_MAX = no expiry until device has RTC/NTP)
 * @param validFromMs UTC ms when cert was issued (BRC-52 validFrom); defaults to now
 * @returns { cell, sig, payloadHash } — payloadHash = SHA-256(payload[66]), used as
 *   cert_hash in cm_channel_commitment_t for BRC-108 binding.
 */
export function buildCapabilityCertCell(
  channelId:   Uint8Array,
  relayKey:    { sk: Uint8Array; pk: Uint8Array },
  masterKey:   PrivateKey,
  expiryMs:    bigint,
  validFromMs: bigint = BigInt(Date.now()),
): { cell: Uint8Array; sig: Uint8Array; payloadHash: Uint8Array } {
  // owner_id = first 16 bytes of master pubkey (fingerprint)
  const masterPk = new Uint8Array(Buffer.from(masterKey.toPublicKey().toString(), 'hex'));
  const ownerId  = masterPk.subarray(0, 16);

  const payload     = buildCapabilityCertPayload(relayKey.pk, channelId, expiryMs, CAP_ROUTE_FWD_V1, validFromMs);
  const payloadHash = sha256(payload);  // BRC-108 cert_hash
  const cell        = mintCell(CAPABILITY_V0_TYPE, payload, ownerId, BigInt(Date.now()));
  const sig         = signCell(cell, masterKey);
  return { cell, sig, payloadHash };
}
