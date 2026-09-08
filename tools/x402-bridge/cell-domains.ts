/**
 * cell-domains.ts — which authority rail each cell type belongs to.
 *
 * The domain flag names WHO may act. `type_hash` (header offset 30) already
 * names WHAT the cell is, so a flag per cell type would make the domain a
 * second, redundant type field. Many types therefore share one rail, and this
 * table is the mapping — not a flag registry. The flags themselves come from
 * `tools/domains.ts`, generated from `tools/fleet-zig/src/domains.zig`.
 *
 * Several minters here are generic (`mintCell(typeHashBytes, …)` with the type
 * passed in), so they cannot name a constant at the call site. They call
 * `domainForType` instead, which keeps the mapping in one place rather than
 * scattering flags across a dozen files that would then drift.
 *
 * ⚠ `capability.v0` and the forward family MUST resolve to the same flag.
 * `cm_cap_lookup` keys on it, so a cert in one domain cannot authorise a
 * forward cell in another — the lookup misses and the device drops the cell.
 * `assertRelayRailConsistent()` below is that constraint as an assertion.
 */

import { DOMAIN } from '../domains.js';
import { typeHash } from './cell-codec.js';

const hex = (u8: Uint8Array): string => Buffer.from(u8).toString('hex');

/** cell type name -> the rail that authorises it. */
const RAIL: ReadonlyArray<readonly [string, number]> = [
  // Relay: the cert GRANTS, the forwards EXERCISE. One rail, by necessity.
  //
  // forward.v0 belongs here too. It was on the telemetry rail while it was the
  // unauthenticated path — a label for something with no authority. It is now
  // signature-verified and requires a relay grant, so putting it anywhere else
  // means the grant it needs is looked up in a domain the cert was never issued
  // for, and every v0 cell is refused for want of a capability that exists.
  ['cellmesh.capability.v0', DOMAIN.meshRelay],
  ['cellmesh.forward.v0', DOMAIN.meshRelay],
  ['cellmesh.forward.v1', DOMAIN.meshRelay],
  ['cellmesh.forward.v2', DOMAIN.meshRelay],
  ['cellmesh.routing.cont.v0', DOMAIN.meshRelay],

  // Payment: authorised by the wallet funding the channel.
  ['cellmesh.channel_open.v0', DOMAIN.meshPayment],
  ['cellmesh.channel_commitment.v0', DOMAIN.meshPayment],
  ['cellmesh.channel_close.v0', DOMAIN.meshPayment],
  ['cellmesh.channel_settle.v0', DOMAIN.meshPayment],

  // Control: authorised to move something in the world. Kept apart from
  // payment on purpose — "may spend" and "may actuate" are different powers.
  ['cellmesh.actuator_offer.v0', DOMAIN.meshControl],
  ['cellmesh.actuator_activate.v0', DOMAIN.meshControl],
  ['cellmesh.confirmed_tap.v0', DOMAIN.meshControl],
  ['cellmesh.rule.v0', DOMAIN.meshControl],

  // Script: the authority is inside the locking script the cell carries.
  ['cellmesh.scripted.v0', DOMAIN.meshScript],

  // Telemetry: UNSIGNED. A namespace for schema purposes, NOT a boundary —
  // nothing covers an unsigned cell's header, so the flag is forgeable and a
  // device must not treat it as authority.
  ['cellmesh.heartbeat.v0', DOMAIN.meshTelemetry],
  ['cellmesh.tap.v0', DOMAIN.meshTelemetry],
  ['cellmesh.telemetry.v0', DOMAIN.meshTelemetry],
  ['scada.event.v0', DOMAIN.meshTelemetry],
] as const;

const BY_TYPE_HASH = new Map<string, number>(
  RAIL.map(([name, flag]) => [hex(typeHash(name)), flag] as const),
);

/** Every type name this table knows, for tests and error messages. */
export const KNOWN_CELL_TYPES: ReadonlyArray<string> = RAIL.map(([n]) => n);

/**
 * The rail that authorises `typeHashBytes`.
 *
 * Throws on an unknown type rather than defaulting to 0. Silently minting into
 * the undeclared domain is how every cell in this repo came to carry flag 0 in
 * the first place — a default that looks like a value. A new cell type should
 * fail loudly here until someone decides which authority it answers to.
 */
export const domainForType = (typeHashBytes: Uint8Array): number => {
  const flag = BY_TYPE_HASH.get(hex(typeHashBytes));
  if (flag === undefined) {
    throw new Error(
      `no authority rail for cell type ${hex(typeHashBytes).slice(0, 16)}… — ` +
        `add it to RAIL in tools/x402-bridge/cell-domains.ts. Known: ${KNOWN_CELL_TYPES.join(', ')}`,
    );
  }
  return flag;
};

/**
 * The capability cert and every cell it authorises share one flag.
 *
 * Called from the test suite. If this ever fails, `cm_cap_lookup` on the device
 * will miss for every forward cell and the whole relay path goes dark — a
 * failure that looks like a radio problem, not a namespace problem.
 */
export const assertRelayRailConsistent = (): void => {
  const cert = domainForType(typeHash('cellmesh.capability.v0'));
  for (const t of ['cellmesh.forward.v0', 'cellmesh.forward.v1',
                   'cellmesh.forward.v2', 'cellmesh.routing.cont.v0']) {
    const got = domainForType(typeHash(t));
    if (got !== cert) {
      throw new Error(
        `${t} is on domain 0x${got.toString(16)} but the capability cert that ` +
          `authorises it is on 0x${cert.toString(16)} — cm_cap_lookup would miss`,
      );
    }
  }
};
