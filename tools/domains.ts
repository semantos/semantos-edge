/**
 * domains.ts — GENERATED from tools/fleet-zig/src/domains.zig.
 * Do not hand-edit; run `zig build gen-domains -- write` in tools/fleet-zig.
 *
 * Domain flags name WHO may act, not WHAT the cell is — `type_hash` at
 * header offset 30 already says what it is. Cells authorised by the same
 * thing share a flag; cells authorised by different things do not.
 *
 * The flag lives at cell header bytes 24-27 and is read by
 * OP_CHECKDOMAINFLAG (opcode 198): exact equality, fail-closed.
 *
 * ⚠ A flag on an UNSIGNED cell is a label, not a boundary — nothing
 * covers its header, so anyone may set it to anything. A domain check
 * only means something where a signature covers bytes 24-27.
 *
 * ⚠ Bit 31 must stay clear: the engine reads the expected flag as a BSV
 * script number, so bit 31 is a SIGN bit. See
 * components/cell-mesh/test/vectors/README.md.
 */

export const DOMAIN = {
  /** semantos-core canonical ZONE_KEY */
  zone: 0x0000000e,
  /** a physical unit in the field; also the relay rail */
  fleetDevice: 0x00f10001,
  /** a person, mirrored from an IdP */
  orgMember: 0x00f10002,
  /** capability.v0 grants it; forward.v1/v2 + routing.cont.v0 exercise it (== fleet.device) */
  meshRelay: 0x00f10001,
  /** channel open/commitment/close/settle */
  meshPayment: 0x00f10010,
  /** actuator offer/activate, confirmed_tap, rule.v0 */
  meshControl: 0x00f10020,
  /** UNSIGNED: heartbeat, tap, telemetry, forward.v0, MNCA tiles - a label, not a gate */
  meshTelemetry: 0x00f10030,
  /** scripted.v0; authority is in the locking script */
  meshScript: 0x00f10040,
} as const;

/** Largest flag OP_CHECKDOMAINFLAG can be handed unambiguously. */
export const SCRIPT_SAFE_MAX = 0x7fffffff;

/** Human name for a flag, for logs and receipts. */
export const domainName = (flag: number): string =>
  Object.entries(DOMAIN).find(([, v]) => v === flag)?.[0] ?? `unknown(0x${(flag >>> 0).toString(16)})`;
