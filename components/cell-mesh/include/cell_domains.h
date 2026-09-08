/*
 * cell_domains.h — GENERATED from tools/fleet-zig/src/domains.zig.
 * Do not hand-edit; run `zig build gen-domains -- write` in tools/fleet-zig.
 *
 * Domain flags name WHO may act, not WHAT the cell is — `type_hash` at
 * header offset 30 already says what it is. Cells authorised by the same
 * thing share a flag; cells authorised by different things do not.
 *
 * The flag lives at cell header bytes 24-27 and is read by
 * OP_CHECKDOMAINFLAG (opcode 198), exact equality, fail-closed.
 *
 * WARNING: a flag on an UNSIGNED cell is a label, not a boundary —
 * nothing covers its header, so anyone may set it to anything. Only
 * where a signature covers bytes 24-27 (every signed cell, since
 * cm_sig_hash_cell hashes all 1024) is a domain check meaningful.
 *
 * WARNING: bit 31 must stay clear. The engine reads the expected flag
 * as a BSV script number, so bit 31 is a SIGN bit — see
 * components/cell-mesh/test/vectors/README.md.
 */
#pragma once

#include <stdint.h>

/** semantos-core canonical ZONE_KEY */
#define CM_DOMAIN_ZONE 0x0000000eu

/** a physical unit in the field; also the relay rail */
#define CM_DOMAIN_FLEET_DEVICE 0x00f10001u

/** a person, mirrored from an IdP */
#define CM_DOMAIN_ORG_MEMBER 0x00f10002u

/** capability.v0 grants it; forward.v1/v2 + routing.cont.v0 exercise it (== fleet.device) */
#define CM_DOMAIN_MESH_RELAY 0x00f10001u

/** channel open/commitment/close/settle */
#define CM_DOMAIN_MESH_PAYMENT 0x00f10010u

/** actuator offer/activate, confirmed_tap, rule.v0 */
#define CM_DOMAIN_MESH_CONTROL 0x00f10020u

/** UNSIGNED: heartbeat, tap, telemetry, forward.v0, MNCA tiles - a label, not a gate */
#define CM_DOMAIN_MESH_TELEMETRY 0x00f10030u

/** scripted.v0; authority is in the locking script */
#define CM_DOMAIN_MESH_SCRIPT 0x00f10040u

/** Largest flag OP_CHECKDOMAINFLAG can be handed unambiguously. */
#define CM_DOMAIN_SCRIPT_SAFE_MAX 0x7fffffffu

/** Number of flags this layer allocates. */
#define CM_DOMAIN_ALLOCATED_COUNT 8
