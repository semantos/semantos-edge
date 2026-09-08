//! Domain flags: the namespace, and the thing the runtime actually enforces.
//!
//! An earlier version of this plane separated devices from people with the
//! `resourceId` slot name — `"device"` vs `"member"`. That works arithmetically
//! (the allocator is keyed on the whole tuple) but it is the wrong mechanism,
//! because it is invisible to everything below the control plane.
//!
//! `domainFlag` is the mechanism. It is folded into the BRC-42 invoice number,
//! so it separates keys; it is carried in the **cell header at bytes 24–27**;
//! and `OP_CHECKDOMAINFLAG` (opcode 198) asserts it inside the engine, which is
//! what binds a derived key to its declared domain rather than merely labelling
//! it. It is also the key of the schema registry — `DomainSchema` is looked up
//! by `(domainFlag, version)` — and it is what `FunctionalDomainRecord` carries
//! into a Plexus recovery enrolment. One value, four jobs.
//!
//! A slot name is a label. A domain flag is enforced.
//!
//! ## Bands
//!
//! From the SDK's `tokens/domainFlags.ts`:
//!
//!   0x00000001–0x000000ff  Plexus well-known
//!   0x00000100–0x0000ffff  extended standard
//!   0x00010000–0xffffffff  client sovereign
//!
//! ## ⚠ A registry gap worth knowing
//!
//! `ZONE_KEY = 0x0e` is allocated in semantos-core's `core/constants/constants.json`,
//! which is the codegen source for that repo. The **Plexus SDK does not know
//! about it** — `tokens/domainFlags.ts` lists 0x01–0x0a, 0xca, 0xcb, and nothing
//! at 0x0e. So a well-known-band value is spoken for in one registry and free in
//! the other. That is exactly the shape of the `ZONE_KEY` 0x0b→0x0e collision
//! with `CHANGE` that already happened once.
//!
//! This plane uses 0x0e because semantos-core is canonical for zones, and keeps
//! its OWN flags in the sovereign band where neither registry allocates, rather
//! than claiming more well-known space it does not own.

const std = @import("std");

pub const Error = error{ NotSovereign, FlagCollision };

/// Zone — semantos-core canonical (`constants.json` `domainFlags.ZONE_KEY`).
/// See the registry-gap note above before changing this.
pub const zone: u64 = 0x0e;

/// This layer's sovereign page. Provisional: these are not registry-allocated,
/// and if they should become canonical they belong in
/// `semantos-core/core/constants/constants.json`, which is the codegen source —
/// not redeclared here and there.
pub const fleet_page: u64 = 0x00f1_0000;

/// A physical unit in the field. Verifies and acts; holds no private key.
pub const fleet_device: u64 = fleet_page | 0x01;

/// A person, mirrored from an IdP. Same tree, different domain.
pub const org_member: u64 = fleet_page | 0x02;

// ── Mesh authority rails ────────────────────────────────────────────────────
//
// These name WHO may act, not WHAT the cell is. The cell already says what it
// is: `type_hash` at header offset 30. Minting a flag per cell type would make
// the domain a second, redundant type field — the same mistake as separating
// namespaces by `resourceId`, which is what this module exists to correct.
//
// So the split is by authority: cells that are authorised by the same thing
// share a domain, and cells authorised by different things do not.
//
// ⚠ A flag on an UNSIGNED cell is a label, not a boundary. Nothing covers the
// header of an unsigned cell, so anyone can set it to anything. `mesh_telemetry`
// exists so those cells have a namespace for schema purposes; it must never be
// mistaken for an authority claim. Domain enforcement is only meaningful where
// a signature covers bytes 24-27 — which, because `cm_sig_hash_cell` hashes all
// 1024 bytes, is every signed cell.

/// Device relay authority: `cellmesh.capability.v0` GRANTS it, and
/// `forward.v1` / `forward.v2` / `routing.cont.v0` EXERCISE it.
///
/// This is deliberately the SAME flag as `fleet_device`, not a sibling. A
/// capability cert grants a device the right to relay; that is exactly what a
/// fleet device's identity is for, so it is one namespace reached from two
/// provisioning paths. Different ISSUERS are separated by the signature anchor,
/// not by the domain.
///
/// ⚠ HARD CONSTRAINT: the cert and the forward cells it authorises must carry
/// the SAME flag. `cm_cap_lookup` keys on it, so a mismatch is a miss and every
/// forward drops. Do not give them separate flags "for clarity".
pub const mesh_relay: u64 = fleet_device;

/// Payment-channel authority: `channel_open` / `channel_commitment` /
/// `channel_close` / `channel_settle`. Authority is the wallet funding the
/// channel — distinct from the right to relay traffic on it.
pub const mesh_payment: u64 = fleet_page | 0x10;

/// Physical-actuation authority: `actuator_offer` / `actuator_activate` /
/// `confirmed_tap` / `rule.v0`. Kept apart from payment because "may spend"
/// and "may move something in the world" are not the same permission, and this
/// is the rail where conflating them is most expensive.
pub const mesh_control: u64 = fleet_page | 0x20;

/// Unsigned observational cells: `heartbeat` / `tap` / `telemetry` /
/// `forward.v0` / MNCA tiles. See the warning above — a namespace, not a gate.
pub const mesh_telemetry: u64 = fleet_page | 0x30;

/// `cellmesh.scripted.v0`, which carries its own locking script. The authority
/// is IN the script, so the domain says only which namespace the script runs in.
pub const mesh_script: u64 = fleet_page | 0x40;

pub const sovereign_min: u64 = 0x0001_0000;
pub const sovereign_max: u64 = 0xffff_ffff;

/// The largest flag OP_CHECKDOMAINFLAG can be handed unambiguously.
///
/// ⚠ Measured against the live engine, not inferred. The opcode reads the
/// expected flag off the stack as a BSV SCRIPT NUMBER — sign-magnitude, little
/// endian, bit 7 of the top byte is the SIGN. A four-byte push of 0x80000000 is
/// the bytes `00 00 00 80`, which is script-number NEGATIVE ZERO, so the engine
/// compares it as 0 — and a cell declaring domain 0 then ACCEPTS against an
/// expected flag of 0x80000000. Same for 0xffffffff.
///
/// That is a silent authorisation bypass for any flag with bit 31 set, so this
/// layer refuses to allocate one. Reproduced for three values and pinned in
/// `components/cell-mesh/test/vectors/gen-domainflag-vectors.mjs`, which fails
/// if the engine ever stops behaving this way.
pub const script_safe_max: u64 = 0x7fff_ffff;

/// Is this flag safe to hand to OP_CHECKDOMAINFLAG?
pub fn isScriptSafe(flag: u64) bool {
    return flag <= script_safe_max;
}

comptime {
    // A flag this layer allocates must never be one the engine misreads.
    if (!isScriptSafe(zone)) @compileError("zone flag has bit 31 set");
    if (!isScriptSafe(fleet_device)) @compileError("fleet_device flag has bit 31 set");
    if (!isScriptSafe(org_member)) @compileError("org_member flag has bit 31 set");
    if (!isScriptSafe(mesh_payment)) @compileError("mesh_payment flag has bit 31 set");
    if (!isScriptSafe(mesh_control)) @compileError("mesh_control flag has bit 31 set");
    if (!isScriptSafe(mesh_telemetry)) @compileError("mesh_telemetry flag has bit 31 set");
    if (!isScriptSafe(mesh_script)) @compileError("mesh_script flag has bit 31 set");
}

/// Every flag this layer allocates, so a generator and a collision test can
/// walk them without a hand-maintained second list going stale.
pub const Allocated = struct {
    name: []const u8,
    c_name: []const u8,
    ts_name: []const u8,
    value: u64,
    doc: []const u8,
};

pub const allocated = [_]Allocated{
    .{ .name = "zone", .c_name = "CM_DOMAIN_ZONE", .ts_name = "zone", .value = zone, .doc = "semantos-core canonical ZONE_KEY" },
    .{ .name = "fleet.device", .c_name = "CM_DOMAIN_FLEET_DEVICE", .ts_name = "fleetDevice", .value = fleet_device, .doc = "a physical unit in the field; also the relay rail" },
    .{ .name = "org.member", .c_name = "CM_DOMAIN_ORG_MEMBER", .ts_name = "orgMember", .value = org_member, .doc = "a person, mirrored from an IdP" },
    .{ .name = "mesh.relay", .c_name = "CM_DOMAIN_MESH_RELAY", .ts_name = "meshRelay", .value = mesh_relay, .doc = "capability.v0 grants it; forward.v1/v2 + routing.cont.v0 exercise it (== fleet.device)" },
    .{ .name = "mesh.payment", .c_name = "CM_DOMAIN_MESH_PAYMENT", .ts_name = "meshPayment", .value = mesh_payment, .doc = "channel open/commitment/close/settle" },
    .{ .name = "mesh.control", .c_name = "CM_DOMAIN_MESH_CONTROL", .ts_name = "meshControl", .value = mesh_control, .doc = "actuator offer/activate, confirmed_tap, rule.v0" },
    .{ .name = "mesh.telemetry", .c_name = "CM_DOMAIN_MESH_TELEMETRY", .ts_name = "meshTelemetry", .value = mesh_telemetry, .doc = "UNSIGNED: heartbeat, tap, telemetry, forward.v0, MNCA tiles - a label, not a gate" },
    .{ .name = "mesh.script", .c_name = "CM_DOMAIN_MESH_SCRIPT", .ts_name = "meshScript", .value = mesh_script, .doc = "scripted.v0; authority is in the locking script" },
};

pub fn isSovereign(flag: u64) bool {
    return flag >= sovereign_min and flag <= sovereign_max;
}

/// Every flag the Plexus SDK allocates in the well-known band, so a test can
/// assert this layer never lands on one.
pub const plexus_well_known = [_]u64{
    0x01, // EDGE_CREATION
    0x02, // SIGNING
    0x03, // ENCRYPTION
    0x04, // MESSAGING
    0x05, // ATTESTATION
    0x06, // CHILD_CREATION
    0x07, // PERMISSION_GRANT
    0x08, // DATA_SOVEREIGNTY
    0x09, // SCHEMA_SIGNING
    0x0a, // METERING
    0xca, // CAPABILITY_BINDING
    0xcb, // FUNDING
};

/// A human name for a flag, for logs and receipts.
pub fn name(flag: u64) []const u8 {
    return switch (flag) {
        zone => "zone",
        // fleet_device and mesh_relay are the same value by design, so this
        // arm covers both. The rail is named where it is granted.
        fleet_device => "fleet.device",
        org_member => "org.member",
        mesh_payment => "mesh.payment",
        mesh_control => "mesh.control",
        mesh_telemetry => "mesh.telemetry",
        mesh_script => "mesh.script",
        0x06 => "plexus.child.creation",
        else => "unknown",
    };
}
