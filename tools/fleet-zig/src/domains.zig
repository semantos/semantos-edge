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

pub const sovereign_min: u64 = 0x0001_0000;
pub const sovereign_max: u64 = 0xffff_ffff;

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
        fleet_device => "fleet.device",
        org_member => "org.member",
        0x06 => "plexus.child.creation",
        else => "unknown",
    };
}
