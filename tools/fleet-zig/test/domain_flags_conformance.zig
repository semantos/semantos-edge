//! Parity: fleet-zig's SHARED domain-flag values match semantos-core's, so the
//! two planes' registries cannot silently drift apart (the `ZONE_KEY 0x0e`
//! hazard `domains.zig` itself warns about). Asserts `src/domains.zig` against
//! the vendored snapshot of semantos-core's `constants.json -> domainFlags`
//! (`vectors/shared-domain-flags.golden.json`; provenance in vectors/README.md).
//!
//! Only the SHARED subset is checked — fleet-specific flags (fleet_page,
//! fleet_device, org_member, mesh_*) are fleet-owned and absent from the
//! snapshot by design. Design: semantos-core docs/design/IDENTITY-EDGE-CONVERGENCE.md.

const std = @import("std");
const domains = @import("domains");

const GOLDEN = @embedFile("shared_flags_golden");

fn flag(obj: std.json.ObjectMap, key: []const u8) i64 {
    return obj.get(key).?.integer;
}

test "shared domain flags: fleet-zig agrees with semantos-core's constants.json snapshot" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, GOLDEN, .{});
    defer parsed.deinit();
    const shared = parsed.value.object.get("sharedDomainFlags").?.object;

    // ZONE_KEY — the value both planes speak; the one most likely to drift.
    try std.testing.expectEqual(flag(shared, "ZONE_KEY"), @as(i64, @intCast(domains.zone)));

    // The sovereign / client-defined band boundaries (semantos-core names them
    // clientDefined{Min,Max}; fleet-zig names them sovereign_{min,max} — same band).
    try std.testing.expectEqual(flag(shared, "clientDefinedMin"), @as(i64, @intCast(domains.sovereign_min)));
    try std.testing.expectEqual(flag(shared, "clientDefinedMax"), @as(i64, @intCast(domains.sovereign_max)));

    // ZONE_KEY sits in the Plexus well-known band — a sanity tie between the
    // two band definitions, so a snapshot that lost the band bounds is caught.
    try std.testing.expect(domains.zone >= @as(u64, @intCast(flag(shared, "plexusReservedMin"))));
    try std.testing.expect(domains.zone <= @as(u64, @intCast(flag(shared, "plexusReservedMax"))));
}
