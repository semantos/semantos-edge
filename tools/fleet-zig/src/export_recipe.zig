//! Emit a recovery recipe on stdout, so the TypeScript SDK can be asked whether
//! it accepts one this plane produced. The other direction of interop — the
//! conformance tests only prove Zig can consume what the SDK emitted.
const std = @import("std");
const identity = @import("identity");
const store_mod = @import("store");
const recovery = @import("recovery");
const domains = @import("domains");

const EMAIL = "interop@fleet.example";
const SALT = "interop-salt-v1";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const root = try identity.rootIdentity(a, EMAIL, SALT);
    var s = store_mod.Store.initMemory(a);
    defer s.deinit();

    const zi = try s.allocateIndex(&root.cert_id, "zone", domains.zone);
    const zone = try identity.deriveChildIdentity(a, EMAIL, SALT, "root", "zone", domains.zone, zi);
    defer zone.deinit(a);
    try s.putNode(.{ .cert_id = &zone.cert_id, .parent_cert_id = &root.cert_id, .resource_id = "zone", .domain_flag = domains.zone, .child_index = zi, .label = "north" });

    for (0..3) |_| {
        const di = try s.allocateIndex(&zone.cert_id, "device", domains.fleet_device);
        const unit = try identity.deriveChildIdentity(a, EMAIL, SALT, zone.derivation_path, "device", domains.fleet_device, di);
        defer unit.deinit(a);
        try s.putNode(.{ .cert_id = &unit.cert_id, .parent_cert_id = &zone.cert_id, .resource_id = "device", .domain_flag = domains.fleet_device, .child_index = di, .label = "unit" });
    }
    _ = try s.burnSlot(&zone.cert_id, "device", domains.fleet_device); // a retired index to carry

    const recipe = try recovery.exportRecipe(a, &s, &root.cert_id, EMAIL);
    defer a.free(recipe);

    var buf: [64]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    try w.interface.writeAll(recipe);
    try w.interface.flush();
}
