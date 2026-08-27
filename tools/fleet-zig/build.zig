const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const bsvz = b.dependency("bsvz", .{ .target = target, .optimize = optimize });

    // The derivation port, importable by other Zig code.
    const derive_mod = b.addModule("derive", .{
        .root_source_file = b.path("src/derive.zig"),
        .target = target,
        .optimize = optimize,
    });
    derive_mod.addImport("bsvz", bsvz.module("bsvz"));

    const certid_mod = b.addModule("certid", .{
        .root_source_file = b.path("src/certid.zig"),
        .target = target,
        .optimize = optimize,
    });

    const identity_mod = b.addModule("identity", .{
        .root_source_file = b.path("src/identity.zig"),
        .target = target,
        .optimize = optimize,
    });
    identity_mod.addImport("derive", derive_mod);
    identity_mod.addImport("certid", certid_mod);

    const store_mod = b.addModule("store", .{
        .root_source_file = b.path("src/store.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The mesh's own wire format, imported from the component the FIRMWARE
    // builds against rather than re-declared here — so a layout change cannot
    // leave the control plane behind.
    const cell_wire_mod = b.addModule("cell_wire", .{
        .root_source_file = b.path("../../components/cell-mesh-zig/src/cell_wire.zig"),
        .target = target,
        .optimize = optimize,
    });

    const cert_mod = b.addModule("cert", .{
        .root_source_file = b.path("src/cert.zig"),
        .target = target,
        .optimize = optimize,
    });
    cert_mod.addImport("bsvz", bsvz.module("bsvz"));
    cert_mod.addImport("cell_wire", cell_wire_mod);
    cert_mod.addImport("derive", derive_mod);

    // Conformance against the SDK's pinned golden vector. The vector is
    // embedded rather than read at runtime so the test cannot silently pass by
    // failing to find it.
    const conformance = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/conformance.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    conformance.root_module.addImport("derive", derive_mod);
    conformance.root_module.addImport("certid", certid_mod);
    conformance.root_module.addImport("identity", identity_mod);
    conformance.root_module.addImport("store", store_mod);
    conformance.root_module.addImport("cert", cert_mod);
    conformance.root_module.addAnonymousImport("golden", .{
        .root_source_file = b.path("vectors/cross-impl-derivation.golden.json"),
    });
    conformance.root_module.addAnonymousImport("golden_escaping", .{
        .root_source_file = b.path("vectors/canonical-json-escaping.golden.json"),
    });
    conformance.root_module.addAnonymousImport("golden_rotation", .{
        .root_source_file = b.path("vectors/rotation.golden.json"),
    });
    conformance.root_module.addAnonymousImport("golden_cert", .{
        .root_source_file = b.path("vectors/cert.golden.json"),
    });
    conformance.root_module.addAnonymousImport("cap_header", .{
        .root_source_file = b.path("../../components/cell-mesh/include/cell_capability.h"),
    });

    const run_conformance = b.addRunArtifact(conformance);
    b.step("test", "run cross-implementation conformance").dependOn(&run_conformance.step);
}
