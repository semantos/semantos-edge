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

    const domains_mod = b.addModule("domains", .{
        .root_source_file = b.path("src/domains.zig"),
        .target = target,
        .optimize = optimize,
    });

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

    const recovery_mod = b.addModule("recovery", .{
        .root_source_file = b.path("src/recovery.zig"),
        .target = target,
        .optimize = optimize,
    });
    recovery_mod.addImport("derive", derive_mod);
    recovery_mod.addImport("identity", identity_mod);
    recovery_mod.addImport("store", store_mod);

    const scim_mod = b.addModule("scim", .{
        .root_source_file = b.path("src/scim.zig"),
        .target = target,
        .optimize = optimize,
    });
    scim_mod.addImport("identity", identity_mod);
    scim_mod.addImport("store", store_mod);
    scim_mod.addImport("domains", domains_mod);

    const scim_wire_mod = b.addModule("scim_wire", .{
        .root_source_file = b.path("src/scim_wire.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Fleet ↔ wallet bridge (IDENTITY-PLANE-CONVERGENCE §5). This plane signs the
    // fleet half + verifies the wallet's page-0 'anyone'-child half. The digest is
    // pinned by `vectors/fleet-bridge.golden.json` — a copy of semantos-core's
    // `tests/fixtures/fleet_bridge_kat.json` (manual port; the repos don't sync).
    const bridge_mod = b.addModule("bridge", .{
        .root_source_file = b.path("src/bridge.zig"),
        .target = target,
        .optimize = optimize,
    });
    bridge_mod.addImport("bsvz", bsvz.module("bsvz"));
    bridge_mod.addAnonymousImport("bridge_golden", .{
        .root_source_file = b.path("vectors/fleet-bridge.golden.json"),
    });
    const bridge_test = b.addTest(.{ .root_module = bridge_mod });
    const run_bridge = b.addRunArtifact(bridge_test);
    b.step("test-bridge", "run the fleet↔wallet bridge digest KAT + round-trip").dependOn(&run_bridge.step);

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
    conformance.root_module.addImport("recovery", recovery_mod);
    conformance.root_module.addImport("scim", scim_mod);
    conformance.root_module.addImport("scim_wire", scim_wire_mod);
    conformance.root_module.addImport("domains", domains_mod);
    conformance.root_module.addImport("cell_wire", cell_wire_mod);
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
    conformance.root_module.addAnonymousImport("golden_recovery", .{
        .root_source_file = b.path("vectors/recovery.golden.json"),
    });
    conformance.root_module.addAnonymousImport("cap_header", .{
        .root_source_file = b.path("../../components/cell-mesh/include/cell_capability.h"),
    });

    const run_conformance = b.addRunArtifact(conformance);
    const test_step = b.step("test", "run cross-implementation conformance");
    test_step.dependOn(&run_conformance.step);
    test_step.dependOn(&run_bridge.step);

    // M5: drive real boards from this plane.
    const hw = b.addExecutable(.{
        .name = "fleet-hw",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/hardware.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    hw.root_module.addImport("derive", derive_mod);
    hw.root_module.addImport("identity", identity_mod);
    hw.root_module.addImport("cert", cert_mod);
    hw.root_module.addImport("domains", domains_mod);
    b.installArtifact(hw);
    const run_hw = b.addRunArtifact(hw);
    b.step("hw", "run the hardware proof against two C6 boards").dependOn(&run_hw.step);

    const exporter = b.addExecutable(.{
        .name = "export-recipe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/export_recipe.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exporter.root_module.addImport("identity", identity_mod);
    exporter.root_module.addImport("store", store_mod);
    exporter.root_module.addImport("recovery", recovery_mod);
    exporter.root_module.addImport("domains", domains_mod);

    const gen_domains = b.addExecutable(.{
        .name = "gen-domains",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/gen_domains.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    gen_domains.root_module.addImport("domains", domains_mod);
    const run_gen = b.addRunArtifact(gen_domains);
    if (b.args) |args| run_gen.addArgs(args);
    b.step("gen-domains", "Emit cell_domains.h and domains.ts from domains.zig")
        .dependOn(&run_gen.step);
    b.installArtifact(exporter);
    const run_export = b.addRunArtifact(exporter);
    b.step("export-recipe", "print a recovery recipe on stdout").dependOn(&run_export.step);

}
