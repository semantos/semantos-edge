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
    conformance.root_module.addAnonymousImport("golden", .{
        .root_source_file = b.path("vectors/cross-impl-derivation.golden.json"),
    });

    const run_conformance = b.addRunArtifact(conformance);
    b.step("test", "run cross-implementation conformance").dependOn(&run_conformance.step);
}
