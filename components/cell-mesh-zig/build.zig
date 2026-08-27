const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "cell_mesh_zig",
        .linkage = .static,
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    // root.zig, not cell_wire.zig: rooting the test binary at one module meant
    // only that module's tests ever ran. See the test block in root.zig.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run Zig mesh-core unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
