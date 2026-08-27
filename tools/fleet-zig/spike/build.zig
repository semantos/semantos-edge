const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const bsvz = b.dependency("bsvz", .{ .target = target, .optimize = optimize });
    const exe = b.addExecutable(.{
        .name = "spike",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("bsvz", bsvz.module("bsvz"));
    b.installArtifact(exe);
    const run = b.addRunArtifact(exe);
    b.step("run", "run spike").dependOn(&run.step);

    const sigcmp = b.addExecutable(.{
        .name = "sigcmp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/sigcmp.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    sigcmp.root_module.addImport("bsvz", bsvz.module("bsvz"));
    b.installArtifact(sigcmp);
    const run_sigcmp = b.addRunArtifact(sigcmp);
    b.step("sigcmp", "compare bsvz vs @bsv/sdk signatures").dependOn(&run_sigcmp.step);
}
