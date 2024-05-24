const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_aegis128x = b.addStaticLibrary(.{
        .name = "aegis128x",
        .root_source_file = b.path("aegis128x.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib_aegis128x);

    const lib_aegis256x = b.addStaticLibrary(.{
        .name = "aegis256x",
        .root_source_file = b.path("aegis256x.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib_aegis256x);

    const test_vectors = b.addTest(.{
        .root_source_file = b.path("test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_step_run = b.addRunArtifact(test_vectors);
    const test_step = b.step("test", "Check test vectors");
    test_step.dependOn(&test_step_run.step);
}
