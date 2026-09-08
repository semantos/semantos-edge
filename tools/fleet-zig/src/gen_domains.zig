//! Emit the domain-flag constants for the other two languages.
//!
//! `domains.zig` is the single source. Everything else is generated from it:
//!
//!   components/cell-mesh/include/cell_domains.h   <- the firmware
//!   tools/domains.ts                              <- the host tools
//!
//! Three hand-maintained copies of a flag table is exactly how `ZONE_KEY`
//! drifted to 0x0b, collided with `CHANGE`, and moved to 0x0e — with a comment
//! that went on asserting the old value after the registry moved. One source,
//! generated outputs, and a test that fails if the checked-in files are stale.
//!
//!   zig build gen-domains          # print both, for inspection
//!   zig build gen-domains -- write # rewrite them in place

const std = @import("std");
const domains = @import("domains");

fn writeHeader(w: *std.Io.Writer) !void {
    try w.writeAll(
        \\/*
        \\ * cell_domains.h — GENERATED from tools/fleet-zig/src/domains.zig.
        \\ * Do not hand-edit; run `zig build gen-domains -- write` in tools/fleet-zig.
        \\ *
        \\ * Domain flags name WHO may act, not WHAT the cell is — `type_hash` at
        \\ * header offset 30 already says what it is. Cells authorised by the same
        \\ * thing share a flag; cells authorised by different things do not.
        \\ *
        \\ * The flag lives at cell header bytes 24-27 and is read by
        \\ * OP_CHECKDOMAINFLAG (opcode 198), exact equality, fail-closed.
        \\ *
        \\ * WARNING: a flag on an UNSIGNED cell is a label, not a boundary —
        \\ * nothing covers its header, so anyone may set it to anything. Only
        \\ * where a signature covers bytes 24-27 (every signed cell, since
        \\ * cm_sig_hash_cell hashes all 1024) is a domain check meaningful.
        \\ *
        \\ * WARNING: bit 31 must stay clear. The engine reads the expected flag
        \\ * as a BSV script number, so bit 31 is a SIGN bit — see
        \\ * components/cell-mesh/test/vectors/README.md.
        \\ */
        \\#pragma once
        \\
        \\#include <stdint.h>
        \\
        \\
    );
    for (domains.allocated) |a| {
        try w.print("/** {s} */\n#define {s} 0x{x:0>8}u\n\n", .{ a.doc, a.c_name, a.value });
    }
    try w.print("/** Largest flag OP_CHECKDOMAINFLAG can be handed unambiguously. */\n" ++
        "#define CM_DOMAIN_SCRIPT_SAFE_MAX 0x{x:0>8}u\n\n" ++
        "/** Number of flags this layer allocates. */\n" ++
        "#define CM_DOMAIN_ALLOCATED_COUNT {d}\n", .{ domains.script_safe_max, domains.allocated.len });
}

fn writeTs(w: *std.Io.Writer) !void {
    try w.writeAll(
        \\/**
        \\ * domains.ts — GENERATED from tools/fleet-zig/src/domains.zig.
        \\ * Do not hand-edit; run `zig build gen-domains -- write` in tools/fleet-zig.
        \\ *
        \\ * Domain flags name WHO may act, not WHAT the cell is — `type_hash` at
        \\ * header offset 30 already says what it is. Cells authorised by the same
        \\ * thing share a flag; cells authorised by different things do not.
        \\ *
        \\ * The flag lives at cell header bytes 24-27 and is read by
        \\ * OP_CHECKDOMAINFLAG (opcode 198): exact equality, fail-closed.
        \\ *
        \\ * ⚠ A flag on an UNSIGNED cell is a label, not a boundary — nothing
        \\ * covers its header, so anyone may set it to anything. A domain check
        \\ * only means something where a signature covers bytes 24-27.
        \\ *
        \\ * ⚠ Bit 31 must stay clear: the engine reads the expected flag as a BSV
        \\ * script number, so bit 31 is a SIGN bit. See
        \\ * components/cell-mesh/test/vectors/README.md.
        \\ */
        \\
        \\export const DOMAIN = {
        \\
    );
    for (domains.allocated) |a| {
        try w.print("  /** {s} */\n  {s}: 0x{x:0>8},\n", .{ a.doc, a.ts_name, a.value });
    }
    try w.writeAll(
        \\} as const;
        \\
        \\/** Largest flag OP_CHECKDOMAINFLAG can be handed unambiguously. */
        \\
    );
    try w.print("export const SCRIPT_SAFE_MAX = 0x{x:0>8};\n\n", .{domains.script_safe_max});
    try w.writeAll(
        \\/** Human name for a flag, for logs and receipts. */
        \\export const domainName = (flag: number): string =>
        \\  Object.entries(DOMAIN).find(([, v]) => v === flag)?.[0] ?? `unknown(0x${(flag >>> 0).toString(16)})`;
        \\
    );
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    const write = args.len > 1 and std.mem.eql(u8, args[1], "write");

    var hbuf: std.ArrayList(u8) = .empty;
    defer hbuf.deinit(a);
    var hw = std.Io.Writer.Allocating.fromArrayList(a, &hbuf);
    try writeHeader(&hw.writer);
    hbuf = hw.toArrayList();

    var tbuf: std.ArrayList(u8) = .empty;
    defer tbuf.deinit(a);
    var tw = std.Io.Writer.Allocating.fromArrayList(a, &tbuf);
    try writeTs(&tw.writer);
    tbuf = tw.toArrayList();

    if (!write) {
        var out: [4096]u8 = undefined;
        var w = std.fs.File.stdout().writer(&out);
        try w.interface.writeAll(hbuf.items);
        try w.interface.writeAll("\n// ---- domains.ts ----\n");
        try w.interface.writeAll(tbuf.items);
        try w.interface.flush();
        return;
    }

    try std.fs.cwd().writeFile(.{
        .sub_path = "../../components/cell-mesh/include/cell_domains.h",
        .data = hbuf.items,
    });
    try std.fs.cwd().writeFile(.{ .sub_path = "../domains.ts", .data = tbuf.items });

    var out: [256]u8 = undefined;
    var w = std.fs.File.stdout().writer(&out);
    try w.interface.print("wrote cell_domains.h ({d} B) and domains.ts ({d} B) from {d} flags\n",
        .{ hbuf.items.len, tbuf.items.len, domains.allocated.len });
    try w.interface.flush();
}
