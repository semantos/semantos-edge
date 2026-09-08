//! Do bsvz and @bsv/sdk produce byte-identical ECDSA signatures?
const std = @import("std");
const bsvz = @import("bsvz");
const ec = bsvz.primitives.ec;

const TS_PUB = "03079264c4b4bfcd7fe3a7b7b92b6c439f3a5b3abcd29189bf7b54d781ff03d722";
const TS_SHA = "e9183d9a79aad8a047b8e67981210d50b01fc75b1edba5bc32ba3d3ec4d5056d";
const TS_RS = "f26a8dc2e27f4ca15ff7e78b6a4578571befd785a44025da0fa5dc6be80a7e68359f089c07c9adb083d2c5283c4b75fa92e1303aac15507b8ba4223f287af861";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const a = gpa.allocator();

    var cell: [1024]u8 = undefined;
    for (&cell, 0..) |*b, i| b.* = @intCast((i * 7 + 3) & 0xff);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&cell, &digest, .{});
    var dhex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&dhex, "{x}", .{&digest});
    std.debug.print("cell sha256 : {s}\n", .{&dhex});
    std.debug.print("  matches TS: {}\n", .{std.mem.eql(u8, &dhex, TS_SHA)});

    var kb: [32]u8 = [_]u8{0} ** 32;
    kb[31] = 0x42;
    const key = try ec.PrivateKey.fromBytes(kb);
    const pk = try key.publicKey();
    var phex: [66]u8 = undefined;
    _ = try std.fmt.bufPrint(&phex, "{x}", .{&pk.toCompressedSec1()});
    std.debug.print("pubkey      : {s}\n", .{&phex});
    std.debug.print("  matches TS: {}\n", .{std.mem.eql(u8, &phex, TS_PUB)});

    const der = try key.signDigest(digest);
    const parsed = try bsvz.primitives.ecdsa.Signature.fromDer(der.asSlice());
    var rs: [64]u8 = undefined;
    @memcpy(rs[0..32], &parsed.r);
    @memcpy(rs[32..64], &parsed.s);
    var rshex: [128]u8 = undefined;
    _ = try std.fmt.bufPrint(&rshex, "{x}", .{&rs});
    std.debug.print("bsvz  r||s  : {s}\n", .{&rshex});
    std.debug.print("@bsv  r||s  : {s}\n", .{TS_RS});
    std.debug.print("\n>>> byte-identical signature: {}\n", .{std.mem.eql(u8, &rshex, TS_RS)});

    // Whether or not the bytes match, does each side verify the other's?
    const ts_rs = try a.alloc(u8, 64);
    defer a.free(ts_rs);
    _ = try std.fmt.hexToBytes(ts_rs, TS_RS);
    var ts_sig = bsvz.primitives.ecdsa.Signature{ .r = undefined, .s = undefined };
    @memcpy(&ts_sig.r, ts_rs[0..32]);
    @memcpy(&ts_sig.s, ts_rs[32..64]);
    const ok = try ts_sig.verifyDigest(digest, .{ .bytes = pk.toCompressedSec1() });
    std.debug.print(">>> bsvz verifies the TS signature: {}\n", .{ok});
}
