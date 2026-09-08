//! Spike: can bsvz reproduce Plexus derivation byte-for-byte?
//! Checked against src/tests/vectors/cross-impl-derivation.golden.json.
const std = @import("std");
const bsvz = @import("bsvz");
const ec = bsvz.primitives.ec;

const ROOT_EMAIL = "vector@plexus.test";
const ROOT_SALT = "plexus-cross-impl-vector-v1";
const WANT_ROOT_PRIV = "fe99e571a1efe336bae65e3c18ceeca686333fcbcfff5b08ecf5fed42d0f8398";
const WANT_ROOT_PUB = "028abd82d22850c0bff781e9a47e7d4f7bd6bf58102baad9baf5f8fa17d0c2cfa4";
const INVOICE = "inbox:2:0";
const WANT_CHILD_PRIV = "a944d24511981a2277967f3a5dd7d27e8fb417cd4d7c8d8650a06076df816e1e";
const WANT_CHILD_PUB = "02237e12d171edde88f1c6980db9e289788dc418ed251cdecc9683e6186a702ede";

fn hex(comptime n: usize, bytes: [n]u8) [n * 2]u8 {
    var out: [n * 2]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{&bytes}) catch unreachable;
    return out;
}

fn check(label: []const u8, got: []const u8, want: []const u8) bool {
    const ok = std.mem.eql(u8, got, want);
    std.debug.print("  {s:<22} {s}  {s}\n", .{ label, if (ok) "MATCH  " else "DIFFERS", got });
    if (!ok) std.debug.print("  {s:<22} want    {s}\n", .{ "", want });
    return ok;
}

pub fn main() !void {
    std.debug.print("\nbsvz vs Plexus golden vector\n", .{});
    var fails: usize = 0;

    // 1. deriveRootKey = PBKDF2-HMAC-SHA512(password=email, salt=salt, 100_000, 32)
    var root_bytes: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(
        &root_bytes,
        ROOT_EMAIL,
        ROOT_SALT,
        100_000,
        std.crypto.auth.hmac.sha2.HmacSha512,
    );
    if (!check("root priv (PBKDF2)", &hex(32, root_bytes), WANT_ROOT_PRIV)) fails += 1;

    const root = try ec.PrivateKey.fromBytes(root_bytes);
    const root_pub = try root.publicKey();
    if (!check("root pub", &hex(33, root_pub.toCompressedSec1()), WANT_ROOT_PUB)) fails += 1;

    // 2. plexus-kdf-v1: parentPriv.deriveChild(parentPub, invoice) — SELF counterparty,
    //    ASCII invoice. bsvz's ec.deriveChild is the same BRC-42 construction.
    const child = try root.deriveChild(root_pub, INVOICE);
    if (!check("child priv (BRC-42)", &hex(32, child.toBytes()), WANT_CHILD_PRIV)) fails += 1;
    if (!check("child pub", &hex(33, (try child.publicKey()).toCompressedSec1()), WANT_CHILD_PUB)) fails += 1;

    std.debug.print("\n{s}\n\n", .{if (fails == 0)
        "*** bsvz reproduces Plexus derivation exactly ***"
    else
        "*** MISMATCH — the port is not a drop-in ***"});
    if (fails != 0) std.process.exit(1);
}
