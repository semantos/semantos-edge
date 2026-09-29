//! `fleet-bridge-sign` — the fleet operator's half of the live fleet↔wallet
//! bridge (semantos-core `docs/design/IDENTITY-PLANE-CONVERGENCE.md` §5).
//!
//! The wallet operator fetches a challenge nonce and hands (walletPage0Pubkey,
//! nonce) to the fleet operator, who runs this over the SAME nonce. It derives
//! the fleet operator root from its universe (email+salt), signs the shared
//! bridge digest, and prints the fleet half as JSON:
//!   { fleetRootPubkey, fleetSignature (DER hex), nonce, fleetCertId }
//! The wallet operator pastes this into helm `bindFleet`, which adds the wallet
//! half and POSTs both to the wallet brain's /api/v1/auth/bind-fleet.
//!
//! Only PUBLIC material + a signature leave; the operator root private key never
//! does. Usage:
//!   fleet-bridge-sign --wallet-pub <66-hex> --nonce <str> --email <e> --salt <s>

const std = @import("std");
const derive = @import("derive");
const identity = @import("identity");
const bridge = @import("bridge");

fn argValue(args: [][:0]u8, flag: []const u8) ?[]const u8 {
    var i: usize = 1;
    while (i + 1 < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], flag)) return args[i + 1];
    }
    return null;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);

    const wallet_pub_hex = argValue(args, "--wallet-pub") orelse return usage("--wallet-pub required");
    const nonce = argValue(args, "--nonce") orelse return usage("--nonce required");
    const email = argValue(args, "--email") orelse return usage("--email required");
    const salt = argValue(args, "--salt") orelse return usage("--salt required");

    if (wallet_pub_hex.len != 66) return usage("--wallet-pub must be 66-hex compressed SEC1");
    var wallet_pub: [33]u8 = undefined;
    _ = std.fmt.hexToBytes(&wallet_pub, wallet_pub_hex) catch return usage("--wallet-pub is not hex");

    // Derive the fleet operator root from its universe (the private key stays here).
    const root_key = try derive.deriveRootKey(email, salt);
    const fleet_pub = (try root_key.publicKey()).toCompressedSec1();
    const root = try identity.rootIdentity(a, email, salt);

    // Sign the fleet half of the shared, order-independent bridge digest.
    const digest = bridge.buildBridgeDigest(wallet_pub, fleet_pub, nonce);
    const sig_der = try bridge.signFleetHalf(a, root_key, digest);
    defer a.free(sig_der);

    var fleet_pub_hex: [66]u8 = undefined;
    _ = std.fmt.bufPrint(&fleet_pub_hex, "{x}", .{&fleet_pub}) catch unreachable;

    // Hex-encode the DER signature (its length is runtime, so encode explicitly).
    const sig_hex = try a.alloc(u8, sig_der.len * 2);
    defer a.free(sig_hex);
    const hexd = "0123456789abcdef";
    for (sig_der, 0..) |byte, i| {
        sig_hex[i * 2] = hexd[byte >> 4];
        sig_hex[i * 2 + 1] = hexd[byte & 0x0f];
    }

    var out_buf: [640]u8 = undefined;
    const line = try std.fmt.bufPrint(
        &out_buf,
        "{{\"fleetRootPubkey\":\"{s}\",\"fleetSignature\":\"{s}\",\"nonce\":\"{s}\",\"fleetCertId\":\"{s}\"}}\n",
        .{ &fleet_pub_hex, sig_hex, nonce, &root.cert_id },
    );
    var buf: [64]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    try w.interface.writeAll(line);
    try w.interface.flush();
}

fn usage(msg: []const u8) void {
    std.debug.print("fleet-bridge-sign: {s}\n", .{msg});
    std.debug.print("usage: fleet-bridge-sign --wallet-pub <66-hex> --nonce <str> --email <e> --salt <s>\n", .{});
    std.process.exit(2);
}
