//! Fleet ↔ wallet bridge — the fleet plane's half of the SYMMETRIC mutual
//! attestation that links a fleet operator root (World-2, Plexus — this repo)
//! and a wallet page-0 (World-1, hat-identity — semantos-core). See
//! semantos-core `docs/design/IDENTITY-PLANE-CONVERGENCE.md` §5 (option C).
//!
//! Both sides sign the SAME order-independent digest; each verifies in its
//! native dialect:
//!   fleet  half — the operator ROOT signs the digest directly (it holds the key)
//!   wallet half — page-0's BRC-42 'anyone'-child (page-0 cannot sign raw)
//!
//! This plane SIGNS the fleet half and VERIFIES the wallet half; semantos-core
//! does the mirror. The DIGEST is the one cross-language contract, pinned by the
//! shared KAT (`vectors/fleet-bridge.golden.json`, a copy of semantos-core's
//! `tests/fixtures/fleet_bridge_kat.json`). Signatures verify but do not
//! reproduce across implementations (different ECDSA nonce), exactly as the cert
//! vectors treat sigs.
//!
//! ⚠ The constants below MUST match the brain's `auth_handler.zig` byte-for-byte
//! (domain tag + BRC-43 invoice), or a live bridge 401s. The digest KAT catches
//! a domain/order drift; the invoice is exercised by the round-trip test.

const std = @import("std");
const bsvz = @import("bsvz");

pub const ec = bsvz.primitives.ec;
pub const PrivateKey = ec.PrivateKey;
pub const PublicKey = ec.PublicKey;

/// Raw-bytes domain tag prefixing the digest. Matches semantos-core.
pub const BRIDGE_DOMAIN = "semantos:fleet-wallet-bridge:v1";

/// The BRC-43 invoice the wallet page-0's bridge child signs under. Matches
/// semantos-core's `BRIDGE_PROTOCOL_NAME` — space form, level 1, keyID "1".
pub const BRIDGE_INVOICE_LEVEL: u8 = 1;
pub const BRIDGE_PROTOCOL_NAME = "semantos fleet wallet bridge v1";
pub const BRIDGE_KEY_ID = "1";

pub const Error = error{ InvalidPubkey, InvalidSignature };

/// The bridge digest both sides sign: `SHA-256(BRIDGE_DOMAIN ‖ lo ‖ hi ‖ nonce)`,
/// `lo`/`hi` = the two 33-byte compressed pubkeys sorted ASCENDING by bytes
/// (order-independent — the same fact from either side). Byte-identical to the
/// brain's + the TS wallet's `buildBridgeDigest`.
pub fn buildBridgeDigest(
    wallet_pub_sec1: [33]u8,
    fleet_pub_sec1: [33]u8,
    nonce: []const u8,
) [32]u8 {
    const order = std.mem.order(u8, &wallet_pub_sec1, &fleet_pub_sec1);
    const lo = if (order == .gt) fleet_pub_sec1 else wallet_pub_sec1;
    const hi = if (order == .gt) wallet_pub_sec1 else fleet_pub_sec1;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(BRIDGE_DOMAIN);
    hasher.update(&lo);
    hasher.update(&hi);
    hasher.update(nonce);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Sign the FLEET half: the operator root signs the digest directly. Returns a
/// DER signature (the bridge wire form; not the raw r‖s the on-device cell uses).
/// Caller frees.
pub fn signFleetHalf(allocator: std.mem.Allocator, fleet_root: PrivateKey, digest: [32]u8) ![]u8 {
    const der = try fleet_root.signDigest(digest);
    return allocator.dupe(u8, der.asSlice());
}

/// Verify the WALLET half: page-0's BRC-42 'anyone'-child signature (verifier
/// holds no key — re-derive the child of `wallet_pub` under the bridge invoice).
pub fn verifyWalletHalf(
    allocator: std.mem.Allocator,
    wallet_pub_sec1: [33]u8,
    digest: [32]u8,
    sig_der: []const u8,
) !bool {
    const p_pub = PublicKey.fromSec1(&wallet_pub_sec1) catch return Error.InvalidPubkey;
    var anyone_scalar = [_]u8{0} ** 32;
    anyone_scalar[31] = 1;
    const anyone = PrivateKey.fromBytes(anyone_scalar) catch return Error.InvalidPubkey;
    const invoice = try bsvz.primitives.brc43.formatInvoice(allocator, BRIDGE_INVOICE_LEVEL, BRIDGE_PROTOCOL_NAME, BRIDGE_KEY_ID);
    defer allocator.free(invoice);
    const child = p_pub.deriveChild(anyone, invoice) catch return Error.InvalidPubkey;
    const child_sec1 = child.toCompressedSec1();
    return bsvz.crypto.verifyDigest256RelaxedSec1(&child_sec1, digest, sig_der) catch Error.InvalidSignature;
}

/// Verify the FLEET half: the operator root's ECDSA signature over the digest.
pub fn verifyFleetHalf(fleet_pub_sec1: [33]u8, digest: [32]u8, sig_der: []const u8) !bool {
    return bsvz.crypto.verifyDigest256RelaxedSec1(&fleet_pub_sec1, digest, sig_der) catch Error.InvalidSignature;
}

/// Verify BOTH halves over the shared digest — the whole bridge. True only when
/// both the wallet 'anyone'-child and the fleet root signatures verify.
pub fn verifyBridge(
    allocator: std.mem.Allocator,
    wallet_pub_sec1: [33]u8,
    fleet_pub_sec1: [33]u8,
    nonce: []const u8,
    wallet_sig_der: []const u8,
    fleet_sig_der: []const u8,
) !bool {
    const digest = buildBridgeDigest(wallet_pub_sec1, fleet_pub_sec1, nonce);
    if (!(try verifyWalletHalf(allocator, wallet_pub_sec1, digest, wallet_sig_der))) return false;
    return verifyFleetHalf(fleet_pub_sec1, digest, fleet_sig_der);
}

// ── tests ────────────────────────────────────────────────────────────────────

const GOLDEN = @embedFile("bridge_golden");

test "bridge digest KAT: fleet plane agrees with the shared fixture (+ order-independence)" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, GOLDEN, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    const algo = root.get("algorithm").?.object;
    try std.testing.expectEqualStrings(BRIDGE_DOMAIN, algo.get("domain").?.string);
    // The INVOICE too (not just the domain): fleet-zig verifies the wallet half
    // by re-deriving page-0's child under this invoice, so a drift here would
    // reject every live wallet half. Format: [<level>,"<protocol name>"].
    const want_invoice = try std.fmt.allocPrint(alloc, "[{d},\"{s}\"]", .{ BRIDGE_INVOICE_LEVEL, BRIDGE_PROTOCOL_NAME });
    defer alloc.free(want_invoice);
    try std.testing.expectEqualStrings(want_invoice, algo.get("walletInvoice").?.string);

    const vectors = root.get("vectors").?.array;
    try std.testing.expect(vectors.items.len >= 1);
    for (vectors.items) |item| {
        const v = item.object;
        var wallet_pub: [33]u8 = undefined;
        _ = try std.fmt.hexToBytes(&wallet_pub, v.get("walletPage0Pub").?.string);
        var fleet_pub: [33]u8 = undefined;
        _ = try std.fmt.hexToBytes(&fleet_pub, v.get("fleetRootPub").?.string);
        const nonce = v.get("nonce").?.string;

        const digest = buildBridgeDigest(wallet_pub, fleet_pub, nonce);
        var digest_hex: [64]u8 = undefined;
        const hexd = "0123456789abcdef";
        for (digest, 0..) |b, i| {
            digest_hex[i * 2] = hexd[b >> 4];
            digest_hex[i * 2 + 1] = hexd[b & 0x0f];
        }
        try std.testing.expectEqualStrings(v.get("expectedDigest").?.string, &digest_hex);
        // order-independent
        try std.testing.expectEqualSlices(u8, &digest, &buildBridgeDigest(fleet_pub, wallet_pub, nonce));
    }
}

test "bridge: sign the fleet half, verify a full symmetric round-trip, reject a wrong half" {
    const alloc = std.testing.allocator;

    var w_bytes = [_]u8{0} ** 32;
    w_bytes[31] = 7;
    const w = try PrivateKey.fromBytes(w_bytes);
    const wallet_pub = (try w.publicKey()).toCompressedSec1();
    var f_bytes = [_]u8{0} ** 32;
    f_bytes[31] = 42;
    const f = try PrivateKey.fromBytes(f_bytes);
    const fleet_pub = (try f.publicKey()).toCompressedSec1();

    const nonce = "Y3J5cHRvLW5vbmNlLTEyMzQ1Ng==";
    const digest = buildBridgeDigest(wallet_pub, fleet_pub, nonce);

    // Fleet signs its half through the real API.
    const fleet_der = try signFleetHalf(alloc, f, digest);
    defer alloc.free(fleet_der);

    // Wallet signs its half via the page-0 'anyone'-child under the bridge invoice.
    var one = [_]u8{0} ** 32;
    one[31] = 1;
    const anyone_pub = try (try PrivateKey.fromBytes(one)).publicKey();
    const invoice = try bsvz.primitives.brc43.formatInvoice(alloc, BRIDGE_INVOICE_LEVEL, BRIDGE_PROTOCOL_NAME, BRIDGE_KEY_ID);
    defer alloc.free(invoice);
    const wallet_child = try w.deriveChild(anyone_pub, invoice);
    const wallet_der = try wallet_child.signDigest(digest);

    // Both halves verify ⇒ the bridge holds.
    try std.testing.expect(try verifyBridge(alloc, wallet_pub, fleet_pub, nonce, wallet_der.asSlice(), fleet_der));

    // A wrong fleet key fails the fleet half.
    var f2 = [_]u8{0} ** 32;
    f2[31] = 99;
    const fleet2_pub = (try (try PrivateKey.fromBytes(f2)).publicKey()).toCompressedSec1();
    try std.testing.expect(!(verifyBridge(alloc, wallet_pub, fleet2_pub, nonce, wallet_der.asSlice(), fleet_der) catch false));

    // The fleet root's own sig cannot stand in for the wallet 'anyone'-child half.
    try std.testing.expect(!(verifyBridge(alloc, wallet_pub, fleet_pub, nonce, fleet_der, fleet_der) catch false));
}
