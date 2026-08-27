//! Plexus key derivation in Zig.
//!
//! A port of `@dusk-inc/plexus-sdk`'s derivation, conformant to the SDK's pinned
//! golden vector (`vectors/cross-impl-derivation.golden.json`). The SDK is the
//! oracle: where this disagrees with it, this is wrong.
//!
//! Only `plexus-kdf-v1` is implemented — BRC-42 bilateral, which is what a fleet
//! uses. `v2` (unilateral) and `v3` (domain-separated) exist in the vector and
//! are deliberately out of scope until something needs them.
//!
//! ## The one thing to keep straight
//!
//! This is NOT semantos-core's `host.deriveLeaf`, even though both call
//! `bsvz.primitives.ec.deriveChild`. Two differences make them produce different
//! keys from the same inputs:
//!
//!   deriveLeaf   invoice = protocol_hash[16] ++ index_le[8]  (24 binary bytes)
//!                counterparty = an EXTERNAL public key
//!
//!   this         invoice = "resourceId:domainFlag:childIndex" (ASCII, flag decimal)
//!                counterparty = the parent's OWN public key (self-derivation)
//!
//! Reaching for `deriveLeaf` here yields plausible keys that no other Plexus
//! implementation agrees with.

const std = @import("std");
const bsvz = @import("bsvz");

pub const ec = bsvz.primitives.ec;
pub const PrivateKey = ec.PrivateKey;
pub const PublicKey = ec.PublicKey;

pub const Error = error{
    EmptyResourceId,
    InvalidDomainFlag,
    PathMustBeginAtRoot,
    EmptyPathSegment,
    EmptyPath,
};

// ── PBKDF2 root ──────────────────────────────────────────────────────────────

/// PBKDF2 parameters, mirrored from the SDK's `tokens/algorithmVersion.ts`.
/// The vector pins all three; changing any of them forks every key universe.
pub const pbkdf2_iterations: u32 = 100_000;
pub const pbkdf2_key_length: usize = 32;
pub const Pbkdf2Prf = std.crypto.auth.hmac.sha2.HmacSha512;

/// Derive a root private key from a PBKDF2 password and salt.
///
/// Note the slot order, which is easy to invert and silently produces a
/// different, valid universe: `email` is the PASSWORD and `salt` is the SALT.
/// For a challenge-answer universe the SDK swaps them — the recovery secret
/// becomes the password and the email becomes the salt — so a caller porting
/// that path must swap here too.
pub fn deriveRootKey(email: []const u8, salt: []const u8) !PrivateKey {
    var out: [pbkdf2_key_length]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&out, email, salt, pbkdf2_iterations, Pbkdf2Prf);
    return PrivateKey.fromBytes(out);
}

// ── Invoice numbers ──────────────────────────────────────────────────────────

/// True when `flag` is inside the addressable uint32 namespace (1..=0xFFFFFFFF).
/// Zero is not a valid flag in any band.
pub fn isValidFlag(flag: u64) bool {
    return flag >= 1 and flag <= 0xFFFF_FFFF;
}

/// Build the BRC-42 invoice number: `resourceId:domainFlag:childIndex`.
///
/// `domainFlag` is DECIMAL here, and hex only in a certificate's `fields`
/// (`0x1fe02`, lowercase, unpadded). Mixing the two produces a different key
/// that still looks correct.
///
/// ⚠ `resourceId` is not escaped, and neither is it in the SDK. A `resourceId`
/// containing a colon collides into the same string as a different tuple —
/// `("a:b", 2, 0)` and a hypothetical `("a", "b:2", 0)` both render `a:b:2:0`.
/// The golden vector pins that case, so this reproduces it deliberately rather
/// than fixing it unilaterally: a port that rejected colons would diverge from
/// every shipped Plexus universe. Fix it in the SDK first, then here.
///
/// Caller owns the returned slice.
pub fn buildInvoiceNumber(
    allocator: std.mem.Allocator,
    resource_id: []const u8,
    domain_flag: u64,
    child_index: u64,
) ![]u8 {
    if (resource_id.len == 0) return Error.EmptyResourceId;
    if (!isValidFlag(domain_flag)) return Error.InvalidDomainFlag;
    return std.fmt.allocPrint(allocator, "{s}:{d}:{d}", .{ resource_id, domain_flag, child_index });
}

// ── plexus-kdf-v1 ────────────────────────────────────────────────────────────

/// Derive a child key under `plexus-kdf-v1`.
///
/// BRC-42 with the parent as its own counterparty: the ECDH secret is folded
/// against the parent's own public key, so no second party is involved and the
/// whole tree is a function of the root alone. That is what makes a fleet
/// rebuildable from the operator root, and it is also why the root can derive
/// every descendant — the property that keeps private keys off devices.
pub fn deriveChildV1(parent: PrivateKey, invoice_number: []const u8) !PrivateKey {
    const parent_pub = try parent.publicKey();
    return parent.deriveChild(parent_pub, invoice_number);
}

/// Derive one step by its parts, without materialising the invoice string.
pub fn deriveChildAt(
    allocator: std.mem.Allocator,
    parent: PrivateKey,
    resource_id: []const u8,
    domain_flag: u64,
    child_index: u64,
) !PrivateKey {
    const invoice = try buildInvoiceNumber(allocator, resource_id, domain_flag, child_index);
    defer allocator.free(invoice);
    return deriveChildV1(parent, invoice);
}

// ── Paths ────────────────────────────────────────────────────────────────────

/// Walk a derivation path from the root, e.g. `root/inbox:2:0/sub:3:2`.
///
/// The first segment must be the literal `root`; every later segment is an
/// invoice number applied in order. A bare `root` returns the root key itself.
pub fn derivePrivateKeyAtPath(
    email: []const u8,
    salt: []const u8,
    path: []const u8,
) !PrivateKey {
    if (path.len == 0) return Error.EmptyPath;

    var it = std.mem.splitScalar(u8, path, '/');
    const head = it.next() orelse return Error.EmptyPath;
    if (!std.mem.eql(u8, head, "root")) return Error.PathMustBeginAtRoot;

    var key = try deriveRootKey(email, salt);
    while (it.next()) |segment| {
        if (segment.len == 0) return Error.EmptyPathSegment;
        key = try deriveChildV1(key, segment);
    }
    return key;
}

// ── Formatting helpers ───────────────────────────────────────────────────────

/// Lowercase hex of a private key's 32 bytes, zero-padded — the SDK's `privHex`.
pub fn privHex(key: PrivateKey) [64]u8 {
    var out: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{&key.toBytes()}) catch unreachable;
    return out;
}

/// Lowercase hex of the 33-byte compressed public key — the SDK's `pubHex`.
pub fn pubHex(key: PrivateKey) ![66]u8 {
    const pk = try key.publicKey();
    var out: [66]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{&pk.toCompressedSec1()}) catch unreachable;
    return out;
}

/// Certificate-field encoding of a domain flag: `0x` + lowercase, UNPADDED hex.
/// Distinct from the decimal form the invoice number uses. Caller owns the slice.
pub fn encodeDomainFlag(allocator: std.mem.Allocator, flag: u64) ![]u8 {
    if (!isValidFlag(flag)) return Error.InvalidDomainFlag;
    return std.fmt.allocPrint(allocator, "0x{x}", .{flag});
}

// ── Child counters ───────────────────────────────────────────────────────────

/// The monotonic allocator that decides which index a child receives.
///
/// Keyed on the full tuple `(parentCertId, resourceId, domainFlag)` — not on the
/// parent alone. That distinction is load-bearing and the golden vector pins it
/// with a negative control: keyed on the parent alone, a five-call sequence
/// yields 0,1,2,3,4; keyed correctly it yields 0,1,0,0,2. Getting it wrong
/// produces keys that are individually valid and collectively wrong.
///
/// This is the same allocator `rotateContext` burns from in the SDK. Rotation is
/// not implemented here — it belongs with the fleet store in M3.
pub const ChildCounters = struct {
    map: std.StringHashMap(u64),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ChildCounters {
        return .{ .map = std.StringHashMap(u64).init(allocator), .allocator = allocator };
    }

    pub fn deinit(self: *ChildCounters) void {
        var it = self.map.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.map.deinit();
    }

    /// Consume and return the next free index at this context tuple.
    pub fn next(
        self: *ChildCounters,
        parent_cert_id: []const u8,
        resource_id: []const u8,
        domain_flag: u64,
    ) !u64 {
        const key = try std.fmt.allocPrint(
            self.allocator,
            "{s}|{s}|{d}",
            .{ parent_cert_id, resource_id, domain_flag },
        );
        const gop = try self.map.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(key);
            const issued = gop.value_ptr.*;
            gop.value_ptr.* = issued + 1;
            return issued;
        }
        gop.value_ptr.* = 1;
        return 0;
    }
};
