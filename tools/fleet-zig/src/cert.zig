//! Capability certificates: the 66 bytes a device installs, and the cell that
//! carries them.
//!
//! This is the seam. Everything above it is Plexus; everything below it is the
//! mesh's own wire format, unchanged. A device receives a 1 KB cell, verifies
//! one signature against the operator public key it was flashed with, and
//! installs a 66-byte payload into `cm_cap_table_t`. No Plexus concept crosses.
//!
//! The layout is not re-declared here. Offsets come from
//! `components/cell-mesh-zig/src/cell_wire.zig` — the same file the firmware
//! builds against — so a change to the wire format cannot leave this behind.
//! The 66-byte payload offsets are checked against `cell_capability.h` by a test.
//!
//! ## On "byte-identical"
//!
//! The payload and the cell are byte-identical to what the TypeScript plane
//! produces, and tests assert exactly that against a generated vector.
//!
//! The SIGNATURE is not, and cannot be. Both sides are deterministic and neither
//! uses randomness, but they derive the ECDSA nonce differently: @bsv/sdk runs
//! its own HMAC-DRBG, bsvz delegates to Zig's `std.crypto.sign.ecdsa`. Same key,
//! same digest, two different valid signatures. Measured, not assumed.
//!
//! That is not a defect, because the nonce is not part of any contract. What IS
//! contractual is that the signature verifies against the operator key and is
//! low-S — and low-S must be applied deliberately, because bsvz's raw output is
//! not: its `s` comes back above half-n roughly half the time, while @bsv/sdk
//! forces low-S by default. A high-S signature still verifies through mbedTLS on
//! the device, so this would not have failed loudly; it would simply have made
//! the two planes disagree about what they emit.

const std = @import("std");
const bsvz = @import("bsvz");
const wire = @import("cell_wire");
const derive = @import("derive");

pub const Error = error{
    BadPublicKeyLength,
    BadChannelIdLength,
    PayloadTooLarge,
};

pub const cell_size = 1024;
pub const payload_size = 768;

/// The 66-byte `cellmesh.capability.v0` payload, at the offsets
/// `cm_cap_install` reads. Mirrored from cell_capability.h; a test parses that
/// header and checks these against it.
pub const payload_bytes = 66;
pub const off_edge_pubkey = 0;
pub const off_channel_id = 33;
pub const off_expiry_ms = 49;
pub const off_route_type = 57;
pub const off_valid_from_ms = 58;
pub const route_fwd_v1: u8 = 0x01;

/// `UINT64_MAX` — what the firmware reads as "no expiry", until it has an RTC.
pub const no_expiry: u64 = std.math.maxInt(u64);

/// Build the 66-byte capability payload.
pub fn buildPayload(
    edge_pubkey: []const u8,
    channel_id: []const u8,
    expiry_ms: u64,
    valid_from_ms: u64,
) ![payload_bytes]u8 {
    if (edge_pubkey.len != 33) return Error.BadPublicKeyLength;
    if (channel_id.len != 16) return Error.BadChannelIdLength;

    var p: [payload_bytes]u8 = [_]u8{0} ** payload_bytes;
    @memcpy(p[off_edge_pubkey..][0..33], edge_pubkey);
    @memcpy(p[off_channel_id..][0..16], channel_id);
    std.mem.writeInt(u64, p[off_expiry_ms..][0..8], expiry_ms, .little);
    p[off_route_type] = route_fwd_v1;
    std.mem.writeInt(u64, p[off_valid_from_ms..][0..8], valid_from_ms, .little);
    return p;
}

/// SHA-256 of the payload — the BRC-108 `cert_hash` every commitment carries.
pub fn certHash(payload: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &out, .{});
    return out;
}

/// A cell type hash is SHA-256 of the type name.
pub fn typeHash(name: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(name, &out, .{});
    return out;
}

pub const capability_v0_type_name = "cellmesh.capability.v0";

/// Mint a 1 KB cell carrying `payload`.
///
/// Offsets and magic come from `cell_wire`; only the fields this cell kind uses
/// are written here. `domain_payload_root` is SHA-256 over the whole 768-byte
/// payload REGION — the zero padding included, not just the used prefix.
pub fn mintCell(
    type_hash: [32]u8,
    payload: []const u8,
    owner_id: []const u8,
    timestamp_ms: u64,
) ![cell_size]u8 {
    if (payload.len > payload_size) return Error.PayloadTooLarge;

    var cell: [cell_size]u8 = [_]u8{0} ** cell_size;
    wire.initBytes(cell[0..]);
    wire.writeU32(cell[wire.Off.linearity..], @intFromEnum(wire.Linearity.affine));
    wire.setVersion(cell[0..], wire.version);
    @memcpy(cell[wire.Off.type_hash..][0..32], &type_hash);
    const owner_len = @min(owner_id.len, 16);
    @memcpy(cell[wire.Off.owner_id..][0..owner_len], owner_id[0..owner_len]);
    wire.writeU64(cell[wire.Off.timestamp..], timestamp_ms);
    @memcpy(cell[wire.Off.payload..][0..payload.len], payload);
    wire.writeU32(cell[wire.Off.payload_total..], @intCast(payload.len));

    var root: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        cell[wire.Off.payload..][0..payload_size],
        &root,
        .{},
    );
    @memcpy(cell[wire.Off.domain_payload_root..][0..32], &root);
    return cell;
}

// ── signing ──────────────────────────────────────────────────────────────────

const curve_n = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};
const curve_half_n = [_]u8{
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
};

fn greaterThan(a: [32]u8, b: [32]u8) bool {
    return std.mem.order(u8, &a, &b) == .gt;
}

/// s = n - s, big-endian, for low-S normalisation.
fn negateS(s: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    var borrow: u16 = 0;
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        const d = @as(i32, curve_n[i]) - @as(i32, s[i]) - @as(i32, @intCast(borrow));
        if (d < 0) {
            out[i] = @intCast(d + 256);
            borrow = 1;
        } else {
            out[i] = @intCast(d);
            borrow = 0;
        }
    }
    return out;
}

/// Sign a cell as the operator: raw `r||s`, 32+32 big-endian, low-S.
///
/// The device computes `cm_sig_hash_cell` — a single SHA-256 over the 1024
/// canonical bytes — and verifies against that. Single, not double: reaching for
/// bsvz's `signHash256` here would produce a signature over the wrong digest
/// that still looks structurally correct.
///
/// Low-S is applied explicitly. bsvz returns whatever `std.crypto` produced,
/// which is above half-n about half the time, whereas @bsv/sdk forces low-S. A
/// high-S signature still verifies on the device, so the divergence would have
/// been silent.
pub fn signCell(key: derive.PrivateKey, cell: []const u8) ![64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cell, &digest, .{});

    const der = try key.signDigest(digest);
    const parsed = try bsvz.primitives.ecdsa.Signature.fromDer(der.asSlice());

    var out: [64]u8 = undefined;
    @memcpy(out[0..32], &parsed.r);
    const s = if (greaterThan(parsed.s, curve_half_n)) negateS(parsed.s) else parsed.s;
    @memcpy(out[32..64], &s);
    return out;
}

/// Verify a raw `r||s` signature over a cell against a compressed public key.
///
/// The device's side of the same operation, so a cert can be checked before it
/// is ever put on a radio.
pub fn verifyCell(pubkey_compressed: []const u8, cell: []const u8, sig: [64]u8) !bool {
    if (pubkey_compressed.len != 33) return Error.BadPublicKeyLength;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cell, &digest, .{});

    var s = bsvz.primitives.ecdsa.Signature{ .r = undefined, .s = undefined };
    @memcpy(&s.r, sig[0..32]);
    @memcpy(&s.s, sig[32..64]);
    var pk: [33]u8 = undefined;
    @memcpy(&pk, pubkey_compressed);
    return s.verifyDigest(digest, .{ .bytes = pk });
}

/// The 16-byte channel a unit answers on, derived from its certificate id.
///
/// Reproducible from the identity rather than allocated, so a rebuilt fleet does
/// not re-provision units onto channels they do not answer on.
pub fn channelIdFor(cert_id_hex: []const u8) ![16]u8 {
    var out: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, cert_id_hex[0..32]);
    return out;
}
