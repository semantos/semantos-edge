//! Certificate ids: canonical JSON, then SHA-256.
//!
//! `certId = sha256hex(canonicalJson(preimage))`. The id is what a node's
//! identity actually IS in Plexus, so this has to agree with the SDK to the
//! byte. The golden vector pins the intermediate string as well as the hash,
//! and the tests assert both — a hash-only check would pass on an encoder that
//! is accidentally right about one input and wrong in general.
//!
//! ## Why this is not a general JSON canonicalizer
//!
//! It encodes ONE shape: a certificate preimage. Five fixed top-level keys and a
//! small string→string `fields` map. That is deliberate. A general canonicalizer
//! has to answer questions this shape never asks — number formatting, nulls,
//! nested arrays, integer-like keys that JS engines reorder — and every one of
//! those is a way to silently disagree with the oracle. The SDK's own
//! canonicalizer carries an `assertReconstructibleKey` guard for exactly that
//! reason and its docs say to use a different one for wire payloads.
//!
//! Top-level keys are emitted in their known sorted order rather than sorted at
//! runtime, so the ordering is a fact of the code and not a property of a
//! comparison function. `fields` keys ARE sorted, because their set varies: a
//! root carries `{email}`, a derived node carries
//! `{resourceId, domainFlag, childIndex}`.

const std = @import("std");

pub const Error = error{
    TooManyFields,
    DuplicateFieldKey,
};

/// Certificate type strings, from the SDK's `tokens/certificateType.ts`.
pub const type_root = "plexus.identity.root";
pub const type_derived = "plexus.identity.derived";

/// One `fields` entry. Both halves are strings — nothing else occurs in a
/// preimage, and accepting anything else would invite a number-formatting
/// disagreement that has no right answer across languages.
pub const Field = struct {
    key: []const u8,
    value: []const u8,
};

pub const max_fields = 8;

/// A certificate preimage, in the shape `computeCertId` hashes.
pub const Preimage = struct {
    subject_public_key: []const u8,
    certifier_public_key: []const u8,
    type_name: []const u8,
    serial_number: []const u8,
    fields: []const Field,
};

// ── string escaping ──────────────────────────────────────────────────────────

/// Append `s` as a JSON string literal, matching `JSON.stringify`.
///
/// The escape set is exactly JS's: quote and backslash, the five short control
/// escapes, `\u00xx` (lowercase hex) for the remaining C0 controls, and
/// everything else — including DEL and all non-ASCII — passed through as raw
/// UTF-8. Notably `/` is NOT escaped, and non-ASCII is NOT `\u`-escaped; both
/// are common in hand-rolled encoders and both would produce a different hash.
fn writeJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try out.append(allocator, '"');
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            0x08 => try out.appendSlice(allocator, "\\b"),
            0x09 => try out.appendSlice(allocator, "\\t"),
            0x0A => try out.appendSlice(allocator, "\\n"),
            0x0C => try out.appendSlice(allocator, "\\f"),
            0x0D => try out.appendSlice(allocator, "\\r"),
            else => {
                if (c < 0x20) {
                    // Four lowercase hex digits, e.g. \u001f — uppercase would hash differently.
                    try out.appendSlice(allocator, "\\u00");
                    const hex = "0123456789abcdef";
                    try out.append(allocator, hex[(c >> 4) & 0xF]);
                    try out.append(allocator, hex[c & 0xF]);
                } else {
                    try out.append(allocator, c);
                }
            },
        }
    }
    try out.append(allocator, '"');
}

// ── canonical encoding ───────────────────────────────────────────────────────

/// Compare two UTF-8 strings in UTF-16 CODE-UNIT order.
///
/// The SDK sorts `fields` keys with `(a < b ? -1 : a > b ? 1 : 0)`, which in JS
/// is UTF-16 code-unit order. Sorting the same strings by UTF-8 bytes — the
/// obvious thing to do in Zig — disagrees for every pair of an astral character
/// (U+10000 and above) against one in U+E000..U+FFFF: in UTF-16 the astral char
/// leads with a surrogate in 0xD800..0xDBFF and sorts FIRST, while in UTF-8 it
/// leads with 0xF0 and sorts LAST. Different key order, different canonical
/// JSON, different certId — for two strings that are both perfectly valid keys.
///
/// Unreachable through this port's own callers, whose field keys are fixed
/// ASCII. Implemented anyway because `canonicalJson` is public here exactly as
/// it is in the SDK, and "our callers happen not to do that" is not a property
/// the type system enforces.
fn utf16LessThan(a: []const u8, b: []const u8) bool {
    var ia: usize = 0;
    var ib: usize = 0;
    var ua: [2]u16 = undefined;
    var ub: [2]u16 = undefined;
    var na: usize = 0;
    var nb: usize = 0;
    var pa: usize = 0;
    var pb: usize = 0;

    while (true) {
        if (pa == na) {
            if (ia >= a.len) break;
            const len = std.unicode.utf8ByteSequenceLength(a[ia]) catch 1;
            const cp = std.unicode.utf8Decode(a[ia..][0..len]) catch a[ia];
            ia += len;
            na = utf16Units(cp, &ua);
            pa = 0;
        }
        if (pb == nb) {
            if (ib >= b.len) return false; // b exhausted first: a > b
            const len = std.unicode.utf8ByteSequenceLength(b[ib]) catch 1;
            const cp = std.unicode.utf8Decode(b[ib..][0..len]) catch b[ib];
            ib += len;
            nb = utf16Units(cp, &ub);
            pb = 0;
        }
        if (ua[pa] != ub[pb]) return ua[pa] < ub[pb];
        pa += 1;
        pb += 1;
    }
    // a exhausted; a < b iff b still has units left.
    return pb != nb or ib < b.len;
}

/// Encode one code point as 1 or 2 UTF-16 code units; returns how many.
fn utf16Units(cp: u21, out: *[2]u16) usize {
    if (cp < 0x10000) {
        out[0] = @intCast(cp);
        return 1;
    }
    const v = cp - 0x10000;
    out[0] = @intCast(0xD800 + (v >> 10));
    out[1] = @intCast(0xDC00 + (v & 0x3FF));
    return 2;
}

fn lessThanKey(_: void, a: Field, b: Field) bool {
    return utf16LessThan(a.key, b.key);
}

/// Encode a preimage to its canonical JSON. Caller owns the returned slice.
///
/// `fields` is sorted here, so callers may pass entries in any order — the SDK's
/// vector includes a deliberately scrambled case proving the id does not depend
/// on input order.
pub fn canonicalJson(allocator: std.mem.Allocator, p: Preimage) ![]u8 {
    if (p.fields.len > max_fields) return Error.TooManyFields;

    var sorted: [max_fields]Field = undefined;
    @memcpy(sorted[0..p.fields.len], p.fields);
    const view = sorted[0..p.fields.len];
    std.mem.sort(Field, view, {}, lessThanKey);

    // Duplicate keys cannot round-trip: JS would keep the last write and the
    // sort would not reveal which. Refuse rather than pick.
    if (view.len > 1) {
        for (view[1..], 0..) |f, i| {
            if (std.mem.eql(u8, f.key, view[i].key)) return Error.DuplicateFieldKey;
        }
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    // Sorted top-level order: certifierPublicKey, fields, serialNumber,
    // subjectPublicKey, type.
    try out.appendSlice(allocator, "{\"certifierPublicKey\":");
    try writeJsonString(&out, allocator, p.certifier_public_key);
    try out.appendSlice(allocator, ",\"fields\":{");
    for (view, 0..) |f, i| {
        if (i != 0) try out.append(allocator, ',');
        try writeJsonString(&out, allocator, f.key);
        try out.append(allocator, ':');
        try writeJsonString(&out, allocator, f.value);
    }
    try out.appendSlice(allocator, "},\"serialNumber\":");
    try writeJsonString(&out, allocator, p.serial_number);
    try out.appendSlice(allocator, ",\"subjectPublicKey\":");
    try writeJsonString(&out, allocator, p.subject_public_key);
    try out.appendSlice(allocator, ",\"type\":");
    try writeJsonString(&out, allocator, p.type_name);
    try out.append(allocator, '}');

    return out.toOwnedSlice(allocator);
}

/// Lowercase hex SHA-256 of a byte slice.
pub fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    var out: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{&digest}) catch unreachable;
    return out;
}

/// `certId = sha256hex(canonicalJson(preimage))`.
pub fn computeCertId(allocator: std.mem.Allocator, p: Preimage) ![64]u8 {
    const json = try canonicalJson(allocator, p);
    defer allocator.free(json);
    return sha256Hex(json);
}
