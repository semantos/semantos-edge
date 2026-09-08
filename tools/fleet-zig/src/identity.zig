//! Certificate preimages: turning a key and its position into an identity.
//!
//! Composes `derive` (keys) and `certid` (canonical JSON) into the two shapes
//! Plexus actually builds. Kept separate so `certid` stays a pure encoder and
//! `derive` stays pure crypto — neither needs to know what a certificate is.
//!
//! There are exactly two shapes and no third:
//!
//!   root     self-certified. subject == certifier == the root's own pubkey.
//!            serialNumber = sha256hex("root:" + email). fields = {email}.
//!
//!   derived  certifier is the IMMEDIATE PARENT's pubkey, not the root's. At
//!            depth 2 the certifier is the depth-1 child. Getting that wrong is
//!            silent: the id simply forks, and every descendant forks with it.
//!            serialNumber = sha256hex("child:" + parentPubHex + ":" + invoice).
//!            fields = {resourceId, domainFlag as 0x-hex, childIndex decimal}.
//!
//! Note the DECIMAL/HEX split, which is the easiest thing here to get wrong:
//! the invoice number carries the domain flag in DECIMAL, while `fields.domainFlag`
//! carries the same flag in unpadded lowercase HEX with a `0x` prefix. Both
//! appear in the same certificate.
//!
//! `childIndex` is an INPUT, never a computation. It comes from the allocator
//! keyed on `(parentCertId, resourceId, domainFlag)` — see `derive.ChildCounters`.

const std = @import("std");
const derive = @import("derive");
const certid = @import("certid");

pub const Preimage = certid.Preimage;
pub const Field = certid.Field;

/// The certificate id of a root identity, and the pieces it was built from.
pub const Root = struct {
    public_key_hex: [66]u8,
    serial_number: [64]u8,
    cert_id: [64]u8,
};

/// Build a root identity's certificate from its universe.
pub fn rootIdentity(allocator: std.mem.Allocator, email: []const u8, salt: []const u8) !Root {
    const key = try derive.deriveRootKey(email, salt);
    const pub_hex = try derive.pubHex(key);

    // The salt never enters the certificate — only the email does. Two universes
    // with the same email therefore share a serialNumber and differ only by the
    // public key, which is what actually separates them.
    const serial_input = try std.fmt.allocPrint(allocator, "root:{s}", .{email});
    defer allocator.free(serial_input);
    const serial = certid.sha256Hex(serial_input);

    const fields = [_]Field{.{ .key = "email", .value = email }};
    const id = try certid.computeCertId(allocator, .{
        .subject_public_key = &pub_hex,
        .certifier_public_key = &pub_hex,
        .type_name = certid.type_root,
        .serial_number = &serial,
        .fields = &fields,
    });
    return .{ .public_key_hex = pub_hex, .serial_number = serial, .cert_id = id };
}

/// A derived child's certificate, plus what it took to get there.
pub const Child = struct {
    public_key_hex: [66]u8,
    derivation_path: []u8,
    invoice_number: []u8,
    serial_number: [64]u8,
    cert_id: [64]u8,

    pub fn deinit(self: Child, allocator: std.mem.Allocator) void {
        allocator.free(self.derivation_path);
        allocator.free(self.invoice_number);
    }
};

/// Derive a child under `parent` and build its certificate.
///
/// `parent_path` is the parent's derivation path, so the child's can be built
/// by appending. `child_index` is supplied by the caller's allocator.
pub fn deriveChildIdentity(
    allocator: std.mem.Allocator,
    email: []const u8,
    salt: []const u8,
    parent_path: []const u8,
    resource_id: []const u8,
    domain_flag: u64,
    child_index: u64,
) !Child {
    const parent = try derive.derivePrivateKeyAtPath(email, salt, parent_path);
    const parent_pub = try derive.pubHex(parent);

    const invoice = try derive.buildInvoiceNumber(allocator, resource_id, domain_flag, child_index);
    errdefer allocator.free(invoice);

    const child = try derive.deriveChildV1(parent, invoice);
    const child_pub = try derive.pubHex(child);

    const serial_input = try std.fmt.allocPrint(
        allocator,
        "child:{s}:{s}",
        .{ &parent_pub, invoice },
    );
    defer allocator.free(serial_input);
    const serial = certid.sha256Hex(serial_input);

    const flag_hex = try derive.encodeDomainFlag(allocator, domain_flag);
    defer allocator.free(flag_hex);
    const index_dec = try std.fmt.allocPrint(allocator, "{d}", .{child_index});
    defer allocator.free(index_dec);

    const fields = [_]Field{
        .{ .key = "resourceId", .value = resource_id },
        .{ .key = "domainFlag", .value = flag_hex },
        .{ .key = "childIndex", .value = index_dec },
    };
    const id = try certid.computeCertId(allocator, .{
        .subject_public_key = &child_pub,
        .certifier_public_key = &parent_pub,
        .type_name = certid.type_derived,
        .serial_number = &serial,
        .fields = &fields,
    });

    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ parent_path, invoice });
    errdefer allocator.free(path);

    return .{
        .public_key_hex = child_pub,
        .derivation_path = path,
        .invoice_number = invoice,
        .serial_number = serial,
        .cert_id = id,
    };
}
