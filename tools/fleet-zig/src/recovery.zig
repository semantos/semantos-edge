//! Recovery recipes: what it takes to rebuild a fleet without its server.
//!
//! A recipe carries derivation paths and per-slot high-water marks. It carries
//! no key material and could not usefully be made to — every key in the fleet is
//! a deterministic function of the operator root, which stays out of the recipe
//! by construction. That is the whole trick: losing the provisioning database
//! costs an afternoon rather than a fleet.
//!
//! ## The counter is not trusted
//!
//! `currentIndex` arrives from a recovery service that does not authenticate its
//! callers. A value BELOW the paths replayed beside it rewinds the allocator
//! underneath live certificates — and because a certId is deterministic in
//! `(parent, resourceId, domainFlag, childIndex)`, the next derivations
//! reproduce a live holder's certId AND public key byte for byte. That is not a
//! malformed-payload hypothetical; it is the threat model the service is
//! documented to have.
//!
//! So every counter is floored against the payload's own paths, and a triple the
//! paths prove but the domains never mention gets a counter anyway — a rewind by
//! omission is the same rewind. A counter ABOVE the paths is preserved untouched,
//! because that is exactly what a rotation's burn leaves behind and dragging it
//! down would un-retire a deliberately retired index.
//!
//! ## Paths are verified, not believed
//!
//! Each path declares the certId it should arrive at. Import re-derives the
//! whole ancestry and refuses a path that does not reproduce it, so a recipe
//! cannot inject a node the operator root would never have derived.
//!
//! ## What a recipe does NOT carry
//!
//! Labels. They are metadata, not identity — a rebuilt fleet knows a unit is
//! `member:2` under a given zone, and does not know it was called
//! "cold-chain-01". Re-attaching human names is the operator's job and wants a
//! separate, non-cryptographic backup.

const std = @import("std");
const derive = @import("derive");
const identity = @import("identity");
const store_mod = @import("store");
const Store = store_mod.Store;
const NodeView = store_mod.NodeView;

pub const Error = error{
    PathDoesNotDerive,
    EmptyPath,
    MissingField,
    BadPayload,
};

pub const algorithm_version = "plexus-kdf-v1";
pub const schema_version = "v1";

/// One step of an ancestry: which slot, and which index within it.
pub const Step = struct {
    tenant_type: u64 = 0,
    child_index: u64,
    resource_id: []const u8,
    domain_flag: u64,
};

/// A node's full ancestry from the root.
pub const TenantPath = struct {
    cert_id: []const u8,
    resource_id: []const u8,
    parent_cert_id: []const u8,
    steps: []const Step,
};

/// A per-slot high-water mark.
pub const FunctionalDomain = struct {
    cert_id: []const u8,
    resource_id: []const u8,
    parent_cert_id: []const u8,
    domain_flag: u64,
    current_index: u64,
};

fn tripleKey(
    allocator: std.mem.Allocator,
    parent: []const u8,
    resource: []const u8,
    flag: u64,
) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}\x00{s}\x00{d}", .{ parent, resource, flag });
}

// ── export ───────────────────────────────────────────────────────────────────

/// Serialize a fleet's recipe as JSON the SDK will accept.
///
/// Key order is irrelevant here — unlike a certificate preimage, a recipe is
/// never hashed, so this is ordinary JSON rather than a canonical encoding.
/// Caller owns the returned slice.
pub fn exportRecipe(
    allocator: std.mem.Allocator,
    store: *Store,
    root_cert_id: []const u8,
    email: []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const w = out.writer(allocator);

    try w.print(
        "{{\"schemaVersion\":\"{s}\",\"certId\":\"{s}\",\"email\":\"",
        .{ schema_version, root_cert_id },
    );
    try writeJsonEscaped(w, email);
    try w.writeAll("\",\"resourceRegistrations\":[],\"edges\":[],\"algorithmVersions\":[],");

    // tenantPaths: every non-root node, with its ancestry rebuilt by walking
    // parents. A node whose chain does not reach the root is skipped rather
    // than emitted with a truncated path that would silently derive elsewhere.
    try w.writeAll("\"tenantPaths\":[");
    var first = true;
    var ceilings = std.StringHashMap(u64).init(allocator);
    defer {
        var it = ceilings.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        ceilings.deinit();
    }

    var nit = store.nodes.valueIterator();
    while (nit.next()) |n| {
        const parent = n.parent_cert_id orelse continue;

        var chain: std.ArrayList(NodeView) = .empty;
        defer chain.deinit(allocator);
        var cur = n.*;
        var reached_root = false;
        while (true) {
            try chain.append(allocator, .{
                .resource_id = cur.resource_id,
                .domain_flag = cur.domain_flag,
                .child_index = cur.child_index,
            });
            const p = cur.parent_cert_id orelse break;
            if (std.mem.eql(u8, p, root_cert_id)) {
                reached_root = true;
                break;
            }
            cur = store.getNode(p) orelse break;
        }
        if (!reached_root) continue;
        std.mem.reverse(NodeView, chain.items);

        if (!first) try w.writeByte(',');
        first = false;
        try w.print(
            "{{\"certId\":\"{s}\",\"resourceId\":\"{s}\",\"parentCertId\":\"{s}\",\"steps\":[",
            .{ n.cert_id, n.resource_id, parent },
        );
        for (chain.items, 0..) |s, i| {
            if (i != 0) try w.writeByte(',');
            try w.print(
                "{{\"tenantType\":0,\"childIndex\":{d},\"resourceId\":\"{s}\",\"domainFlag\":{d}}}",
                .{ s.child_index, s.resource_id, s.domain_flag },
            );
        }
        try w.writeAll("]}");

        // The mark for this node's own slot, taken from the store rather than
        // inferred from the node — the store knows about burns the nodes cannot.
        const key = try tripleKey(allocator, parent, n.resource_id, n.domain_flag);
        const gop = try ceilings.getOrPut(key);
        if (gop.found_existing) {
            allocator.free(key);
        } else {
            gop.value_ptr.* = try store.highWaterMark(parent, n.resource_id, n.domain_flag);
        }
    }
    try w.writeAll("],\"functionalDomains\":[");

    var first_d = true;
    var cit = ceilings.iterator();
    while (cit.next()) |e| {
        var parts = std.mem.splitScalar(u8, e.key_ptr.*, 0);
        const parent = parts.next().?;
        const resource = parts.next().?;
        const flag = try std.fmt.parseInt(u64, parts.next().?, 10);
        if (!first_d) try w.writeByte(',');
        first_d = false;
        try w.print(
            "{{\"certId\":\"{s}\",\"resourceId\":\"{s}\",\"parentCertId\":\"{s}\"," ++
                "\"domainFlag\":{d},\"currentIndex\":{d},\"algorithmVersion\":\"{s}\"}}",
            .{ parent, resource, parent, flag, e.value_ptr.*, algorithm_version },
        );
    }
    try w.writeAll("]}");
    return out.toOwnedSlice(allocator);
}

fn writeJsonEscaped(w: anytype, s: []const u8) !void {
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        else => {
            if (c < 0x20) try w.print("\\u{x:0>4}", .{c}) else try w.writeByte(c);
        },
    };
}

// ── import ───────────────────────────────────────────────────────────────────

pub const ImportResult = struct {
    /// The root the recipe describes.
    root_cert_id: []const u8,
    /// How many nodes were rebuilt.
    nodes: usize,
    /// How many counters were raised above what the payload declared, because
    /// the paths proved a higher index. Non-zero means the payload would have
    /// rewound the allocator.
    floored: usize,
};

/// Rebuild a store from a recipe, deriving under `(email, salt)`.
///
/// Refuses any path that does not re-derive to its declared certId, and floors
/// every counter against the paths. See the module docs for why both matter.
pub fn importRecipe(
    allocator: std.mem.Allocator,
    store: *Store,
    email: []const u8,
    salt: []const u8,
    payload_json: []const u8,
) !ImportResult {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    const o = parsed.value.object;

    const root_cert_id = (o.get("certId") orelse return Error.MissingField).string;
    const paths = (o.get("tenantPaths") orelse return Error.MissingField).array.items;

    // Floors proven by the paths themselves.
    var floors = std.StringHashMap(u64).init(allocator);
    defer {
        var it = floors.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        floors.deinit();
    }

    var nodes: usize = 0;
    for (paths) |p| {
        const po = p.object;
        const declared = (po.get("certId") orelse return Error.MissingField).string;
        const steps = (po.get("steps") orelse return Error.MissingField).array.items;
        if (steps.len == 0) return Error.EmptyPath;

        // Re-derive the whole ancestry. A path that does not reproduce its own
        // certId is refused, so a recipe cannot introduce a node the operator
        // root would never have derived.
        var path_buf: std.ArrayList(u8) = .empty;
        defer path_buf.deinit(allocator);
        try path_buf.appendSlice(allocator, "root");

        var parent_cert = try allocator.dupe(u8, root_cert_id);
        defer allocator.free(parent_cert);

        var last_resource: []const u8 = "";
        var last_flag: u64 = 0;
        var last_index: u64 = 0;

        for (steps) |s| {
            const so = s.object;
            const resource = (so.get("resourceId") orelse return Error.MissingField).string;
            const flag: u64 = @intCast((so.get("domainFlag") orelse return Error.MissingField).integer);
            const index: u64 = @intCast((so.get("childIndex") orelse return Error.MissingField).integer);

            const child = try identity.deriveChildIdentity(
                allocator,
                email,
                salt,
                path_buf.items,
                resource,
                flag,
                index,
            );
            defer child.deinit(allocator);

            path_buf.clearRetainingCapacity();
            try path_buf.appendSlice(allocator, child.derivation_path);

            allocator.free(parent_cert);
            parent_cert = try allocator.dupe(u8, &child.cert_id);

            last_resource = resource;
            last_flag = flag;
            last_index = index;
        }

        if (!std.mem.eql(u8, parent_cert, declared)) return Error.PathDoesNotDerive;

        // The parent of the LAST step is the node's parent; walk one back.
        const parent_of_last = (po.get("parentCertId") orelse return Error.MissingField).string;
        store.putNode(.{
            .cert_id = declared,
            .parent_cert_id = parent_of_last,
            .resource_id = last_resource,
            .domain_flag = last_flag,
            .child_index = last_index,
            .label = "",
        }) catch |err| switch (err) {
            error.DuplicateNode => {},
            else => return err,
        };
        nodes += 1;

        const key = try tripleKey(allocator, parent_of_last, last_resource, last_flag);
        const gop = try floors.getOrPut(key);
        const floor = last_index + 1;
        if (gop.found_existing) {
            allocator.free(key);
            if (floor > gop.value_ptr.*) gop.value_ptr.* = floor;
        } else {
            gop.value_ptr.* = floor;
        }
    }

    // Declared counters, reduced to the MAXIMUM per triple. Rows arrive in
    // insertion order, which bears no relation to index magnitude, so restoring
    // them one by one would refuse a lower row arriving after a higher one.
    var declared = std.StringHashMap(u64).init(allocator);
    defer {
        var it = declared.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        declared.deinit();
    }
    if (o.get("functionalDomains")) |fds| {
        for (fds.array.items) |d| {
            const dobj = d.object;
            const parent = (dobj.get("parentCertId") orelse return Error.MissingField).string;
            const resource = (dobj.get("resourceId") orelse return Error.MissingField).string;
            const flag: u64 = @intCast((dobj.get("domainFlag") orelse return Error.MissingField).integer);
            const idx: u64 = @intCast((dobj.get("currentIndex") orelse return Error.MissingField).integer);
            const key = try tripleKey(allocator, parent, resource, flag);
            const gop = try declared.getOrPut(key);
            if (gop.found_existing) {
                allocator.free(key);
                if (idx > gop.value_ptr.*) gop.value_ptr.* = idx;
            } else {
                gop.value_ptr.* = idx;
            }
        }
    }

    // Restore max(declared, floor) for every triple either side knows about.
    var floored: usize = 0;
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var dit = declared.iterator();
    while (dit.next()) |e| {
        const floor = floors.get(e.key_ptr.*) orelse 0;
        const value = @max(e.value_ptr.*, floor);
        if (floor > e.value_ptr.*) floored += 1;
        try restoreByKey(store, e.key_ptr.*, value);
        try seen.put(e.key_ptr.*, {});
    }
    var fit = floors.iterator();
    while (fit.next()) |e| {
        if (seen.contains(e.key_ptr.*)) continue;
        // A triple the paths prove that no functionalDomains row mentioned.
        // Skipping it is the same rewind, arrived at by omission.
        floored += 1;
        try restoreByKey(store, e.key_ptr.*, e.value_ptr.*);
    }

    return .{ .root_cert_id = root_cert_id, .nodes = nodes, .floored = floored };
}

fn restoreByKey(store: *Store, key: []const u8, value: u64) !void {
    var parts = std.mem.splitScalar(u8, key, 0);
    const parent = parts.next() orelse return Error.BadPayload;
    const resource = parts.next() orelse return Error.BadPayload;
    const flag = try std.fmt.parseInt(u64, parts.next() orelse return Error.BadPayload, 10);
    store.restoreCounter(parent, resource, flag, value) catch |err| switch (err) {
        // Already at or above this value: nothing to restore, and refusing here
        // would make importing twice an error rather than a no-op.
        error.CounterWouldRewind => {},
        else => return err,
    };
}
