//! The fleet store: who exists, and which index comes next.
//!
//! Two things live here, and only one of them is subtle.
//!
//! The nodes are a plain record of what has been provisioned. The counters are
//! the part that has to be right: **one allocator per
//! `(parentCertId, resourceId, domainFlag)`**, which both allocation and burning
//! draw from. Keying it on the parent alone is the failure the SDK's vector
//! carries a negative control for, and it produces indices that are individually
//! valid and collectively wrong.
//!
//! ## One counter, not two
//!
//! The SDK has `child_counters.next_index` AND `derivation_state.current_index`.
//! That is not a design — it is a repair. The two tables were written by
//! different code paths and nothing reconciled them, so `rotateContext` advanced
//! a counter that `deriveChild` never read and rotation changed no key at all.
//! The fix made one the allocator and the other its mirror.
//!
//! A store written from scratch should reproduce the SDK's *behaviour*, not the
//! shape of its bug. So there is one counter here, and `currentIndex` is a read
//! of it. The rotation vector is generated from the SDK's real store, so the
//! equivalence is checked rather than assumed.
//!
//! ## Durability
//!
//! Persistence is an append-only log of what happened. Two properties fall out
//! of that rather than being enforced by a check: an allocation cannot be
//! un-issued, and replaying the log twice cannot rewind a counter — replay takes
//! the maximum, so it is idempotent and order-independent. A process killed
//! mid-write leaves a torn final line, which replay detects and drops.

const std = @import("std");

pub const Error = error{
    CounterWouldRewind,
    UnknownNode,
    DuplicateNode,
    CorruptRecord,
};

/// One provisioned identity, as the control plane records it.
pub const Node = struct {
    cert_id: []const u8,
    parent_cert_id: ?[]const u8,
    resource_id: []const u8,
    domain_flag: u64,
    child_index: u64,
    label: []const u8,
};

fn contextKey(
    allocator: std.mem.Allocator,
    parent_cert_id: []const u8,
    resource_id: []const u8,
    domain_flag: u64,
) ![]u8 {
    // NUL-separated: neither a cert id nor a resource id can contain one, so
    // two distinct contexts cannot be made to collide on a single counter.
    return std.fmt.allocPrint(
        allocator,
        "{s}\x00{s}\x00{d}",
        .{ parent_cert_id, resource_id, domain_flag },
    );
}

pub const Store = struct {
    allocator: std.mem.Allocator,
    /// context key -> next free index. The single allocator.
    counters: std.StringHashMap(u64),
    /// certId -> node.
    nodes: std.StringHashMap(Node),
    /// Append-only log, or null for an in-memory store.
    log: ?std.fs.File,

    pub fn initMemory(allocator: std.mem.Allocator) Store {
        return .{
            .allocator = allocator,
            .counters = std.StringHashMap(u64).init(allocator),
            .nodes = std.StringHashMap(Node).init(allocator),
            .log = null,
        };
    }

    /// Open a persistent store, replaying any existing log.
    pub fn open(allocator: std.mem.Allocator, path: []const u8) !Store {
        var self = Store.initMemory(allocator);
        errdefer self.deinit();

        const file = std.fs.cwd().createFile(path, .{
            .read = true,
            .truncate = false,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => try std.fs.cwd().openFile(path, .{ .mode = .read_write }),
            else => return err,
        };
        errdefer file.close();

        const contents = try file.readToEndAlloc(allocator, 64 * 1024 * 1024);
        defer allocator.free(contents);
        const good_bytes = try self.replay(contents);

        // A torn final line is a process that died mid-append. Truncate to the
        // last complete record so the next append starts from a clean boundary
        // rather than extending a fragment into a plausible-looking record.
        if (good_bytes != contents.len) {
            try file.setEndPos(good_bytes);
        }
        try file.seekFromEnd(0);
        self.log = file;
        return self;
    }

    pub fn deinit(self: *Store) void {
        var ck = self.counters.keyIterator();
        while (ck.next()) |k| self.allocator.free(k.*);
        self.counters.deinit();

        var nv = self.nodes.valueIterator();
        while (nv.next()) |n| self.freeNode(n.*);
        self.nodes.deinit();

        if (self.log) |f| f.close();
        self.log = null;
    }

    fn freeNode(self: *Store, n: Node) void {
        self.allocator.free(n.cert_id);
        if (n.parent_cert_id) |p| self.allocator.free(p);
        self.allocator.free(n.resource_id);
        self.allocator.free(n.label);
    }

    // ── counters ─────────────────────────────────────────────────────────────

    /// Raise a context's counter to `value`, never lowering it.
    fn raise(
        self: *Store,
        parent_cert_id: []const u8,
        resource_id: []const u8,
        domain_flag: u64,
        value: u64,
    ) !void {
        const key = try contextKey(self.allocator, parent_cert_id, resource_id, domain_flag);
        const gop = try self.counters.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(key);
            if (value > gop.value_ptr.*) gop.value_ptr.* = value;
        } else {
            gop.value_ptr.* = value;
        }
    }

    /// The next index this context will issue — its high-water mark.
    ///
    /// Equivalent to the SDK's `getDerivationState().currentIndex`, and the same
    /// number a recovery export carries as `functionalDomains[].currentIndex`.
    pub fn highWaterMark(
        self: *Store,
        parent_cert_id: []const u8,
        resource_id: []const u8,
        domain_flag: u64,
    ) !u64 {
        const key = try contextKey(self.allocator, parent_cert_id, resource_id, domain_flag);
        defer self.allocator.free(key);
        return self.counters.get(key) orelse 0;
    }

    /// Consume the next free index and issue it.
    pub fn allocateIndex(
        self: *Store,
        parent_cert_id: []const u8,
        resource_id: []const u8,
        domain_flag: u64,
    ) !u64 {
        const issued = try self.highWaterMark(parent_cert_id, resource_id, domain_flag);
        try self.raise(parent_cert_id, resource_id, domain_flag, issued + 1);
        try self.append("alloc", parent_cert_id, resource_id, domain_flag, issued + 1);
        return issued;
    }

    /// Burn the next free index without issuing it, and return the new mark.
    ///
    /// This is what makes a rotation bite. The index is consumed from the same
    /// allocator, so the next holder lands strictly past anything the outgoing
    /// one could have held, and the burned index is never handed to anyone.
    /// Burning an untouched context still burns index 0, so "rotated" is never
    /// mistakable for "untouched".
    pub fn burnSlot(
        self: *Store,
        parent_cert_id: []const u8,
        resource_id: []const u8,
        domain_flag: u64,
    ) !u64 {
        const mark = (try self.highWaterMark(parent_cert_id, resource_id, domain_flag)) + 1;
        try self.raise(parent_cert_id, resource_id, domain_flag, mark);
        try self.append("burn", parent_cert_id, resource_id, domain_flag, mark);
        return mark;
    }

    /// Restore a high-water mark, as recovery does. Refuses to rewind.
    pub fn restoreCounter(
        self: *Store,
        parent_cert_id: []const u8,
        resource_id: []const u8,
        domain_flag: u64,
        next_index: u64,
    ) !void {
        const current = try self.highWaterMark(parent_cert_id, resource_id, domain_flag);
        if (next_index < current) return Error.CounterWouldRewind;
        try self.raise(parent_cert_id, resource_id, domain_flag, next_index);
        try self.append("restore", parent_cert_id, resource_id, domain_flag, next_index);
    }

    // ── nodes ────────────────────────────────────────────────────────────────

    pub fn putNode(self: *Store, node: Node) !void {
        if (self.nodes.contains(node.cert_id)) return Error.DuplicateNode;
        const owned = Node{
            .cert_id = try self.allocator.dupe(u8, node.cert_id),
            .parent_cert_id = if (node.parent_cert_id) |p| try self.allocator.dupe(u8, p) else null,
            .resource_id = try self.allocator.dupe(u8, node.resource_id),
            .domain_flag = node.domain_flag,
            .child_index = node.child_index,
            .label = try self.allocator.dupe(u8, node.label),
        };
        errdefer self.freeNode(owned);
        try self.nodes.put(owned.cert_id, owned);
        try self.appendNode(owned);
    }

    pub fn getNode(self: *Store, cert_id: []const u8) ?Node {
        return self.nodes.get(cert_id);
    }

    pub fn nodeCount(self: *Store) usize {
        return self.nodes.count();
    }

    /// Direct children of a node, in allocation order. Caller owns the slice.
    pub fn children(self: *Store, parent_cert_id: []const u8) ![]Node {
        var out: std.ArrayList(Node) = .empty;
        errdefer out.deinit(self.allocator);
        var it = self.nodes.valueIterator();
        while (it.next()) |n| {
            if (n.parent_cert_id) |p| {
                if (std.mem.eql(u8, p, parent_cert_id)) try out.append(self.allocator, n.*);
            }
        }
        const slice = try out.toOwnedSlice(self.allocator);
        std.mem.sort(Node, slice, {}, struct {
            fn lt(_: void, a: Node, b: Node) bool {
                return a.child_index < b.child_index;
            }
        }.lt);
        return slice;
    }

    // ── log ──────────────────────────────────────────────────────────────────

    fn writeEscaped(w: anytype, s: []const u8) !void {
        try w.writeByte('"');
        for (s) |c| switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            else => {
                if (c < 0x20) {
                    try w.print("\\u{x:0>4}", .{c});
                } else try w.writeByte(c);
            },
        };
        try w.writeByte('"');
    }

    fn append(
        self: *Store,
        op: []const u8,
        parent_cert_id: []const u8,
        resource_id: []const u8,
        domain_flag: u64,
        value: u64,
    ) !void {
        const f = self.log orelse return;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);
        try w.print("{{\"op\":\"{s}\",\"p\":", .{op});
        try writeEscaped(w, parent_cert_id);
        try w.writeAll(",\"r\":");
        try writeEscaped(w, resource_id);
        try w.print(",\"f\":{d},\"v\":{d}}}\n", .{ domain_flag, value });
        try f.writeAll(buf.items);
    }

    fn appendNode(self: *Store, n: Node) !void {
        const f = self.log orelse return;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        const w = buf.writer(self.allocator);
        try w.writeAll("{\"op\":\"node\",\"certId\":");
        try writeEscaped(w, n.cert_id);
        try w.writeAll(",\"parent\":");
        if (n.parent_cert_id) |p| try writeEscaped(w, p) else try w.writeAll("null");
        try w.writeAll(",\"r\":");
        try writeEscaped(w, n.resource_id);
        try w.print(",\"f\":{d},\"i\":{d},\"label\":", .{ n.domain_flag, n.child_index });
        try writeEscaped(w, n.label);
        try w.writeAll("}\n");
        try f.writeAll(buf.items);
    }

    /// Replay a log, returning how many bytes formed complete records.
    ///
    /// Counters are RAISED rather than set, so replaying is idempotent and does
    /// not depend on record order — a property worth having in a file that a
    /// crash can interleave.
    fn replay(self: *Store, contents: []const u8) !usize {
        var consumed: usize = 0;
        var it = std.mem.splitScalar(u8, contents, '\n');
        while (it.next()) |line| {
            if (line.len == 0) {
                if (consumed < contents.len) consumed += 1;
                continue;
            }
            // A line without a terminator is a torn final write.
            const is_last = consumed + line.len >= contents.len;
            if (is_last) break;

            var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, line, .{}) catch {
                break; // malformed: stop here and treat the rest as torn
            };
            defer parsed.deinit();
            const o = parsed.value.object;
            const op = (o.get("op") orelse break).string;

            if (std.mem.eql(u8, op, "node")) {
                const parent_v = o.get("parent") orelse break;
                const node = Node{
                    .cert_id = (o.get("certId") orelse break).string,
                    .parent_cert_id = if (parent_v == .null) null else parent_v.string,
                    .resource_id = (o.get("r") orelse break).string,
                    .domain_flag = @intCast((o.get("f") orelse break).integer),
                    .child_index = @intCast((o.get("i") orelse break).integer),
                    .label = (o.get("label") orelse break).string,
                };
                if (!self.nodes.contains(node.cert_id)) {
                    const owned = Node{
                        .cert_id = try self.allocator.dupe(u8, node.cert_id),
                        .parent_cert_id = if (node.parent_cert_id) |p| try self.allocator.dupe(u8, p) else null,
                        .resource_id = try self.allocator.dupe(u8, node.resource_id),
                        .domain_flag = node.domain_flag,
                        .child_index = node.child_index,
                        .label = try self.allocator.dupe(u8, node.label),
                    };
                    try self.nodes.put(owned.cert_id, owned);
                }
            } else {
                try self.raise(
                    (o.get("p") orelse break).string,
                    (o.get("r") orelse break).string,
                    @intCast((o.get("f") orelse break).integer),
                    @intCast((o.get("v") orelse break).integer),
                );
            }
            consumed += line.len + 1;
        }
        return consumed;
    }
};
