//! The SCIM 2.0 wire surface: parsing what an IdP actually sends.
//!
//! Written against Okta's and Entra's observed behaviour rather than against
//! RFC 7644 in the abstract, because the two disagree in exactly the place that
//! matters most.
//!
//! ## The deactivation trap
//!
//! Okta deactivates a user with:
//!
//!     {"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
//!      "Operations":[{"op":"replace","value":{"active":false}}]}
//!
//! No `path`. `value` is an OBJECT. Entra sends the other shape:
//!
//!     {"Operations":[{"op":"Replace","path":"active","value":false}]}
//!
//! `path` present, `value` a bare boolean, `op` capitalised. Both are RFC-legal
//! — §3.5.2.3 makes `path` optional and defines the omitted case as "the target
//! is the resource itself, and value holds the attributes to replace".
//!
//! A provider written for one shape does not error on the other. It parses the
//! request, finds nothing it recognises, and returns **200 with the user still
//! active**. Every offboarding silently fails, and the IdP reports success. That
//! is why both shapes are parsed here and why the tests carry both verbatim.
//!
//! ## Two more that bite
//!
//! Okta **never** sends `DELETE /Users`. Deprovisioning is always a soft delete
//! via `active:false` — a provider waiting for a DELETE waits forever. And
//! integrations built with the App Integration Wizard send **PUT for everything**,
//! including deactivation, with no way to reconfigure them; so PUT has to carry
//! the same meaning as PATCH.
//!
//! ## Not implemented
//!
//! Filtering beyond `userName eq "..."` (the existence probe Okta sends before
//! every create), pagination, bulk, ETags, `/Schemas`, `/ResourceTypes`,
//! `/ServiceProviderConfig` (Okta does not call it), and PATCH paths other than
//! `active` and group membership. Stated rather than stubbed, because a stub
//! that returns 200 is how the trap above happens.

const std = @import("std");

pub const Error = error{
    UnsupportedOperation,
    MalformedRequest,
    UnsupportedFilter,
};

pub const patch_op_schema = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const user_schema = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const group_schema = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const list_schema = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const error_schema = "urn:ietf:params:scim:api:messages:2.0:Error";

/// What an IdP asked for, once the dialect is stripped away.
pub const Intent = union(enum) {
    /// The existence probe Okta sends before every create.
    find_user_by_username: []const u8,
    create_user: UserFields,
    /// PUT — a full replacement. AIW integrations deactivate this way.
    replace_user: struct { id: []const u8, fields: UserFields },
    /// PATCH, in either dialect, reduced to what it means.
    set_user_active: struct { id: []const u8, active: bool },
    create_group: struct { external_id: []const u8, display_name: []const u8 },
};

pub const UserFields = struct {
    external_id: []const u8,
    user_name: []const u8,
    display_name: []const u8,
    active: bool,
};

fn getStr(o: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = o.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn getBool(o: std.json.ObjectMap, key: []const u8) ?bool {
    const v = o.get(key) orelse return null;
    return switch (v) {
        .bool => |b| b,
        // Some clients send "true"/"false" as strings. RFC says boolean; being
        // lenient on input here is safe because the meaning is unambiguous.
        .string => |s| if (std.mem.eql(u8, s, "true")) true else if (std.mem.eql(u8, s, "false")) false else null,
        else => null,
    };
}

/// Pull a userName out of `userName eq "value"`, the only filter Okta sends.
///
/// Anything else is refused rather than answered wrongly: returning an empty
/// ListResponse to a filter you did not understand tells the IdP the user does
/// not exist, and it will happily create a duplicate.
pub fn parseUserNameFilter(filter: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, filter, " ");
    const prefix = "userName eq ";
    if (!std.ascii.startsWithIgnoreCase(trimmed, prefix)) return Error.UnsupportedFilter;
    var value = std.mem.trim(u8, trimmed[prefix.len..], " ");
    if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
        value = value[1 .. value.len - 1];
    }
    if (value.len == 0) return Error.UnsupportedFilter;
    return value;
}

fn parseUserFields(o: std.json.ObjectMap) !UserFields {
    const user_name = getStr(o, "userName") orelse return Error.MalformedRequest;
    // externalId is the IdP's immutable handle and is what identity should be
    // keyed on. Okta usually sends it; when it does not, userName is the only
    // thing left — and a later rename then strands the mapping, which is why
    // externalId is strongly preferred and this fallback is a fallback.
    const external_id = getStr(o, "externalId") orelse user_name;

    var display: []const u8 = user_name;
    if (getStr(o, "displayName")) |d| {
        display = d;
    } else if (o.get("name")) |n| {
        if (n == .object) {
            if (getStr(n.object, "formatted")) |f| display = f;
        }
    }
    // Okta sends `password` on every create even with sync disabled - a legacy
    // placeholder. It is deliberately not read.
    return .{
        .external_id = external_id,
        .user_name = user_name,
        .display_name = display,
        .active = getBool(o, "active") orelse true,
    };
}

/// Reduce a PATCH body to what it means, in either dialect.
fn parsePatch(body: std.json.ObjectMap, id: []const u8) !Intent {
    const ops_v = body.get("Operations") orelse body.get("operations") orelse return Error.MalformedRequest;
    if (ops_v != .array) return Error.MalformedRequest;

    for (ops_v.array.items) |op_v| {
        if (op_v != .object) continue;
        const op = op_v.object;
        const verb = getStr(op, "op") orelse continue;
        // Okta lowercases, Entra capitalises. Neither is wrong.
        if (!std.ascii.eqlIgnoreCase(verb, "replace") and !std.ascii.eqlIgnoreCase(verb, "add")) continue;

        if (getStr(op, "path")) |path| {
            // Entra's shape: path-addressed, value is a bare boolean.
            if (std.ascii.eqlIgnoreCase(path, "active")) {
                const active = getBool(op, "value") orelse return Error.MalformedRequest;
                return .{ .set_user_active = .{ .id = id, .active = active } };
            }
            continue;
        }

        // Okta's shape: no path, value is an object of attributes to replace.
        // Missing this branch is the silent-no-op bug this module exists for.
        const value = op.get("value") orelse continue;
        if (value != .object) continue;
        if (getBool(value.object, "active")) |active| {
            return .{ .set_user_active = .{ .id = id, .active = active } };
        }
    }
    return Error.UnsupportedOperation;
}

/// What `parse` hands back. `deinit` releases everything the intent borrows
/// from, so a caller never has to know whether a given intent points into the
/// parsed JSON tree or into a decoded query string.
pub const Request = struct {
    intent: Intent,
    parsed: ?std.json.Parsed(std.json.Value) = null,
    owned: ?[]u8 = null,

    pub fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        if (self.parsed) |*p| p.deinit();
        if (self.owned) |o| allocator.free(o);
        self.parsed = null;
        self.owned = null;
    }
};

/// Parse a request into the operation it represents.
///
/// `query` is the raw query string (may be empty). `body_json` may be empty for
/// GET. Paths are matched on their last segments, so any mount point works.
pub fn parse(
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    query: []const u8,
    body_json: []const u8,
) !Request {
    const is_users = std.mem.indexOf(u8, path, "/Users") != null;
    const is_groups = std.mem.indexOf(u8, path, "/Groups") != null;
    if (!is_users and !is_groups) return Error.UnsupportedOperation;

    // The resource id is the segment after /Users or /Groups, if any.
    const marker = if (is_users) "/Users" else "/Groups";
    const after = path[(std.mem.indexOf(u8, path, marker).? + marker.len)..];
    const id = std.mem.trim(u8, after, "/");

    if (std.mem.eql(u8, method, "GET")) {
        if (!is_users) return Error.UnsupportedOperation;
        const needle = "filter=";
        const at = std.mem.indexOf(u8, query, needle) orelse return Error.UnsupportedFilter;
        var raw = query[at + needle.len ..];
        if (std.mem.indexOfScalar(u8, raw, '&')) |amp| raw = raw[0..amp];
        const decoded = try percentDecode(allocator, raw);
        errdefer allocator.free(decoded);
        // The filter points INTO `decoded`, so the buffer travels with the
        // request rather than being freed here and dangling.
        return .{
            .intent = .{ .find_user_by_username = try parseUserNameFilter(decoded) },
            .owned = decoded,
        };
    }

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body_json, .{});
    errdefer parsed.deinit();
    if (parsed.value != .object) return Error.MalformedRequest;
    const o = parsed.value.object;

    if (is_groups) {
        if (!std.mem.eql(u8, method, "POST")) return Error.UnsupportedOperation;
        const display = getStr(o, "displayName") orelse return Error.MalformedRequest;
        const ext = getStr(o, "externalId") orelse display;
        return .{ .intent = .{ .create_group = .{ .external_id = ext, .display_name = display } }, .parsed = parsed };
    }

    if (std.mem.eql(u8, method, "POST")) {
        return .{ .intent = .{ .create_user = try parseUserFields(o) }, .parsed = parsed };
    }
    if (std.mem.eql(u8, method, "PUT")) {
        // AIW integrations deactivate through here, so a PUT that flips active
        // has to mean the same thing a PATCH would.
        return .{ .intent = .{ .replace_user = .{ .id = id, .fields = try parseUserFields(o) } }, .parsed = parsed };
    }
    if (std.mem.eql(u8, method, "PATCH")) {
        return .{ .intent = try parsePatch(o, id), .parsed = parsed };
    }
    // Okta never sends DELETE /Users; a provider that waits for one waits
    // forever. Refused loudly rather than accepted as a no-op.
    return Error.UnsupportedOperation;
}

fn percentDecode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        switch (s[i]) {
            '+' => try out.append(allocator, ' '),
            '%' => {
                if (i + 2 >= s.len) return Error.MalformedRequest;
                const hi = std.fmt.charToDigit(s[i + 1], 16) catch return Error.MalformedRequest;
                const lo = std.fmt.charToDigit(s[i + 2], 16) catch return Error.MalformedRequest;
                try out.append(allocator, @intCast(hi * 16 + lo));
                i += 2;
            },
            else => try out.append(allocator, s[i]),
        }
    }
    return out.toOwnedSlice(allocator);
}

// ── responses ────────────────────────────────────────────────────────────────

/// Render a SCIM User. Caller owns the slice.
///
/// `id` must be non-empty and stable: Okta stores it as the externalId on its
/// own profile, and an empty response body fails the provisioning job outright
/// with an admin-visible error rather than degrading quietly.
pub fn renderUser(
    allocator: std.mem.Allocator,
    id: []const u8,
    external_id: []const u8,
    user_name: []const u8,
    display_name: []const u8,
    active: bool,
) ![]u8 {
    return std.fmt.allocPrint(allocator,
        "{{\"schemas\":[\"{s}\"],\"id\":\"{s}\",\"externalId\":\"{s}\"," ++
        "\"userName\":\"{s}\",\"displayName\":\"{s}\",\"active\":{s}," ++
        "\"meta\":{{\"resourceType\":\"User\"}}}}",
        .{ user_schema, id, external_id, user_name, display_name, if (active) "true" else "false" });
}

/// Render a ListResponse.
///
/// `totalResults`, `startIndex` and `itemsPerPage` must be JSON INTEGERS. Okta's
/// conformance suite rejects them as strings, and a rejected probe means the
/// IdP creates a duplicate rather than finding the existing user.
pub fn renderList(allocator: std.mem.Allocator, resources_json: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const w = out.writer(allocator);
    try w.print(
        "{{\"schemas\":[\"{s}\"],\"totalResults\":{d},\"startIndex\":1,\"itemsPerPage\":{d},\"Resources\":[",
        .{ list_schema, resources_json.len, resources_json.len },
    );
    for (resources_json, 0..) |r, i| {
        if (i != 0) try w.writeByte(',');
        try w.writeAll(r);
    }
    try w.writeAll("]}");
    return out.toOwnedSlice(allocator);
}

/// Render a SCIM error.
///
/// `status` is a STRING. RFC 7644 §3.12 requires it; Okta's own examples show an
/// integer. A string satisfies both, an integer satisfies only one.
pub fn renderError(allocator: std.mem.Allocator, status: u16, detail: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator,
        "{{\"schemas\":[\"{s}\"],\"status\":\"{d}\",\"detail\":\"{s}\"}}",
        .{ error_schema, status, detail });
}
