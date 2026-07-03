const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const wire = @import("cell_wire.zig");

pub const table_max: usize = 4;
pub const payload_bytes: usize = 66;
pub const route_fwd_v1: u8 = 0x01;
const no_expiry = std.math.maxInt(u64);

const ok: c_int = 0;
const err_bad_payload: c_int = -1;
const err_expired: c_int = -2;
const err_table_full: c_int = -3;

pub const CapEntry = extern struct {
    valid: bool,
    channel_id: [16]u8,
    edge_pubkey: [33]u8,
    route_type: u8,
    expiry_ms: u64,
    valid_from_ms: u64,
    cert_hash: [32]u8,
};

pub const CapTable = extern struct {
    entries: [table_max]CapEntry,
};

pub export fn cm_cap_table_init(maybe_t: ?*CapTable) callconv(.c) void {
    const t = maybe_t orelse return;
    t.* = std.mem.zeroes(CapTable);
}

pub export fn cm_cap_install(
    maybe_t: ?*CapTable,
    maybe_payload: ?[*]const u8,
    payload_len: usize,
    now_ms: u64,
) callconv(.c) c_int {
    const t = maybe_t orelse return err_bad_payload;
    const payload = maybe_payload orelse return err_bad_payload;
    if (payload_len < payload_bytes) return err_bad_payload;

    const expiry_ms = wire.readU64(payload[49..][0..8]);
    const route_type = payload[57];
    const valid_from_ms = wire.readU64(payload[58..][0..8]);

    if (expiry_ms != no_expiry and expiry_ms <= now_ms) return err_expired;

    var cert_hash: [32]u8 = undefined;
    Sha256.hash(payload[0..payload_bytes], cert_hash[0..], .{});

    var free_slot: ?usize = null;
    for (&t.entries, 0..) |*e, i| {
        if (!e.valid or (e.expiry_ms != no_expiry and e.expiry_ms <= now_ms)) {
            if (free_slot == null) free_slot = i;
            continue;
        }
        if (std.mem.eql(u8, e.channel_id[0..], payload[33..49]) and e.route_type == route_type) {
            @memcpy(e.edge_pubkey[0..], payload[0..33]);
            @memcpy(e.cert_hash[0..], cert_hash[0..]);
            e.expiry_ms = expiry_ms;
            e.valid_from_ms = valid_from_ms;
            return ok;
        }
    }

    const idx = free_slot orelse return err_table_full;
    var e = &t.entries[idx];
    e.valid = true;
    e.route_type = route_type;
    e.expiry_ms = expiry_ms;
    e.valid_from_ms = valid_from_ms;
    @memcpy(e.channel_id[0..], payload[33..49]);
    @memcpy(e.edge_pubkey[0..], payload[0..33]);
    @memcpy(e.cert_hash[0..], cert_hash[0..]);
    return ok;
}

fn findEntry(maybe_t: ?*CapTable, maybe_channel_id: ?[*]const u8, route_type: u8, now_ms: u64) ?*CapEntry {
    const t = maybe_t orelse return null;
    const channel_id = maybe_channel_id orelse return null;
    for (&t.entries) |*e| {
        if (!e.valid) continue;
        if (e.expiry_ms != no_expiry and e.expiry_ms <= now_ms) {
            e.valid = false;
            continue;
        }
        if (e.route_type != route_type) continue;
        if (!std.mem.eql(u8, e.channel_id[0..], channel_id[0..16])) continue;
        return e;
    }
    return null;
}

pub export fn cm_cap_lookup(
    maybe_t: ?*CapTable,
    maybe_channel_id: ?[*]const u8,
    route_type: u8,
    now_ms: u64,
) callconv(.c) ?[*]const u8 {
    const e = findEntry(maybe_t, maybe_channel_id, route_type, now_ms) orelse return null;
    return @ptrCast(&e.edge_pubkey);
}

pub export fn cm_cap_cert_hash(
    maybe_t: ?*CapTable,
    maybe_channel_id: ?[*]const u8,
    route_type: u8,
    now_ms: u64,
) callconv(.c) ?[*]const u8 {
    const e = findEntry(maybe_t, maybe_channel_id, route_type, now_ms) orelse return null;
    return @ptrCast(&e.cert_hash);
}

pub export fn cm_cap_evict_expired(maybe_t: ?*CapTable, now_ms: u64) callconv(.c) void {
    const t = maybe_t orelse return;
    for (&t.entries) |*e| {
        if (e.valid and e.expiry_ms != no_expiry and e.expiry_ms <= now_ms) {
            e.valid = false;
        }
    }
}

pub export fn cm_cap_valid_count(maybe_t: ?*const CapTable, now_ms: u64) callconv(.c) c_int {
    const t = maybe_t orelse return 0;
    var n: c_int = 0;
    for (&t.entries) |*e| {
        if (e.valid and (e.expiry_ms == no_expiry or e.expiry_ms > now_ms)) n += 1;
    }
    return n;
}
