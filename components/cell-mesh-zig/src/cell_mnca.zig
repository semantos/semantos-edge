const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const wire = @import("cell_wire.zig");

pub const tile_header_bytes: usize = 16;
pub const max_state_bytes: usize = wire.payload_size - tile_header_bytes;
pub const tile_w: usize = 8;
pub const tile_h: usize = 8;
pub const tile_cells: usize = tile_w * tile_h;
pub const quorum_slots: usize = 4;
pub const quorum_k: usize = 2;
pub const quorum_ttl_ms: u64 = 60000;

pub const MncaRule = extern struct {
    alive_threshold: u8,
    inner_radius: u8,
    birth_lo: u8,
    birth_hi: u8,
    survive_lo: u8,
    survive_hi: u8,
    grow_step: u8,
    decay_step: u8,
    rule_id: [4]u8,
};

pub export const CM_MNCA_DEFAULT_RULE: MncaRule = .{
    .alive_threshold = 128,
    .inner_radius = 1,
    .birth_lo = 3,
    .birth_hi = 3,
    .survive_lo = 2,
    .survive_hi = 3,
    .grow_step = 64,
    .decay_step = 64,
    .rule_id = .{ 'M', 'N', 'C', 'A' },
};

pub const Tile = extern struct {
    x: u16,
    y: u16,
    generation: u32,
    state: [tile_cells]u8,
};

pub const QuorumSlot = extern struct {
    valid: bool,
    x: u16,
    y: u16,
    generation: u32,
    seen_count: u8,
    tile_hash: [quorum_k + 1][32]u8,
    sender_mac: [quorum_k + 1][6]u8,
    first_seen_ms: u64,
};

pub const Quorum = extern struct {
    slots: [quorum_slots]QuorumSlot,
};

pub export fn cm_mnca_tile_init_random(maybe_t: ?*Tile, x: u16, y: u16, seed: u32) callconv(.c) void {
    const t = maybe_t orelse return;
    t.x = x;
    t.y = y;
    t.generation = 0;
    var s = seed ^ 0xDEADBEEF;
    for (&t.state) |*cell| {
        s = s *% 1664525 +% 1013904223;
        cell.* = @intCast((s >> 16) & 0xff);
    }
}

fn countAlive(cells: *const [tile_cells]u8, cx: i32, cy: i32, radius: u8, thresh: u8) i32 {
    var n: i32 = 0;
    var dy: i32 = -@as(i32, radius);
    while (dy <= radius) : (dy += 1) {
        var dx: i32 = -@as(i32, radius);
        while (dx <= radius) : (dx += 1) {
            if (dx == 0 and dy == 0) continue;
            const nx = cx + dx;
            const ny = cy + dy;
            if (nx < 0 or nx >= @as(i32, @intCast(tile_w)) or ny < 0 or ny >= @as(i32, @intCast(tile_h))) continue;
            const idx: usize = @intCast(ny * @as(i32, @intCast(tile_w)) + nx);
            if (cells[idx] >= thresh) n += 1;
        }
    }
    return n;
}

fn clampU8(v: i32) u8 {
    if (v < 0) return 0;
    if (v > 255) return 255;
    return @intCast(v);
}

pub export fn cm_mnca_step(maybe_cur: ?*const Tile, maybe_next: ?*Tile, maybe_rule: ?*const MncaRule) callconv(.c) c_int {
    const cur = maybe_cur orelse return -1;
    const next = maybe_next orelse return -1;
    const rule = maybe_rule orelse return -1;

    next.* = cur.*;
    next.generation = cur.generation +% 1;

    for (0..tile_h) |yy| {
        for (0..tile_w) |xx| {
            const idx = yy * tile_w + xx;
            const self = cur.state[idx];
            const alive = countAlive(&cur.state, @intCast(xx), @intCast(yy), rule.inner_radius, rule.alive_threshold);
            const is_alive = self >= rule.alive_threshold;
            const delta: i32 = if (is_alive)
                if (alive >= rule.survive_lo and alive <= rule.survive_hi) rule.grow_step else -@as(i32, rule.decay_step)
            else if (alive >= rule.birth_lo and alive <= rule.birth_hi)
                rule.grow_step
            else
                -@as(i32, rule.decay_step);
            next.state[idx] = clampU8(@as(i32, self) + delta);
        }
    }
    return 0;
}

pub export fn cm_mnca_tile_encode(
    maybe_t: ?*const Tile,
    maybe_rule: ?*const MncaRule,
    maybe_out: ?[*]u8,
) callconv(.c) usize {
    const t = maybe_t orelse return 0;
    const out = maybe_out orelse return 0;

    @memset(out[0..wire.payload_size], 0);
    wire.writeU16(out[0..2], t.x);
    wire.writeU16(out[2..4], t.y);
    wire.writeU32(out[4..8], t.generation);
    if (maybe_rule) |rule| @memcpy(out[8..12], rule.rule_id[0..]);
    wire.writeU32(out[12..16], tile_cells);
    @memcpy(out[16..][0..tile_cells], t.state[0..]);
    return tile_header_bytes + tile_cells;
}

pub export fn cm_mnca_tile_decode(maybe_payload: ?[*]const u8, payload_len: usize, maybe_out: ?*Tile) callconv(.c) c_int {
    const payload = maybe_payload orelse return -1;
    const out = maybe_out orelse return -1;
    if (payload_len < tile_header_bytes) return -1;
    const state_len = wire.readU32(payload[12..][0..4]);
    if (tile_header_bytes + @as(usize, @intCast(state_len)) > payload_len) return -1;
    if (state_len != tile_cells) return -1;
    out.x = wire.readU16(payload[0..2]);
    out.y = wire.readU16(payload[2..4]);
    out.generation = wire.readU32(payload[4..8]);
    @memcpy(out.state[0..], payload[16..][0..tile_cells]);
    return 0;
}

pub export fn cm_mnca_tile_hash(maybe_t: ?*const Tile, maybe_out_hash: ?[*]u8) callconv(.c) void {
    const t = maybe_t orelse return;
    const out_hash = maybe_out_hash orelse return;
    Sha256.hash(t.state[0..], out_hash[0..32], .{});
}

pub export fn cm_mnca_quorum_init(maybe_q: ?*Quorum) callconv(.c) void {
    const q = maybe_q orelse return;
    q.* = std.mem.zeroes(Quorum);
}

pub export fn cm_mnca_quorum_update(
    maybe_q: ?*Quorum,
    x: u16,
    y: u16,
    generation: u32,
    maybe_tile_hash: ?[*]const u8,
    maybe_sender_mac: ?[*]const u8,
    now_ms: u64,
) callconv(.c) c_int {
    const q = maybe_q orelse return 0;
    const tile_hash = maybe_tile_hash orelse return 0;
    const sender_mac = maybe_sender_mac orelse return 0;

    for (&q.slots) |*s| {
        if (s.valid and (now_ms -% s.first_seen_ms) > quorum_ttl_ms) {
            s.valid = false;
        }
    }

    var slot: ?*QuorumSlot = null;
    var free_idx: ?usize = null;
    for (&q.slots, 0..) |*s, i| {
        if (!s.valid) {
            if (free_idx == null) free_idx = i;
            continue;
        }
        if (s.x == x and s.y == y and s.generation == generation) {
            slot = s;
            break;
        }
    }

    if (slot == null) {
        const idx = free_idx orelse return 0;
        var s = &q.slots[idx];
        s.valid = true;
        s.x = x;
        s.y = y;
        s.generation = generation;
        s.seen_count = 0;
        s.first_seen_ms = now_ms;
        slot = s;
    }

    var s = slot.?;
    for (s.sender_mac[0..s.seen_count]) |mac| {
        if (std.mem.eql(u8, mac[0..], sender_mac[0..6])) return 0;
    }

    const idx = s.seen_count;
    if (idx >= quorum_k + 1) return 0;
    @memcpy(s.tile_hash[idx][0..], tile_hash[0..32]);
    @memcpy(s.sender_mac[idx][0..], sender_mac[0..6]);
    s.seen_count += 1;

    var a: usize = 0;
    while (a < s.seen_count) : (a += 1) {
        var match: u8 = 1;
        var b = a + 1;
        while (b < s.seen_count) : (b += 1) {
            if (std.mem.eql(u8, s.tile_hash[a][0..], s.tile_hash[b][0..])) match += 1;
        }
        if (match >= quorum_k) {
            s.valid = false;
            return 1;
        }
    }
    return 0;
}
