const std = @import("std");
const wire = @import("cell_wire.zig");
const ring_mod = @import("cell_ring.zig");

pub const rules_max: usize = 8;
pub const encoded_size: usize = 139;
pub const schema_version: u8 = 0x01;

const trigger_none: c_int = 0;
const trigger_on_type: c_int = 1;
const trigger_quorum: c_int = 2;

const effect_none: c_int = 0;
const effect_blink: c_int = 1;
const effect_emit: c_int = 2;

pub const BlinkEffect = extern struct {
    duration_ms: u16,
};

pub const EmitEffect = extern struct {
    type_hash: [32]u8,
    payload_len: u16,
    payload: [64]u8,
};

pub const EffectAs = extern union {
    blink: BlinkEffect,
    emit: EmitEffect,
};

pub const Effect = extern struct {
    kind: c_int,
    as: EffectAs,
};

pub const Rule = extern struct {
    occupied: bool,
    trigger_kind: c_int,
    trigger_type_hash: [32]u8,
    quorum_n: u8,
    quorum_window_ms: u16,
    quorum_distinct_peers: bool,
    effect: Effect,
};

pub const Rules = extern struct {
    entries: [rules_max]Rule,
    total_evaluated: u32,
    total_fired: u32,
};

pub export fn cm_rule_encode(maybe_rule: ?*const Rule, maybe_out_buf: ?[*]u8) callconv(.c) c_int {
    const rule = maybe_rule orelse return -1;
    const out_buf = maybe_out_buf orelse return -1;

    @memset(out_buf[0..encoded_size], 0);
    out_buf[0] = schema_version;
    out_buf[1] = @intCast(rule.trigger_kind & 0xff);
    @memcpy(out_buf[2..34], rule.trigger_type_hash[0..]);

    if (rule.trigger_kind == trigger_quorum) {
        out_buf[34] = rule.quorum_n;
        wire.writeU16(out_buf[35..][0..2], rule.quorum_window_ms);
        out_buf[37] = if (rule.quorum_distinct_peers) 1 else 0;
    }

    out_buf[38] = @intCast(rule.effect.kind & 0xff);
    switch (rule.effect.kind) {
        effect_blink => wire.writeU16(out_buf[39..][0..2], rule.effect.as.blink.duration_ms),
        effect_emit => {
            @memcpy(out_buf[41..73], rule.effect.as.emit.type_hash[0..]);
            wire.writeU16(out_buf[73..][0..2], rule.effect.as.emit.payload_len);
            if (rule.effect.as.emit.payload_len > 0 and rule.effect.as.emit.payload_len <= 64) {
                const n: usize = rule.effect.as.emit.payload_len;
                @memcpy(out_buf[75..][0..n], rule.effect.as.emit.payload[0..n]);
            }
        },
        else => {},
    }
    return 0;
}

pub export fn cm_rule_decode(maybe_buf: ?[*]const u8, maybe_out_rule: ?*Rule) callconv(.c) c_int {
    const buf = maybe_buf orelse return -1;
    const out_rule = maybe_out_rule orelse return -1;
    if (buf[0] != schema_version) return -1;

    out_rule.* = std.mem.zeroes(Rule);
    const tk = buf[1];
    if (tk != trigger_on_type and tk != trigger_quorum) return -1;
    out_rule.trigger_kind = tk;
    @memcpy(out_rule.trigger_type_hash[0..], buf[2..34]);

    if (tk == trigger_quorum) {
        out_rule.quorum_n = buf[34];
        out_rule.quorum_window_ms = wire.readU16(buf[35..][0..2]);
        out_rule.quorum_distinct_peers = buf[37] != 0;
    }

    const ek = buf[38];
    if (ek != effect_blink and ek != effect_emit) return -1;
    out_rule.effect.kind = ek;
    switch (ek) {
        effect_blink => out_rule.effect.as.blink.duration_ms = wire.readU16(buf[39..][0..2]),
        effect_emit => {
            @memcpy(out_rule.effect.as.emit.type_hash[0..], buf[41..73]);
            out_rule.effect.as.emit.payload_len = wire.readU16(buf[73..][0..2]);
            if (out_rule.effect.as.emit.payload_len > 64) return -1;
            const n: usize = out_rule.effect.as.emit.payload_len;
            @memcpy(out_rule.effect.as.emit.payload[0..n], buf[75..][0..n]);
        },
        else => return -1,
    }
    return 0;
}

pub export fn cm_rule_equals(maybe_a: ?*const Rule, maybe_b: ?*const Rule) callconv(.c) bool {
    const a = maybe_a orelse return false;
    const b = maybe_b orelse return false;
    var buf_a: [encoded_size]u8 = undefined;
    var buf_b: [encoded_size]u8 = undefined;
    if (cm_rule_encode(a, &buf_a) != 0) return false;
    if (cm_rule_encode(b, &buf_b) != 0) return false;
    return std.mem.eql(u8, buf_a[0..], buf_b[0..]);
}

pub export fn cm_rules_init(maybe_rules: ?*Rules) callconv(.c) void {
    const rules = maybe_rules orelse return;
    rules.* = std.mem.zeroes(Rules);
}

pub export fn cm_rules_install(maybe_rules: ?*Rules, maybe_rule: ?*const Rule) callconv(.c) c_int {
    const rules = maybe_rules orelse return -1;
    const rule = maybe_rule orelse return -1;
    if (rule.trigger_kind == trigger_none) return -1;
    if (rule.effect.kind == effect_none) return -1;

    for (&rules.entries, 0..) |*entry, i| {
        if (!entry.occupied) {
            entry.* = rule.*;
            entry.occupied = true;
            return @intCast(i);
        }
    }
    return -1;
}

pub export fn cm_rules_remove(maybe_rules: ?*Rules, slot: usize) callconv(.c) c_int {
    const rules = maybe_rules orelse return -1;
    if (slot >= rules_max) return -1;
    rules.entries[slot].occupied = false;
    return 0;
}

fn triggerMatches(r: *const Rule, maybe_ring: ?*const ring_mod.Ring, cell: [*]const u8, now_ms: u64) bool {
    switch (r.trigger_kind) {
        trigger_on_type => return std.mem.eql(u8, cell[wire.Off.type_hash..][0..32], r.trigger_type_hash[0..]),
        trigger_quorum => {
            const ring = maybe_ring orelse return false;
            if (!std.mem.eql(u8, cell[wire.Off.type_hash..][0..32], r.trigger_type_hash[0..])) return false;
            const n = ring_mod.cm_ring_count_recent(
                ring,
                @ptrCast(&r.trigger_type_hash),
                now_ms,
                r.quorum_window_ms,
                r.quorum_distinct_peers,
            );
            return n >= r.quorum_n;
        },
        else => return false,
    }
}

pub export fn cm_rules_evaluate(
    maybe_rules: ?*Rules,
    maybe_ring: ?*const ring_mod.Ring,
    maybe_cell: ?[*]const u8,
    now_ms: u64,
    maybe_out_effects: ?[*]Effect,
) callconv(.c) usize {
    const rules = maybe_rules orelse return 0;
    const cell = maybe_cell orelse return 0;
    const out_effects = maybe_out_effects orelse return 0;

    rules.total_evaluated +%= 1;

    var count: usize = 0;
    for (&rules.entries) |*r| {
        if (!r.occupied) continue;
        if (!triggerMatches(r, maybe_ring, cell, now_ms)) continue;
        out_effects[count] = r.effect;
        count += 1;
        rules.total_fired +%= 1;
    }
    return count;
}
