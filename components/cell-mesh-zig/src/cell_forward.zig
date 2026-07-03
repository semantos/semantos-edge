const std = @import("std");
const wire = @import("cell_wire.zig");

pub const max_hops: usize = 4;
pub const header_bytes: usize = 48;
pub const max_inner_bytes: usize = 720;

const fwd_next: c_int = 0;
const fwd_delivered: c_int = 1;
const fwd_err_bad: c_int = -1;

pub const Forward = extern struct {
    flow_id: [16]u8,
    hop_index: u8,
    total_hops: u8,
    segments_remaining: u8,
    hop_verb: c_int,
    segments: [max_hops][6]u8,
    inner_payload_len: u32,
    inner_payload: [max_inner_bytes]u8,
};

pub export fn cm_forward_encode(
    maybe_in: ?*const Forward,
    maybe_out: ?[*]u8,
    maybe_out_used: ?*usize,
) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    const out_used = maybe_out_used orelse return -1;

    if (in.inner_payload_len > max_inner_bytes) return -1;
    if (in.segments_remaining > max_hops) return -1;

    @memcpy(out[0..16], in.flow_id[0..]);
    out[16] = in.hop_index;
    out[17] = in.total_hops;
    out[18] = in.segments_remaining;
    out[19] = @intCast(in.hop_verb & 0xff);
    wire.writeU32(out[20..][0..4], in.inner_payload_len);

    for (0..max_hops) |i| {
        @memcpy(out[24 + i * 6 ..][0..6], in.segments[i][0..]);
    }

    if (in.inner_payload_len > 0) {
        const n: usize = @intCast(in.inner_payload_len);
        @memcpy(out[48..][0..n], in.inner_payload[0..n]);
    }

    out_used.* = header_bytes + @as(usize, @intCast(in.inner_payload_len));
    return 0;
}

pub export fn cm_forward_decode(
    maybe_in: ?[*]const u8,
    in_used: usize,
    maybe_out: ?*Forward,
) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    if (in_used < header_bytes) return -1;

    out.* = std.mem.zeroes(Forward);
    @memcpy(out.flow_id[0..], in[0..16]);
    out.hop_index = in[16];
    out.total_hops = in[17];
    out.segments_remaining = in[18];
    out.hop_verb = in[19];
    out.inner_payload_len = wire.readU32(in[20..][0..4]);

    if (out.segments_remaining > max_hops) return -1;
    if (out.inner_payload_len > max_inner_bytes) return -1;
    if (header_bytes + @as(usize, @intCast(out.inner_payload_len)) > in_used) return -1;

    for (0..max_hops) |i| {
        @memcpy(out.segments[i][0..], in[24 + i * 6 ..][0..6]);
    }

    if (out.inner_payload_len > 0) {
        const n: usize = @intCast(out.inner_payload_len);
        @memcpy(out.inner_payload[0..n], in[48..][0..n]);
    }

    return 0;
}

pub export fn cm_forward_step(maybe_fwd: ?*Forward, maybe_out_next_mac: ?[*]u8) callconv(.c) c_int {
    const fwd = maybe_fwd orelse return fwd_err_bad;

    if (fwd.segments_remaining == 0) {
        if (maybe_out_next_mac) |out_next_mac| @memset(out_next_mac[0..6], 0);
        return fwd_delivered;
    }

    if (fwd.segments_remaining > max_hops) return fwd_err_bad;

    for (0..max_hops - 1) |i| {
        fwd.segments[i] = fwd.segments[i + 1];
    }
    @memset(fwd.segments[max_hops - 1][0..], 0);

    fwd.segments_remaining -= 1;
    fwd.hop_index +%= 1;

    if (fwd.segments_remaining == 0) {
        if (maybe_out_next_mac) |out_next_mac| @memset(out_next_mac[0..6], 0);
        return fwd_delivered;
    }
    if (maybe_out_next_mac) |out_next_mac| {
        @memcpy(out_next_mac[0..6], fwd.segments[0][0..]);
    }
    return fwd_next;
}
