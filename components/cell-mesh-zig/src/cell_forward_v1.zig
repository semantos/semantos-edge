const std = @import("std");
const wire = @import("cell_wire.zig");
const channel = @import("cell_channel.zig");
const forward = @import("cell_forward.zig");

pub const commit_slot_bytes: usize = 68;
pub const commit_array_bytes: usize = forward.max_hops * commit_slot_bytes;
pub const header_bytes: usize = forward.header_bytes + commit_array_bytes;
pub const max_inner_bytes: usize = wire.payload_size - header_bytes;

pub const ForwardV1 = extern struct {
    flow_id: [16]u8,
    hop_index: u8,
    total_hops: u8,
    segments_remaining: u8,
    hop_verb: c_int,
    segments: [forward.max_hops][6]u8,
    hop_commitments: [forward.max_hops]channel.ChannelCommitment,
    inner_payload_len: u32,
    inner_payload: [max_inner_bytes]u8,
};

pub export fn cm_forward_v1_encode(
    maybe_in: ?*const ForwardV1,
    maybe_out: ?[*]u8,
    maybe_out_used: ?*usize,
) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    const out_used = maybe_out_used orelse return -1;

    if (in.inner_payload_len > max_inner_bytes) return -1;
    if (in.segments_remaining > forward.max_hops) return -1;

    @memcpy(out[0..16], in.flow_id[0..]);
    out[16] = in.hop_index;
    out[17] = in.total_hops;
    out[18] = in.segments_remaining;
    out[19] = @intCast(in.hop_verb & 0xff);
    wire.writeU32(out[20..][0..4], in.inner_payload_len);
    for (0..forward.max_hops) |i| {
        @memcpy(out[24 + i * 6 ..][0..6], in.segments[i][0..]);
    }

    for (0..forward.max_hops) |i| {
        if (channel.cm_channel_commitment_encode(
            &in.hop_commitments[i],
            out[48 + i * commit_slot_bytes ..][0..commit_slot_bytes],
        ) != 0) return -1;
    }

    if (in.inner_payload_len > 0) {
        const n: usize = @intCast(in.inner_payload_len);
        @memcpy(out[header_bytes..][0..n], in.inner_payload[0..n]);
    }

    out_used.* = header_bytes + @as(usize, @intCast(in.inner_payload_len));
    return 0;
}

pub export fn cm_forward_v1_decode(
    maybe_in: ?[*]const u8,
    in_used: usize,
    maybe_out: ?*ForwardV1,
) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    if (in_used < header_bytes) return -1;

    out.* = std.mem.zeroes(ForwardV1);
    @memcpy(out.flow_id[0..], in[0..16]);
    out.hop_index = in[16];
    out.total_hops = in[17];
    out.segments_remaining = in[18];
    out.hop_verb = in[19];
    out.inner_payload_len = wire.readU32(in[20..][0..4]);

    if (out.segments_remaining > forward.max_hops) return -1;
    if (out.inner_payload_len > max_inner_bytes) return -1;
    if (header_bytes + @as(usize, @intCast(out.inner_payload_len)) > in_used) return -1;

    for (0..forward.max_hops) |i| {
        @memcpy(out.segments[i][0..], in[24 + i * 6 ..][0..6]);
    }
    for (0..forward.max_hops) |i| {
        if (channel.cm_channel_commitment_decode(
            in[48 + i * commit_slot_bytes ..][0..commit_slot_bytes],
            &out.hop_commitments[i],
        ) != 0) return -1;
    }

    if (out.inner_payload_len > 0) {
        const n: usize = @intCast(out.inner_payload_len);
        @memcpy(out.inner_payload[0..n], in[header_bytes..][0..n]);
    }
    return 0;
}

pub export fn cm_forward_v1_step(maybe_fwd: ?*ForwardV1, maybe_out_next_mac: ?[*]u8) callconv(.c) c_int {
    const fwd = maybe_fwd orelse return -1;

    if (fwd.segments_remaining == 0) {
        if (maybe_out_next_mac) |out_next_mac| @memset(out_next_mac[0..6], 0);
        return 1;
    }
    if (fwd.segments_remaining > forward.max_hops) return -1;

    for (0..forward.max_hops - 1) |i| {
        fwd.segments[i] = fwd.segments[i + 1];
    }
    @memset(fwd.segments[forward.max_hops - 1][0..], 0);

    fwd.segments_remaining -= 1;
    fwd.hop_index +%= 1;

    if (fwd.segments_remaining == 0) {
        if (maybe_out_next_mac) |out_next_mac| @memset(out_next_mac[0..6], 0);
        return 1;
    }
    if (maybe_out_next_mac) |out_next_mac| {
        @memcpy(out_next_mac[0..6], fwd.segments[0][0..]);
    }
    return 0;
}
