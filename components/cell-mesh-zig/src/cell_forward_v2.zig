const std = @import("std");
const wire = @import("cell_wire.zig");
const channel = @import("cell_channel.zig");
const forward = @import("cell_forward.zig");

pub const header_bytes: usize = 24;
pub const max_inner_bytes: usize = wire.payload_size - header_bytes;
pub const routing_cont_flag: u8 = 0x01;
pub const commit_slot_bytes: usize = 68;
pub const routing_used_bytes: usize = 320;

pub const ForwardV2 = extern struct {
    flow_id: [16]u8,
    hop_index: u8,
    total_hops: u8,
    hop_verb: c_int,
    flags: u8,
    inner_payload_len: u32,
    inner_payload: [max_inner_bytes]u8,
};

pub const RoutingCont = extern struct {
    flow_id: [16]u8,
    hop_index: u8,
    segments_remaining: u8,
    reserved: [6]u8,
    segments: [forward.max_hops][6]u8,
    hop_commitments: [forward.max_hops]channel.ChannelCommitment,
};

pub export fn cm_forward_v2_encode(
    maybe_in: ?*const ForwardV2,
    maybe_out: ?[*]u8,
    maybe_out_used: ?*usize,
) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    const out_used = maybe_out_used orelse return -1;

    if (in.inner_payload_len > max_inner_bytes) return -1;

    @memcpy(out[0..16], in.flow_id[0..]);
    out[16] = in.hop_index;
    out[17] = in.total_hops;
    out[18] = @intCast(in.hop_verb & 0xff);
    out[19] = in.flags | routing_cont_flag;
    wire.writeU32(out[20..][0..4], in.inner_payload_len);

    if (in.inner_payload_len > 0) {
        const n: usize = @intCast(in.inner_payload_len);
        @memcpy(out[24..][0..n], in.inner_payload[0..n]);
    }

    out_used.* = header_bytes + @as(usize, @intCast(in.inner_payload_len));
    return 0;
}

pub export fn cm_forward_v2_decode(
    maybe_in: ?[*]const u8,
    in_used: usize,
    maybe_out: ?*ForwardV2,
) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    if (in_used < header_bytes) return -1;

    out.* = std.mem.zeroes(ForwardV2);
    @memcpy(out.flow_id[0..], in[0..16]);
    out.hop_index = in[16];
    out.total_hops = in[17];
    out.hop_verb = in[18];
    out.flags = in[19];
    out.inner_payload_len = wire.readU32(in[20..][0..4]);

    if (out.inner_payload_len > max_inner_bytes) return -1;
    if (header_bytes + @as(usize, @intCast(out.inner_payload_len)) > in_used) return -1;

    if (out.inner_payload_len > 0) {
        const n: usize = @intCast(out.inner_payload_len);
        @memcpy(out.inner_payload[0..n], in[24..][0..n]);
    }
    return 0;
}

pub export fn cm_routing_cont_encode(
    maybe_in: ?*const RoutingCont,
    maybe_out: ?[*]u8,
    maybe_out_used: ?*usize,
) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    const out_used = maybe_out_used orelse return -1;

    if (in.segments_remaining > forward.max_hops) return -1;

    @memcpy(out[0..16], in.flow_id[0..]);
    out[16] = in.hop_index;
    out[17] = in.segments_remaining;
    @memset(out[18..24], 0);
    for (0..forward.max_hops) |i| {
        @memcpy(out[24 + i * 6 ..][0..6], in.segments[i][0..]);
    }
    for (0..forward.max_hops) |i| {
        if (channel.cm_channel_commitment_encode(
            &in.hop_commitments[i],
            out[48 + i * commit_slot_bytes ..][0..commit_slot_bytes],
        ) != 0) return -1;
    }

    out_used.* = routing_used_bytes;
    return 0;
}

pub export fn cm_routing_cont_decode(
    maybe_in: ?[*]const u8,
    in_used: usize,
    maybe_out: ?*RoutingCont,
) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    if (in_used < routing_used_bytes) return -1;

    out.* = std.mem.zeroes(RoutingCont);
    @memcpy(out.flow_id[0..], in[0..16]);
    out.hop_index = in[16];
    out.segments_remaining = in[17];
    if (out.segments_remaining > forward.max_hops) return -1;

    for (0..forward.max_hops) |i| {
        @memcpy(out.segments[i][0..], in[24 + i * 6 ..][0..6]);
    }
    for (0..forward.max_hops) |i| {
        if (channel.cm_channel_commitment_decode(
            in[48 + i * commit_slot_bytes ..][0..commit_slot_bytes],
            &out.hop_commitments[i],
        ) != 0) return -1;
    }
    return 0;
}

pub export fn cm_forward_v2_step(
    maybe_primary: ?*ForwardV2,
    maybe_routing: ?*RoutingCont,
    maybe_out_next_mac: ?[*]u8,
) callconv(.c) c_int {
    const primary = maybe_primary orelse return -1;
    const routing = maybe_routing orelse return -1;
    const out_next_mac = maybe_out_next_mac orelse return -1;

    if (primary.hop_index != routing.hop_index) return -1;
    if (routing.segments_remaining == 0) return 1;
    if (routing.segments_remaining > forward.max_hops) return -1;

    for (0..forward.max_hops - 1) |i| {
        routing.segments[i] = routing.segments[i + 1];
    }
    @memset(routing.segments[forward.max_hops - 1][0..], 0);

    routing.segments_remaining -= 1;
    primary.hop_index +%= 1;
    routing.hop_index +%= 1;

    if (routing.segments_remaining == 0) {
        @memset(out_next_mac[0..6], 0);
        return 1;
    }
    @memcpy(out_next_mac[0..6], routing.segments[0][0..]);
    return 0;
}
