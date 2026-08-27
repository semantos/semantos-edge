const std = @import("std");
const wire = @import("cell_wire.zig");
const channel = @import("cell_channel.zig");
const forward = @import("cell_forward.zig");

/// 24 header bytes + a 32-byte digest of Cell B.
///
/// Cell A is signed and Cell B is not, and Cell B is where the ROUTE and the
/// PAYMENT COMMITMENTS live. Without this field, "Cell A's signature verified"
/// said nothing about the route the cell travelled or the shares claimed along
/// it — both rode in a cell anyone could mint. The digest pulls Cell B under
/// Cell A's signature transitively: change one byte of the route and Cell A no
/// longer vouches for it.
pub const header_bytes: usize = 56;
pub const routing_digest_offset: usize = 24;
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
    /// SHA-256 over the whole 1024-byte Cell B. Zero means "not bound", which
    /// a verifying device must refuse — see header_bytes.
    routing_digest: [32]u8,
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
    @memcpy(out[routing_digest_offset..][0..32], in.routing_digest[0..]);

    if (in.inner_payload_len > 0) {
        const n: usize = @intCast(in.inner_payload_len);
        @memcpy(out[header_bytes..][0..n], in.inner_payload[0..n]);
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
    @memcpy(out.routing_digest[0..], in[routing_digest_offset..][0..32]);

    if (out.inner_payload_len > max_inner_bytes) return -1;
    if (header_bytes + @as(usize, @intCast(out.inner_payload_len)) > in_used) return -1;

    if (out.inner_payload_len > 0) {
        const n: usize = @intCast(out.inner_payload_len);
        @memcpy(out.inner_payload[0..n], in[header_bytes..][0..n]);
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
