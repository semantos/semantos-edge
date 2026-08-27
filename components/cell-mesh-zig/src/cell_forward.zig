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

// ── Where am I on an immutable route? ────────────────────────────────────────
//
// Cells are relayed VERBATIM — the origin signs 1024 bytes and every hop
// forwards exactly those bytes — so nothing mutates a hop cursor in flight and a
// device has to work out its own position instead of reading one.
//
// This lived three times in main.c, once per forward version, copy-pasted. It is
// protocol, not application: it decides who may act on a cell and who it goes to
// next. That belongs here, where it is host-testable, rather than in the demo
// app where each copy could drift from the others.

pub const locate_not_on_route: c_int = -1;
pub const locate_out_of_order: c_int = -2;
pub const locate_bad_route: c_int = -3;
pub const locate_relay: c_int = 0;
pub const locate_deliver: c_int = 1;

/// Find this device's hop on `segments`, and say whether to relay or deliver.
///
/// `sender_mac` is who this cell arrived from, and it is load-bearing. Every
/// board hears the origin's broadcast, so position alone would let the LAST hop
/// act before the first had relayed — the route would be a suggestion. Hop 0
/// takes the cell from the origin (any sender); every later hop takes it only
/// from its immediate predecessor.
///
/// Returns `locate_relay` with `out_next_mac` filled, `locate_deliver` with it
/// zeroed, or a negative code. `out_hop` is set whenever the device is on the
/// route, including when the cell is refused for arriving out of order — a
/// caller that wants to log the refusal needs to know which hop it was.
pub export fn cm_forward_locate(
    maybe_segments: ?[*]const [6]u8,
    total_hops: u8,
    maybe_my_mac: ?[*]const u8,
    maybe_sender_mac: ?[*]const u8,
    maybe_out_hop: ?*u8,
    maybe_out_next_mac: ?[*]u8,
) callconv(.c) c_int {
    const segments = maybe_segments orelse return locate_not_on_route;
    const my_mac = maybe_my_mac orelse return locate_not_on_route;

    // Refuse an over-long route rather than clamping it. Clamping looks
    // defensive but silently turns a malformed route into a DIFFERENT, shorter
    // one — a cell claiming 200 hops would become a 4-hop cell relaying into
    // whatever the unused slots happen to hold. The decoders already refuse
    // out-of-range hop counts; match them.
    if (total_hops == 0 or total_hops > max_hops) return locate_bad_route;
    const path_len: usize = total_hops;

    var my_hop: usize = max_hops;
    for (0..path_len) |i| {
        if (std.mem.eql(u8, segments[i][0..], my_mac[0..6])) {
            my_hop = i;
            break;
        }
    }
    if (my_hop == max_hops) return locate_not_on_route;
    if (maybe_out_hop) |out_hop| out_hop.* = @intCast(my_hop);

    if (my_hop > 0) {
        const sender = maybe_sender_mac orelse return locate_out_of_order;
        if (!std.mem.eql(u8, segments[my_hop - 1][0..], sender[0..6])) {
            return locate_out_of_order;
        }
    }

    if (my_hop + 1 < path_len) {
        const next = segments[my_hop + 1];
        // A zero next-hop inside the declared path is a malformed route, not an
        // end marker — relaying to it would unicast into nothing.
        if (std.mem.allEqual(u8, next[0..], 0)) return locate_bad_route;
        if (maybe_out_next_mac) |out| @memcpy(out[0..6], next[0..]);
        return locate_relay;
    }
    if (maybe_out_next_mac) |out| @memset(out[0..6], 0);
    return locate_deliver;
}

test "locate: finds its own hop and names the next one" {
    const testing = std.testing;
    const A = [6]u8{ 0xaa, 0, 0, 0, 0, 1 };
    const B = [6]u8{ 0xbb, 0, 0, 0, 0, 2 };
    const C = [6]u8{ 0xcc, 0, 0, 0, 0, 3 };
    const segs = [_][6]u8{ B, C, [_]u8{0} ** 6, [_]u8{0} ** 6 };

    var hop: u8 = 0xff;
    var next: [6]u8 = undefined;

    // B is hop 0 and takes it from the origin, whoever that is.
    try testing.expectEqual(locate_relay, cm_forward_locate(&segs, 2, &B, &A, &hop, &next));
    try testing.expectEqual(@as(u8, 0), hop);
    try testing.expectEqualSlices(u8, C[0..], next[0..]);

    // C is the last hop: deliver, and next is zeroed rather than left stale.
    @memset(next[0..], 0xee);
    try testing.expectEqual(locate_deliver, cm_forward_locate(&segs, 2, &C, &B, &hop, &next));
    try testing.expectEqual(@as(u8, 1), hop);
    try testing.expectEqualSlices(u8, &[_]u8{0} ** 6, next[0..]);
}

test "locate: ordering is enforced, and hop 0 is exempt" {
    const testing = std.testing;
    const A = [6]u8{ 0xaa, 0, 0, 0, 0, 1 };
    const B = [6]u8{ 0xbb, 0, 0, 0, 0, 2 };
    const C = [6]u8{ 0xcc, 0, 0, 0, 0, 3 };
    const segs = [_][6]u8{ B, C, [_]u8{0} ** 6, [_]u8{0} ** 6 };
    var hop: u8 = 0xff;
    var next: [6]u8 = undefined;

    // C hears the ORIGIN's broadcast directly. It must not act on it: without
    // this the last hop delivers before the first has relayed.
    try testing.expectEqual(locate_out_of_order, cm_forward_locate(&segs, 2, &C, &A, &hop, &next));
    // ...but it still learns which hop it is, so the refusal can be logged.
    try testing.expectEqual(@as(u8, 1), hop);

    // From its actual predecessor, it is accepted.
    try testing.expectEqual(locate_deliver, cm_forward_locate(&segs, 2, &C, &B, &hop, &next));
}

test "locate: a device not on the route is refused before anything else" {
    const testing = std.testing;
    const B = [6]u8{ 0xbb, 0, 0, 0, 0, 2 };
    const C = [6]u8{ 0xcc, 0, 0, 0, 0, 3 };
    const D = [6]u8{ 0xdd, 0, 0, 0, 0, 4 };
    const segs = [_][6]u8{ B, C, [_]u8{0} ** 6, [_]u8{0} ** 6 };
    var hop: u8 = 0xff;
    var next: [6]u8 = undefined;
    try testing.expectEqual(locate_not_on_route, cm_forward_locate(&segs, 2, &D, &B, &hop, &next));
    // hop is untouched — there is no hop to report.
    try testing.expectEqual(@as(u8, 0xff), hop);
}

test "locate: an over-long route is refused, not silently shortened" {
    const testing = std.testing;
    const B = [6]u8{ 0xbb, 0, 0, 0, 0, 2 };
    const segs = [_][6]u8{ B, [_]u8{0} ** 6, [_]u8{0} ** 6, [_]u8{0} ** 6 };
    var hop: u8 = 0xff;
    var next: [6]u8 = undefined;
    // Clamping 200 to 4 would have made this device hop 0 of a route it never
    // agreed to, relaying into an empty slot. Refuse instead.
    try testing.expectEqual(locate_bad_route, cm_forward_locate(&segs, 200, &B, &B, &hop, &next));
    try testing.expectEqual(locate_bad_route, cm_forward_locate(&segs, 0, &B, &B, &hop, &next));
}

test "locate: a zero next-hop inside the path is a bad route, not a delivery" {
    const testing = std.testing;
    const B = [6]u8{ 0xbb, 0, 0, 0, 0, 2 };
    const zero = [_]u8{0} ** 6;
    const segs = [_][6]u8{ B, zero, zero, zero };
    var hop: u8 = 0xff;
    var next: [6]u8 = undefined;
    // total_hops=2 says slot 1 is a real hop, and it is empty. Relaying there
    // would unicast into nothing; treating it as the end would let a truncated
    // route deliver early. Neither — refuse.
    try testing.expectEqual(locate_bad_route, cm_forward_locate(&segs, 2, &B, &B, &hop, &next));
}
