const std = @import("std");
const wire = @import("cell_wire.zig");

pub const capacity: usize = 16;

pub const RingEntry = extern struct {
    cell: [wire.cell_size]u8,
    peer_mac: [6]u8,
    received_at_ms: u64,
    occupied: bool,
};

pub const Ring = extern struct {
    entries: [capacity]RingEntry,
    next_index: u32,
    total_pushed: u32,
};

pub const VisitFn = *const fn (*const RingEntry, ?*anyopaque) callconv(.c) bool;

pub export fn cm_ring_init(maybe_r: ?*Ring) callconv(.c) void {
    const r = maybe_r orelse return;
    r.* = std.mem.zeroes(Ring);
}

pub export fn cm_ring_push(
    maybe_r: ?*Ring,
    maybe_cell: ?[*]const u8,
    maybe_peer_mac: ?[*]const u8,
    received_at_ms: u64,
) callconv(.c) void {
    const r = maybe_r orelse return;
    const cell = maybe_cell orelse return;

    const slot = r.next_index % capacity;
    var e = &r.entries[slot];

    @memcpy(e.cell[0..], cell[0..wire.cell_size]);
    if (maybe_peer_mac) |peer_mac| {
        @memcpy(e.peer_mac[0..], peer_mac[0..6]);
    } else {
        @memset(e.peer_mac[0..], 0);
    }
    e.received_at_ms = received_at_ms;
    e.occupied = true;

    r.next_index +%= 1;
    r.total_pushed +%= 1;
}

pub export fn cm_ring_visit_newest_first(
    maybe_r: ?*const Ring,
    maybe_cb: ?VisitFn,
    userdata: ?*anyopaque,
) callconv(.c) usize {
    const r = maybe_r orelse return 0;
    const cb = maybe_cb orelse return 0;

    var visited: usize = 0;
    for (0..capacity) |i| {
        const slot = (@as(usize, r.next_index) + capacity - 1 - i) % capacity;
        const e = &r.entries[slot];
        if (!e.occupied) continue;
        visited += 1;
        if (!cb(e, userdata)) break;
    }
    return visited;
}

fn peerAlreadySeen(seen_peers: *[capacity][6]u8, seen_peers_n: usize, mac: *const [6]u8) bool {
    for (seen_peers[0..seen_peers_n]) |seen| {
        if (std.mem.eql(u8, seen[0..], mac[0..])) return true;
    }
    return false;
}

pub export fn cm_ring_count_recent(
    maybe_r: ?*const Ring,
    maybe_type_hash: ?[*]const u8,
    now_ms: u64,
    window_ms: u32,
    distinct_peers_only: bool,
) callconv(.c) usize {
    const r = maybe_r orelse return 0;
    const type_hash = maybe_type_hash orelse return 0;

    var count: usize = 0;
    var seen_peers: [capacity][6]u8 = std.mem.zeroes([capacity][6]u8);
    var seen_peers_n: usize = 0;

    for (0..capacity) |i| {
        const slot = (@as(usize, r.next_index) + capacity - 1 - i) % capacity;
        const e = &r.entries[slot];
        if (!e.occupied) continue;
        if (now_ms < e.received_at_ms) break;
        const age_ms = now_ms - e.received_at_ms;
        if (age_ms > window_ms) break;

        if (!std.mem.eql(u8, e.cell[wire.Off.type_hash..][0..32], type_hash[0..32])) continue;

        if (distinct_peers_only) {
            if (peerAlreadySeen(&seen_peers, seen_peers_n, &e.peer_mac)) continue;
            if (seen_peers_n < capacity) {
                seen_peers[seen_peers_n] = e.peer_mac;
                seen_peers_n += 1;
            }
        }
        count += 1;
    }

    return count;
}
