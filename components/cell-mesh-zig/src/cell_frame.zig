const std = @import("std");
const wire = @import("cell_wire.zig");

pub const magic: u16 = 0x5C5C;
pub const header_size: usize = 12;
pub const max_payload: usize = 238;
pub const sig_size: usize = 64;
pub const signed_cell_size: usize = wire.cell_size + sig_size;
pub const frames_per_cell: usize = 5;
pub const total_size: usize = header_size + max_payload;
pub const flag_signed: u8 = 0x01;
pub const reasm_slots: usize = 6;
pub const reasm_ttl_ms: u64 = 1000;

pub const Frame = extern struct {
    bytes: [total_size]u8,
    len: u16,
};

pub const ReasmSlot = extern struct {
    occupied: bool,
    sender_mac: [6]u8,
    cell_id: u32,
    frame_count: u8,
    received_mask: u8,
    first_seen_ms: u64,
    buf: [signed_cell_size]u8,
};

pub const Reasm = extern struct {
    slots: [reasm_slots]ReasmSlot,
    total_pushed: u32,
    total_reassembled: u32,
    total_dropped: u32,
    total_bad_frame: u32,
};

pub export fn cm_frame_split(
    maybe_cell: ?[*]const u8,
    maybe_sig: ?[*]const u8,
    cell_id: u32,
    maybe_out_frames: ?[*]Frame,
) callconv(.c) usize {
    const cell = maybe_cell orelse return 0;
    const sig = maybe_sig orelse return 0;
    const out_frames = maybe_out_frames orelse return 0;

    for (0..frames_per_cell) |i| {
        var f = &out_frames[i];
        const offset: u16 = @intCast(i * max_payload);
        const remaining: u16 = if (offset < signed_cell_size) @intCast(signed_cell_size - offset) else 0;
        const payload_len: u16 = if (remaining > max_payload) max_payload else remaining;

        wire.writeU16(f.bytes[0..2], magic);
        f.bytes[2] = flag_signed;
        f.bytes[3] = @intCast(i);
        f.bytes[4] = @intCast(frames_per_cell);
        f.bytes[5] = 0;
        wire.writeU32(f.bytes[6..10], cell_id);
        wire.writeU16(f.bytes[10..12], offset);

        var written: u16 = 0;
        var src_offset = offset;
        var to_write = payload_len;

        if (src_offset < wire.cell_size) {
            var from_cell: u16 = @intCast(wire.cell_size - src_offset);
            if (from_cell > to_write) from_cell = to_write;
            const dst_start = header_size + @as(usize, written);
            @memcpy(f.bytes[dst_start..][0..from_cell], cell[src_offset..][0..from_cell]);
            written += from_cell;
            src_offset += from_cell;
            to_write -= from_cell;
        }
        if (to_write > 0) {
            const sig_offset = src_offset - wire.cell_size;
            const dst_start = header_size + @as(usize, written);
            @memcpy(f.bytes[dst_start..][0..to_write], sig[sig_offset..][0..to_write]);
            written += to_write;
        }

        f.len = @intCast(header_size + @as(usize, written));
    }
    return frames_per_cell;
}

pub export fn cm_reasm_init(maybe_r: ?*Reasm) callconv(.c) void {
    const r = maybe_r orelse return;
    r.* = std.mem.zeroes(Reasm);
}

fn acquireSlot(r: *Reasm, sender_mac: *const [6]u8, cell_id: u32, now_ms: u64) ?*ReasmSlot {
    var match: ?*ReasmSlot = null;
    var free_slot: ?*ReasmSlot = null;
    var oldest: ?*ReasmSlot = null;
    var oldest_age: u64 = 0;

    for (&r.slots) |*s| {
        if (s.occupied) {
            if (now_ms > s.first_seen_ms and (now_ms - s.first_seen_ms) > reasm_ttl_ms) {
                s.occupied = false;
                r.total_dropped +%= 1;
            }
        }
        if (s.occupied and std.mem.eql(u8, s.sender_mac[0..], sender_mac[0..]) and s.cell_id == cell_id) {
            match = s;
            break;
        }
        if (!s.occupied and free_slot == null) free_slot = s;
        if (s.occupied) {
            const age = if (now_ms > s.first_seen_ms) now_ms - s.first_seen_ms else 0;
            if (oldest == null or age > oldest_age) {
                oldest = s;
                oldest_age = age;
            }
        }
    }

    if (match) |s| return s;
    if (free_slot) |s| {
        initSlot(s, sender_mac, cell_id, now_ms);
        return s;
    }
    if (oldest) |s| {
        initSlot(s, sender_mac, cell_id, now_ms);
        r.total_dropped +%= 1;
        return s;
    }
    return null;
}

fn initSlot(s: *ReasmSlot, sender_mac: *const [6]u8, cell_id: u32, now_ms: u64) void {
    @memcpy(s.sender_mac[0..], sender_mac[0..]);
    s.cell_id = cell_id;
    s.frame_count = 0;
    s.received_mask = 0;
    s.first_seen_ms = now_ms;
    s.occupied = true;
    @memset(s.buf[0..], 0);
}

pub export fn cm_reasm_push(
    maybe_r: ?*Reasm,
    maybe_frame_bytes: ?[*]const u8,
    frame_len: usize,
    maybe_sender_mac: ?[*]const u8,
    now_ms: u64,
    maybe_out_cell: ?[*]u8,
    maybe_out_sig: ?[*]u8,
) callconv(.c) c_int {
    const r = maybe_r orelse return 2;
    const frame_bytes = maybe_frame_bytes orelse return 2;
    const sender_mac_ptr = maybe_sender_mac orelse return 2;

    if (frame_len < header_size) {
        r.total_bad_frame +%= 1;
        return 2;
    }
    if (wire.readU16(frame_bytes[0..2]) != magic) {
        r.total_bad_frame +%= 1;
        return 2;
    }

    const frame_seq = frame_bytes[3];
    const frame_count = frame_bytes[4];
    const cell_id = wire.readU32(frame_bytes[6..][0..4]);
    const cell_offset = wire.readU16(frame_bytes[10..][0..2]);
    const payload_len = frame_len - header_size;

    if (frame_count == 0 or frame_count > 8) {
        r.total_bad_frame +%= 1;
        return 2;
    }
    if (frame_seq >= frame_count) {
        r.total_bad_frame +%= 1;
        return 2;
    }
    if (@as(usize, cell_offset) + payload_len > signed_cell_size) {
        r.total_bad_frame +%= 1;
        return 2;
    }

    r.total_pushed +%= 1;

    const sender_mac: *const [6]u8 = @ptrCast(sender_mac_ptr);
    const slot = acquireSlot(r, sender_mac, cell_id, now_ms) orelse return 2;

    if (slot.frame_count == 0) {
        slot.frame_count = frame_count;
    } else if (slot.frame_count != frame_count) {
        slot.occupied = false;
        r.total_bad_frame +%= 1;
        return 2;
    }

    @memcpy(slot.buf[cell_offset..][0..payload_len], frame_bytes[header_size..][0..payload_len]);
    slot.received_mask |= @as(u8, 1) << @intCast(frame_seq);

    const expected_mask = (@as(u8, 1) << @intCast(frame_count)) - 1;
    if ((slot.received_mask & expected_mask) == expected_mask) {
        if (maybe_out_cell) |out_cell| @memcpy(out_cell[0..wire.cell_size], slot.buf[0..wire.cell_size]);
        if (maybe_out_sig) |out_sig| @memcpy(out_sig[0..sig_size], slot.buf[wire.cell_size..][0..sig_size]);
        slot.occupied = false;
        r.total_reassembled +%= 1;
        return 1;
    }
    return 0;
}
