// cell_templog.zig — the temperature logger's pure core.
//
// DS18B20 decoding, the flash record and its ring, the store-and-forward
// window, the batch and ack payload codecs, the send schedule, and the heat
// policy's scripts. No ESP-IDF, no I/O: examples/temp_logger is the glue.
// Layouts and rules are specified in docs/TEMP-LOGGER.md.

const std = @import("std");
const wire = @import("cell_wire.zig");

pub const payload_size: usize = wire.payload_size;

// ── Sample flags ────────────────────────────────────────────────────────

pub const SF_POLICY_REJECT: u8 = 0x01;
pub const SF_VM_ERROR: u8 = 0x02;
pub const SF_SENSOR_ERROR: u8 = 0x04;
pub const SF_POR_SUSPECT: u8 = 0x08;
pub const SF_RECORD_LOST: u8 = 0x10;

/// centi-°C stored when there is no valid reading.
pub const temp_invalid: i16 = std.math.minInt(i16);

// ── CRC-8/MAXIM (Dallas 1-Wire) ─────────────────────────────────────────

fn crc8(bytes: []const u8) u8 {
    var crc: u8 = 0;
    for (bytes) |b| {
        crc ^= b;
        var i: u4 = 0;
        while (i < 8) : (i += 1) {
            crc = if (crc & 1 != 0) (crc >> 1) ^ 0x8C else crc >> 1;
        }
    }
    return crc;
}

pub export fn cm_crc8_maxim(data: ?[*]const u8, len: usize) callconv(.c) u8 {
    const d = data orelse return 0;
    return crc8(d[0..len]);
}

// ── DS18B20 scratchpad ──────────────────────────────────────────────────

pub const DS_OK: i32 = 0;
pub const DS_POR: i32 = 1;
pub const DS_ERR_NULL: i32 = -1;
pub const DS_ERR_NO_DEVICE: i32 = -2;
pub const DS_ERR_CRC: i32 = -3;
pub const DS_ERR_RANGE: i32 = -4;

const ds_raw_min: i16 = -880; // -55 °C in 1/16 °C
const ds_raw_max: i16 = 2000; // +125 °C
const ds_raw_por: i16 = 0x0550; // +85 °C, the value latched at power-on

/// Decode a 9-byte scratchpad to centi-°C. `DS_POR` still writes the value:
/// 85 °C is a real temperature too, so the caller decides whether to retry.
pub export fn cm_ds18b20_decode(sp_ptr: ?[*]const u8, out_centi: ?*i16) callconv(.c) i32 {
    const sp_many = sp_ptr orelse return DS_ERR_NULL;
    const out = out_centi orelse return DS_ERR_NULL;
    const sp = sp_many[0..9];

    // A floating line reads all ones and a shorted one all zeros. All zeros
    // passes the CRC, so it has to be caught before the CRC is trusted.
    if (std.mem.allEqual(u8, sp, 0xFF) or std.mem.allEqual(u8, sp, 0x00)) return DS_ERR_NO_DEVICE;
    if (crc8(sp[0..8]) != sp[8]) return DS_ERR_CRC;

    const raw: i16 = @bitCast(@as(u16, sp[0]) | (@as(u16, sp[1]) << 8));
    if (raw < ds_raw_min or raw > ds_raw_max) return DS_ERR_RANGE;

    // centi = raw * 100 / 16 = raw * 25 / 4, rounded half away from zero.
    const scaled: i32 = @as(i32, raw) * 25;
    const rounded: i32 = if (scaled >= 0) @divTrunc(scaled + 2, 4) else -@divTrunc(-scaled + 2, 4);
    out.* = @intCast(rounded);
    return if (raw == ds_raw_por) DS_POR else DS_OK;
}

// ── Flash record ────────────────────────────────────────────────────────

pub const record_size: usize = 16;
pub const sector_size: u32 = 4096;
pub const records_per_sector: u32 = sector_size / record_size;

pub const Record = extern struct {
    seq: u32,
    boot_id: u32,
    uptime_s: u32,
    centi_c: i16,
    flags: u8,
};

pub export fn cm_tlog_record_encode(rec_ptr: ?*const Record, out_ptr: ?[*]u8) callconv(.c) void {
    const rec = rec_ptr orelse return;
    const out = (out_ptr orelse return)[0..record_size];
    wire.writeU32(out[0..4], rec.seq);
    wire.writeU32(out[4..8], rec.boot_id);
    wire.writeU32(out[8..12], rec.uptime_s);
    wire.writeU16(out[12..14], @bitCast(rec.centi_c));
    out[14] = rec.flags;
    out[15] = crc8(out[0..15]);
}

pub export fn cm_tlog_record_is_erased(bytes_ptr: ?[*]const u8) callconv(.c) bool {
    const bytes = (bytes_ptr orelse return false)[0..record_size];
    return std.mem.allEqual(u8, bytes, 0xFF);
}

/// False for erased flash, a torn write, or a seq no writer could have made.
pub export fn cm_tlog_record_decode(bytes_ptr: ?[*]const u8, out_ptr: ?*Record) callconv(.c) bool {
    const bytes = (bytes_ptr orelse return false)[0..record_size];
    const out = out_ptr orelse return false;
    if (crc8(bytes[0..15]) != bytes[15]) return false;
    const seq = wire.readU32(bytes[0..4]);
    if (seq == 0 or seq == std.math.maxInt(u32)) return false;
    out.* = .{
        .seq = seq,
        .boot_id = wire.readU32(bytes[4..8]),
        .uptime_s = wire.readU32(bytes[8..12]),
        .centi_c = @bitCast(wire.readU16(bytes[12..14])),
        .flags = bytes[14],
    };
    return true;
}

// ── Ring geometry ───────────────────────────────────────────────────────

pub export fn cm_tlog_slot_for_seq(seq: u32, capacity: u32) callconv(.c) u32 {
    if (capacity == 0 or seq == 0) return 0;
    return (seq - 1) % capacity;
}

pub export fn cm_tlog_erase_before_write(seq: u32, capacity: u32) callconv(.c) bool {
    if (capacity == 0 or seq == 0) return false;
    return cm_tlog_slot_for_seq(seq, capacity) % records_per_sector == 0;
}

// ── Log bookkeeping ─────────────────────────────────────────────────────

pub const Log = extern struct {
    capacity: u32,
    /// The seq the next append receives. Always >= 1.
    next_seq: u32,
    /// Oldest record still in flash. Equal to next_seq when the log is empty.
    oldest_seq: u32,
    /// The host holds every seq up to and including this. 0 = nothing.
    acked_through: u32,
    // Recovery scratch: extremes of the valid records fed so far.
    rec_min: u32,
    rec_max: u32,
};

fn usableCapacity(capacity: u32) u32 {
    const whole = capacity - (capacity % records_per_sector);
    // One sector is always being recycled, so a ring needs at least two.
    return if (whole >= 2 * records_per_sector) whole else 0;
}

pub export fn cm_tlog_init(log_ptr: ?*Log, capacity: u32) callconv(.c) void {
    const log = log_ptr orelse return;
    log.* = .{
        .capacity = usableCapacity(capacity),
        .next_seq = 1,
        .oldest_seq = 1,
        .acked_through = 0,
        .rec_min = 0,
        .rec_max = 0,
    };
}

/// Reserve the next seq. The caller erases the sector first when
/// cm_tlog_erase_before_write says so, then writes the record. A failed write
/// still consumes the seq; it reads back later as a lost record.
pub export fn cm_tlog_append(log_ptr: ?*Log) callconv(.c) u32 {
    const log = log_ptr orelse return 0;
    if (log.capacity == 0 or log.next_seq == std.math.maxInt(u32)) return 0;
    const seq = log.next_seq;
    const lap = log.capacity - records_per_sector;
    if (cm_tlog_erase_before_write(seq, log.capacity) and seq > lap) {
        // The erased sector held seq - capacity .. seq - capacity + 255, so
        // the oldest survivor is the first seq of the sector after it.
        const survivor = seq - lap;
        if (survivor > log.oldest_seq) log.oldest_seq = survivor;
    }
    log.next_seq = seq + 1;
    return seq;
}

/// Give up on next_seq without writing it — its slot is not erased.
pub export fn cm_tlog_skip_seq(log_ptr: ?*Log) callconv(.c) u32 {
    return cm_tlog_append(log_ptr);
}

pub export fn cm_tlog_pending_first(log_ptr: ?*const Log) callconv(.c) u32 {
    const log = log_ptr orelse return 0;
    return @max(log.acked_through + 1, log.oldest_seq);
}

pub export fn cm_tlog_pending(log_ptr: ?*const Log) callconv(.c) u32 {
    const log = log_ptr orelse return 0;
    const first = cm_tlog_pending_first(log);
    return if (log.next_seq > first) log.next_seq - first else 0;
}

/// Seqs up to this were overwritten before the host acknowledged them.
pub export fn cm_tlog_lost_through(log_ptr: ?*const Log) callconv(.c) u32 {
    const log = log_ptr orelse return 0;
    return if (log.acked_through + 1 < log.oldest_seq) log.oldest_seq - 1 else 0;
}

/// Set the delivery pointer. Lower is allowed — that is a replay request.
pub export fn cm_tlog_apply_ack(log_ptr: ?*Log, acked_through: u32) callconv(.c) u32 {
    const log = log_ptr orelse return 0;
    log.acked_through = @min(acked_through, log.next_seq - 1);
    return log.acked_through;
}

// ── Recovery ────────────────────────────────────────────────────────────

pub export fn cm_tlog_recover_begin(log_ptr: ?*Log, capacity: u32) callconv(.c) void {
    cm_tlog_init(log_ptr, capacity);
}

/// Feed one slot's decoded record. A record is believed only when its seq
/// belongs in the slot it was found in.
pub export fn cm_tlog_recover_feed(log_ptr: ?*Log, slot: u32, rec_ptr: ?*const Record) callconv(.c) void {
    const log = log_ptr orelse return;
    const rec = rec_ptr orelse return;
    if (log.capacity == 0 or slot >= log.capacity) return;
    if (cm_tlog_slot_for_seq(rec.seq, log.capacity) != slot) return;
    if (log.rec_max == 0 or rec.seq > log.rec_max) log.rec_max = rec.seq;
    if (log.rec_min == 0 or rec.seq < log.rec_min) log.rec_min = rec.seq;
}

/// `persisted_acked` and `seq_floor` come from NVS. The floor keeps seqs
/// moving forward when the data partition was wiped but NVS was not.
pub export fn cm_tlog_recover_finish(log_ptr: ?*Log, persisted_acked: u32, seq_floor: u32) callconv(.c) void {
    const log = log_ptr orelse return;
    if (log.rec_max == 0) {
        const start = @max(seq_floor, 1);
        log.next_seq = start;
        log.oldest_seq = start;
    } else {
        log.next_seq = @max(log.rec_max + 1, seq_floor);
        log.oldest_seq = log.rec_min;
    }
    log.acked_through = @min(persisted_acked, log.next_seq - 1);
    log.rec_min = 0;
    log.rec_max = 0;
}

// ── Batch payload ───────────────────────────────────────────────────────

pub const batch_header_size: usize = 40;
pub const sample_wire_size: usize = 8;
pub const batch_max_samples: u16 = @intCast((payload_size - batch_header_size) / sample_wire_size);
pub const batch_version: u8 = 0;

pub const BatchHeader = extern struct {
    version: u8,
    flags: u8,
    count: u16,
    first_seq: u32,
    boot_id: u32,
    boot_now: u32,
    uptime_now_s: u32,
    boot_epoch_s: u32,
    lost_through: u32,
    sample_interval_s: u32,
    policy_min_centi: i16,
    policy_max_centi: i16,
    log_id: u32,
};

const BOff = struct {
    const version = 0;
    const flags = 1;
    const count = 2;
    const first_seq = 4;
    const boot_id = 8;
    const boot_now = 12;
    const uptime_now_s = 16;
    const boot_epoch_s = 20;
    const lost_through = 24;
    const sample_interval_s = 28;
    const policy_min = 32;
    const policy_max = 34;
    const log_id = 36;
};

fn payloadOf(p: ?[*]u8) ?*[payload_size]u8 {
    const many = p orelse return null;
    return many[0..payload_size];
}

/// Write the header with count = 0 and zero everything after it. The caller
/// sets `first_seq` and `boot_id` for the first sample it will add.
pub export fn cm_tlog_batch_begin(p_ptr: ?[*]u8, hdr_ptr: ?*const BatchHeader) callconv(.c) void {
    const p = payloadOf(p_ptr) orelse return;
    const h = hdr_ptr orelse return;
    @memset(p, 0);
    p[BOff.version] = batch_version;
    p[BOff.flags] = h.flags;
    wire.writeU16(p[BOff.count..][0..2], 0);
    wire.writeU32(p[BOff.first_seq..][0..4], h.first_seq);
    wire.writeU32(p[BOff.boot_id..][0..4], h.boot_id);
    wire.writeU32(p[BOff.boot_now..][0..4], h.boot_now);
    wire.writeU32(p[BOff.uptime_now_s..][0..4], h.uptime_now_s);
    wire.writeU32(p[BOff.boot_epoch_s..][0..4], h.boot_epoch_s);
    wire.writeU32(p[BOff.lost_through..][0..4], h.lost_through);
    wire.writeU32(p[BOff.sample_interval_s..][0..4], h.sample_interval_s);
    wire.writeU16(p[BOff.policy_min..][0..2], @bitCast(h.policy_min_centi));
    wire.writeU16(p[BOff.policy_max..][0..2], @bitCast(h.policy_max_centi));
    wire.writeU32(p[BOff.log_id..][0..4], h.log_id);
}

fn putSample(p: *[payload_size]u8, uptime_s: u32, centi: i16, flags: u8) void {
    const n = wire.readU16(p[BOff.count..][0..2]);
    const off = batch_header_size + @as(usize, n) * sample_wire_size;
    wire.writeU32(p[off..][0..4], uptime_s);
    wire.writeU16(p[off + 4 ..][0..2], @bitCast(centi));
    p[off + 6] = flags;
    p[off + 7] = 0;
    wire.writeU16(p[BOff.count..][0..2], n + 1);
}

fn nextSeqFits(p: *const [payload_size]u8, seq: u32) bool {
    const n = wire.readU16(p[BOff.count..][0..2]);
    if (n >= batch_max_samples) return false;
    return seq == wire.readU32(p[BOff.first_seq..][0..4]) +% n;
}

/// Append a record. False — and nothing written — when the batch is full,
/// the seq is not the next one, or the record is from another boot.
pub export fn cm_tlog_batch_add(p_ptr: ?[*]u8, rec_ptr: ?*const Record) callconv(.c) bool {
    const p = payloadOf(p_ptr) orelse return false;
    const rec = rec_ptr orelse return false;
    if (!nextSeqFits(p, rec.seq)) return false;
    if (rec.boot_id != wire.readU32(p[BOff.boot_id..][0..4])) return false;
    putSample(p, rec.uptime_s, rec.centi_c, rec.flags);
    return true;
}

/// Append a placeholder for a seq whose flash record could not be read.
pub export fn cm_tlog_batch_add_lost(p_ptr: ?[*]u8, seq: u32) callconv(.c) bool {
    const p = payloadOf(p_ptr) orelse return false;
    if (!nextSeqFits(p, seq)) return false;
    putSample(p, 0, temp_invalid, SF_RECORD_LOST | SF_SENSOR_ERROR);
    return true;
}

pub export fn cm_tlog_batch_count(p_ptr: ?[*]const u8) callconv(.c) u16 {
    const p = p_ptr orelse return 0;
    return wire.readU16(p[BOff.count..][0..2]);
}

pub export fn cm_tlog_batch_used_bytes(p_ptr: ?[*]const u8) callconv(.c) usize {
    return batch_header_size + @as(usize, cm_tlog_batch_count(p_ptr)) * sample_wire_size;
}

pub export fn cm_tlog_batch_decode_header(p_ptr: ?[*]const u8, len: usize, out_ptr: ?*BatchHeader) callconv(.c) bool {
    const p_many = p_ptr orelse return false;
    const out = out_ptr orelse return false;
    if (len < batch_header_size) return false;
    const p = p_many[0..len];
    if (p[BOff.version] != batch_version) return false;
    const count = wire.readU16(p[BOff.count..][0..2]);
    if (count > batch_max_samples) return false;
    if (len < batch_header_size + @as(usize, count) * sample_wire_size) return false;
    out.* = .{
        .version = p[BOff.version],
        .flags = p[BOff.flags],
        .count = count,
        .first_seq = wire.readU32(p[BOff.first_seq..][0..4]),
        .boot_id = wire.readU32(p[BOff.boot_id..][0..4]),
        .boot_now = wire.readU32(p[BOff.boot_now..][0..4]),
        .uptime_now_s = wire.readU32(p[BOff.uptime_now_s..][0..4]),
        .boot_epoch_s = wire.readU32(p[BOff.boot_epoch_s..][0..4]),
        .lost_through = wire.readU32(p[BOff.lost_through..][0..4]),
        .sample_interval_s = wire.readU32(p[BOff.sample_interval_s..][0..4]),
        .policy_min_centi = @bitCast(wire.readU16(p[BOff.policy_min..][0..2])),
        .policy_max_centi = @bitCast(wire.readU16(p[BOff.policy_max..][0..2])),
        .log_id = wire.readU32(p[BOff.log_id..][0..4]),
    };
    return true;
}

/// Sample `i` as a record: seq = first_seq + i, boot from the header.
pub export fn cm_tlog_batch_sample(p_ptr: ?[*]const u8, len: usize, i: u16, out_ptr: ?*Record) callconv(.c) bool {
    const out = out_ptr orelse return false;
    var h: BatchHeader = undefined;
    if (!cm_tlog_batch_decode_header(p_ptr, len, &h)) return false;
    if (i >= h.count) return false;
    const p = p_ptr.?;
    const off = batch_header_size + @as(usize, i) * sample_wire_size;
    out.* = .{
        .seq = h.first_seq +% i,
        .boot_id = h.boot_id,
        .uptime_s = wire.readU32(p[off..][0..4]),
        .centi_c = @bitCast(wire.readU16(p[off + 4 ..][0..2])),
        .flags = p[off + 6],
    };
    return true;
}

// ── Ack payload ─────────────────────────────────────────────────────────

pub const ack_size: usize = 16;
pub const ack_version: u8 = 0;

pub export fn cm_tlog_ack_encode(p_ptr: ?[*]u8, mac_ptr: ?[*]const u8, acked_through: u32, host_unix_s: u32) callconv(.c) void {
    const p = payloadOf(p_ptr) orelse return;
    const mac = (mac_ptr orelse return)[0..6];
    @memset(p, 0);
    p[0] = ack_version;
    @memcpy(p[2..8], mac);
    wire.writeU32(p[8..12], acked_through);
    wire.writeU32(p[12..16], host_unix_s);
}

pub export fn cm_tlog_ack_decode(
    p_ptr: ?[*]const u8,
    len: usize,
    out_mac: ?[*]u8,
    out_acked: ?*u32,
    out_host_unix: ?*u32,
) callconv(.c) bool {
    const p_many = p_ptr orelse return false;
    const mac = out_mac orelse return false;
    const acked = out_acked orelse return false;
    const host = out_host_unix orelse return false;
    if (len < ack_size) return false;
    const p = p_many[0..ack_size];
    if (p[0] != ack_version) return false;
    @memcpy(mac[0..6], p[2..8]);
    acked.* = wire.readU32(p[8..12]);
    host.* = wire.readU32(p[12..16]);
    return true;
}

// ── Send schedule ───────────────────────────────────────────────────────
//
// One rule: send when something is pending and the deadline has passed. An
// unanswered send pushes the deadline out and doubles the wait, so a node
// out of range stops shouting; an ack pulls it back to now, so a node that
// comes back into range drains its backlog batch after batch.

pub const sched_min_backoff_ms: u32 = 2000;

pub const Sched = extern struct {
    next_due_ms: u64,
    backoff_ms: u32,
};

pub export fn cm_tlog_sched_init(s_ptr: ?*Sched) callconv(.c) void {
    const s = s_ptr orelse return;
    s.* = .{ .next_due_ms = 0, .backoff_ms = sched_min_backoff_ms };
}

pub export fn cm_tlog_sched_should_send(s_ptr: ?*const Sched, now_ms: u64, pending: u32) callconv(.c) bool {
    const s = s_ptr orelse return false;
    return pending > 0 and now_ms >= s.next_due_ms;
}

pub export fn cm_tlog_sched_on_sent(s_ptr: ?*Sched, now_ms: u64, max_backoff_ms: u32) callconv(.c) void {
    const s = s_ptr orelse return;
    const ceiling = @max(max_backoff_ms, sched_min_backoff_ms);
    s.next_due_ms = now_ms + s.backoff_ms;
    s.backoff_ms = @min(s.backoff_ms *| 2, ceiling);
}

pub export fn cm_tlog_sched_on_ack(s_ptr: ?*Sched, now_ms: u64) callconv(.c) void {
    const s = s_ptr orelse return;
    s.next_due_ms = now_ms;
    s.backoff_ms = sched_min_backoff_ms;
}

// ── Script numbers and the heat policy ──────────────────────────────────

const OP_0: u8 = 0x00;
const OP_1NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51;
const OP_WITHIN: u8 = 0xa5;

/// Push `value` as a minimally encoded script number. Returns the bytes
/// written, or 0 if `out` is null or too small.
pub export fn cm_script_num_push(value: i32, out_ptr: ?[*]u8, cap: usize) callconv(.c) usize {
    const out = out_ptr orelse return 0;
    if (value == 0) {
        if (cap < 1) return 0;
        out[0] = OP_0;
        return 1;
    }
    if (value == -1) {
        if (cap < 1) return 0;
        out[0] = OP_1NEGATE;
        return 1;
    }
    if (value >= 1 and value <= 16) {
        if (cap < 1) return 0;
        out[0] = OP_1 + @as(u8, @intCast(value - 1));
        return 1;
    }

    // Little-endian magnitude; the top bit of the last byte is the sign.
    var mag: u32 = @abs(value);
    var bytes: [5]u8 = undefined;
    var n: usize = 0;
    while (mag != 0) : (n += 1) {
        bytes[n] = @truncate(mag);
        mag >>= 8;
    }
    if (bytes[n - 1] & 0x80 != 0) {
        bytes[n] = if (value < 0) 0x80 else 0x00;
        n += 1;
    } else if (value < 0) {
        bytes[n - 1] |= 0x80;
    }
    if (cap < n + 1) return 0;
    out[0] = @intCast(n); // OP_PUSHBYTES_n
    @memcpy(out[1 .. n + 1], bytes[0..n]);
    return n + 1;
}

/// `<min> <max+1> OP_WITHIN` — accepts min ≤ x ≤ max. 0 if the band is empty.
pub export fn cm_tlog_policy_lock(min_centi: i16, max_centi: i16, out_ptr: ?[*]u8, cap: usize) callconv(.c) usize {
    const out = out_ptr orelse return 0;
    if (min_centi > max_centi) return 0;
    const a = cm_script_num_push(min_centi, out, cap);
    if (a == 0) return 0;
    const b = cm_script_num_push(@as(i32, max_centi) + 1, out + a, cap - a);
    if (b == 0 or a + b >= cap) return 0;
    out[a + b] = OP_WITHIN;
    return a + b + 1;
}

pub export fn cm_tlog_policy_unlock(centi: i16, out_ptr: ?[*]u8, cap: usize) callconv(.c) usize {
    return cm_script_num_push(centi, out_ptr, cap);
}
