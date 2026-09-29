// Tests for cell_templog.zig — the temperature-logger core.
//
// Written against docs/TEMP-LOGGER.md before the module existed. The byte
// layouts are spelled out by hand from that spec, not captured from the
// encoder, so a wrong offset in the encoder cannot also be the expectation.

const std = @import("std");
const t = @import("cell_templog.zig");

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

// ── CRC-8 (Dallas/Maxim) ────────────────────────────────────────────────

test "crc8 matches the published CRC-8/MAXIM check value" {
    const s = "123456789";
    try expectEqual(@as(u8, 0xA1), t.cm_crc8_maxim(s.ptr, s.len));
}

test "crc8 matches the Maxim AN27 ROM-code example" {
    const rom = [_]u8{ 0x02, 0x1C, 0xB8, 0x01, 0x00, 0x00, 0x00 };
    try expectEqual(@as(u8, 0xA2), t.cm_crc8_maxim(&rom, rom.len));
}

test "crc8 of nothing is zero" {
    try expectEqual(@as(u8, 0), t.cm_crc8_maxim(null, 0));
}

// ── DS18B20 scratchpad ──────────────────────────────────────────────────

fn scratchpad(raw: i16) [9]u8 {
    const u: u16 = @bitCast(raw);
    var sp = [9]u8{ @truncate(u), @truncate(u >> 8), 0x4B, 0x46, 0x7F, 0xFF, 0x0C, 0x10, 0 };
    sp[8] = t.cm_crc8_maxim(&sp, 8);
    return sp;
}

fn decodeRaw(raw: i16) !i16 {
    const sp = scratchpad(raw);
    var c: i16 = 0;
    try expectEqual(t.DS_OK, t.cm_ds18b20_decode(&sp, &c));
    return c;
}

test "ds18b20 decodes the datasheet table to centi-degrees, rounding half away from zero" {
    try expectEqual(@as(i16, 12500), try decodeRaw(0x07D0)); // +125
    try expectEqual(@as(i16, 2506), try decodeRaw(0x0191)); // +25.0625
    try expectEqual(@as(i16, 1013), try decodeRaw(0x00A2)); // +10.125
    try expectEqual(@as(i16, 50), try decodeRaw(0x0008)); // +0.5
    try expectEqual(@as(i16, 0), try decodeRaw(0x0000)); // 0 — still a valid reading
    try expectEqual(@as(i16, -50), try decodeRaw(@bitCast(@as(u16, 0xFFF8)))); // -0.5
    try expectEqual(@as(i16, -1013), try decodeRaw(@bitCast(@as(u16, 0xFF5E)))); // -10.125
    try expectEqual(@as(i16, -2506), try decodeRaw(@bitCast(@as(u16, 0xFE6F)))); // -25.0625
    try expectEqual(@as(i16, -5500), try decodeRaw(@bitCast(@as(u16, 0xFC90)))); // -55
}

test "ds18b20 flags its 85 degree power-on value instead of passing it off as a reading" {
    const sp = scratchpad(0x0550);
    var c: i16 = 0;
    try expectEqual(t.DS_POR, t.cm_ds18b20_decode(&sp, &c));
    try expectEqual(@as(i16, 8500), c);
}

test "ds18b20 rejects a scratchpad whose CRC does not match" {
    var sp = scratchpad(0x0191);
    sp[0] ^= 0x01;
    var c: i16 = 0;
    try expectEqual(t.DS_ERR_CRC, t.cm_ds18b20_decode(&sp, &c));
}

test "ds18b20 treats a line stuck high or low as no device, even though zeros pass CRC" {
    var c: i16 = 0;
    const high = [_]u8{0xFF} ** 9;
    const low = [_]u8{0x00} ** 9;
    try expectEqual(@as(u8, 0), t.cm_crc8_maxim(&low, 8)); // the trap: all-zero is CRC-valid
    try expectEqual(t.DS_ERR_NO_DEVICE, t.cm_ds18b20_decode(&high, &c));
    try expectEqual(t.DS_ERR_NO_DEVICE, t.cm_ds18b20_decode(&low, &c));
}

test "ds18b20 rejects a CRC-valid value outside the part's -55..125 range" {
    const sp = scratchpad(0x0800); // +128
    var c: i16 = 0;
    try expectEqual(t.DS_ERR_RANGE, t.cm_ds18b20_decode(&sp, &c));
}

test "ds18b20 null arguments are refused" {
    var c: i16 = 0;
    try expectEqual(t.DS_ERR_NULL, t.cm_ds18b20_decode(null, &c));
    const sp = scratchpad(0);
    try expectEqual(t.DS_ERR_NULL, t.cm_ds18b20_decode(&sp, null));
}

// ── Flash record ────────────────────────────────────────────────────────

test "record encodes to the 16-byte layout in the spec" {
    const rec = t.Record{ .seq = 0x01020304, .boot_id = 7, .uptime_s = 0x00000E10, .centi_c = -200, .flags = 0x05 };
    var buf: [t.record_size]u8 = undefined;
    t.cm_tlog_record_encode(&rec, &buf);
    const want_prefix = [_]u8{
        0x04, 0x03, 0x02, 0x01, // seq
        0x07, 0x00, 0x00, 0x00, // boot_id
        0x10, 0x0E, 0x00, 0x00, // uptime_s = 3600
        0x38, 0xFF, // centi_c = -200
        0x05, // flags
    };
    try expectEqualSlices(u8, &want_prefix, buf[0..15]);
    try expectEqual(t.cm_crc8_maxim(&buf, 15), buf[15]);
}

test "record round-trips" {
    const rec = t.Record{ .seq = 42, .boot_id = 3, .uptime_s = 12345, .centi_c = 2506, .flags = t.SF_POLICY_REJECT };
    var buf: [t.record_size]u8 = undefined;
    t.cm_tlog_record_encode(&rec, &buf);
    var out: t.Record = undefined;
    try expect(t.cm_tlog_record_decode(&buf, &out));
    try expectEqual(rec.seq, out.seq);
    try expectEqual(rec.boot_id, out.boot_id);
    try expectEqual(rec.uptime_s, out.uptime_s);
    try expectEqual(rec.centi_c, out.centi_c);
    try expectEqual(rec.flags, out.flags);
}

test "erased flash is recognised and is not a record" {
    const erased = [_]u8{0xFF} ** t.record_size;
    var out: t.Record = undefined;
    try expect(t.cm_tlog_record_is_erased(&erased));
    try expect(!t.cm_tlog_record_decode(&erased, &out));
}

test "a torn record fails its CRC" {
    const rec = t.Record{ .seq = 9, .boot_id = 1, .uptime_s = 60, .centi_c = 1800, .flags = 0 };
    var buf: [t.record_size]u8 = undefined;
    t.cm_tlog_record_encode(&rec, &buf);
    buf[9] |= 0x80; // one byte half-programmed
    var out: t.Record = undefined;
    try expect(!t.cm_tlog_record_is_erased(&buf));
    try expect(!t.cm_tlog_record_decode(&buf, &out));
}

test "seq 0 is never a valid record" {
    var buf: [t.record_size]u8 = [_]u8{0} ** t.record_size;
    buf[15] = t.cm_crc8_maxim(&buf, 15);
    var out: t.Record = undefined;
    try expect(!t.cm_tlog_record_decode(&buf, &out));
}

// ── Ring geometry ───────────────────────────────────────────────────────

test "slots count from seq 1 and wrap at capacity" {
    try expectEqual(@as(u32, 0), t.cm_tlog_slot_for_seq(1, 512));
    try expectEqual(@as(u32, 255), t.cm_tlog_slot_for_seq(256, 512));
    try expectEqual(@as(u32, 256), t.cm_tlog_slot_for_seq(257, 512));
    try expectEqual(@as(u32, 511), t.cm_tlog_slot_for_seq(512, 512));
    try expectEqual(@as(u32, 0), t.cm_tlog_slot_for_seq(513, 512));
}

test "a sector is erased exactly when a write lands on its first slot" {
    try expect(t.cm_tlog_erase_before_write(1, 512));
    try expect(!t.cm_tlog_erase_before_write(2, 512));
    try expect(!t.cm_tlog_erase_before_write(256, 512));
    try expect(t.cm_tlog_erase_before_write(257, 512));
    try expect(t.cm_tlog_erase_before_write(513, 512));
}

// ── Log bookkeeping ─────────────────────────────────────────────────────

test "a fresh log is empty and has nothing to send" {
    var log: t.Log = undefined;
    t.cm_tlog_init(&log, 512);
    try expectEqual(@as(u32, 512), log.capacity);
    try expectEqual(@as(u32, 1), log.next_seq);
    try expectEqual(@as(u32, 1), log.oldest_seq);
    try expectEqual(@as(u32, 0), log.acked_through);
    try expectEqual(@as(u32, 0), t.cm_tlog_pending(&log));
    try expectEqual(@as(u32, 0), t.cm_tlog_lost_through(&log));
}

test "capacity rounds down to whole sectors and a ring needs at least two" {
    var log: t.Log = undefined;
    t.cm_tlog_init(&log, 1000);
    try expectEqual(@as(u32, 768), log.capacity);
    t.cm_tlog_init(&log, 511);
    try expectEqual(@as(u32, 0), log.capacity);
    try expectEqual(@as(u32, 0), t.cm_tlog_append(&log)); // unusable, refuses
}

test "appends hand out consecutive seqs and are pending until acked" {
    var log: t.Log = undefined;
    t.cm_tlog_init(&log, 512);
    var i: u32 = 1;
    while (i <= 300) : (i += 1) try expectEqual(i, t.cm_tlog_append(&log));
    try expectEqual(@as(u32, 301), log.next_seq);
    try expectEqual(@as(u32, 1), log.oldest_seq);
    try expectEqual(@as(u32, 300), t.cm_tlog_pending(&log));
    try expectEqual(@as(u32, 1), t.cm_tlog_pending_first(&log));

    try expectEqual(@as(u32, 120), t.cm_tlog_apply_ack(&log, 120));
    try expectEqual(@as(u32, 180), t.cm_tlog_pending(&log));
    try expectEqual(@as(u32, 121), t.cm_tlog_pending_first(&log));
}

test "wrapping erases the oldest sector and says what was lost before delivery" {
    var log: t.Log = undefined;
    t.cm_tlog_init(&log, 512);
    var i: u32 = 0;
    while (i < 512) : (i += 1) _ = t.cm_tlog_append(&log);
    try expectEqual(@as(u32, 1), log.oldest_seq); // full, nothing erased yet
    try expectEqual(@as(u32, 513), t.cm_tlog_append(&log)); // lands on slot 0: erases 1..256
    try expectEqual(@as(u32, 257), log.oldest_seq);

    // Nothing was ever acked: 1..256 are gone without having been delivered.
    try expectEqual(@as(u32, 256), t.cm_tlog_lost_through(&log));
    try expectEqual(@as(u32, 257), t.cm_tlog_pending_first(&log));
    try expectEqual(@as(u32, 257), t.cm_tlog_pending(&log));

    // Once the host has everything up to the erased sector, nothing was lost.
    _ = t.cm_tlog_apply_ack(&log, 256);
    try expectEqual(@as(u32, 0), t.cm_tlog_lost_through(&log));
}

test "an ack can lower the pointer, which is how the host asks for a replay" {
    var log: t.Log = undefined;
    t.cm_tlog_init(&log, 512);
    var i: u32 = 0;
    while (i < 50) : (i += 1) _ = t.cm_tlog_append(&log);
    _ = t.cm_tlog_apply_ack(&log, 50);
    try expectEqual(@as(u32, 0), t.cm_tlog_pending(&log));
    try expectEqual(@as(u32, 10), t.cm_tlog_apply_ack(&log, 10));
    try expectEqual(@as(u32, 40), t.cm_tlog_pending(&log));
    try expectEqual(@as(u32, 11), t.cm_tlog_pending_first(&log));
}

test "an ack beyond what exists is clamped to the newest record" {
    var log: t.Log = undefined;
    t.cm_tlog_init(&log, 512);
    _ = t.cm_tlog_append(&log);
    _ = t.cm_tlog_append(&log);
    try expectEqual(@as(u32, 2), t.cm_tlog_apply_ack(&log, 9999));
}

// ── Recovery from flash ─────────────────────────────────────────────────

const SimFlash = struct {
    const cap = 512;
    bytes: [cap * t.record_size]u8 = [_]u8{0xFF} ** (cap * t.record_size),

    fn slot(self: *SimFlash, s: u32) *[t.record_size]u8 {
        return self.bytes[s * t.record_size ..][0..t.record_size];
    }

    // Mirror of what the firmware does: bookkeeping first, erase, then write.
    fn appendSample(self: *SimFlash, log: *t.Log, boot: u32, centi: i16) u32 {
        const seq = t.cm_tlog_append(log);
        const s = t.cm_tlog_slot_for_seq(seq, log.capacity);
        if (t.cm_tlog_erase_before_write(seq, log.capacity)) {
            const first = s - (s % t.records_per_sector);
            @memset(self.bytes[first * t.record_size ..][0 .. t.records_per_sector * t.record_size], 0xFF);
        }
        const rec = t.Record{ .seq = seq, .boot_id = boot, .uptime_s = seq * 60, .centi_c = centi, .flags = 0 };
        t.cm_tlog_record_encode(&rec, self.slot(s));
        return seq;
    }

    fn recover(self: *SimFlash, log: *t.Log, acked: u32, floor: u32) void {
        t.cm_tlog_recover_begin(log, cap);
        var s: u32 = 0;
        while (s < cap) : (s += 1) {
            var rec: t.Record = undefined;
            if (t.cm_tlog_record_decode(self.slot(s), &rec)) t.cm_tlog_recover_feed(log, s, &rec);
        }
        t.cm_tlog_recover_finish(log, acked, floor);
    }
};

test "recovery after a wrap finds the live window and the persisted ack" {
    var flash = SimFlash{};
    var log: t.Log = undefined;
    t.cm_tlog_init(&log, SimFlash.cap);
    var i: u32 = 0;
    while (i < 600) : (i += 1) _ = flash.appendSample(&log, 1, 1500);

    var again: t.Log = undefined;
    flash.recover(&again, 450, 0);
    try expectEqual(@as(u32, 601), again.next_seq);
    try expectEqual(@as(u32, 257), again.oldest_seq);
    try expectEqual(@as(u32, 450), again.acked_through);
    try expectEqual(@as(u32, 150), t.cm_tlog_pending(&again));
}

test "recovery of blank flash starts at seq 1" {
    var flash = SimFlash{};
    var log: t.Log = undefined;
    flash.recover(&log, 0, 0);
    try expectEqual(@as(u32, 1), log.next_seq);
    try expectEqual(@as(u32, 1), log.oldest_seq);
    try expectEqual(@as(u32, 0), t.cm_tlog_pending(&log));
}

test "recovery ignores a CRC-valid record sitting in the wrong slot" {
    var flash = SimFlash{};
    var log: t.Log = undefined;
    t.cm_tlog_init(&log, SimFlash.cap);
    var i: u32 = 0;
    while (i < 10) : (i += 1) _ = flash.appendSample(&log, 1, 1500);
    // A stray record claiming seq 5000 written into slot 20.
    const stray = t.Record{ .seq = 5000, .boot_id = 1, .uptime_s = 1, .centi_c = 1, .flags = 0 };
    t.cm_tlog_record_encode(&stray, flash.slot(20));

    var again: t.Log = undefined;
    flash.recover(&again, 0, 0);
    try expectEqual(@as(u32, 11), again.next_seq);
}

test "a seq never goes backwards, even when the data partition was wiped" {
    var flash = SimFlash{};
    var log: t.Log = undefined;
    flash.recover(&log, 900, 901); // NVS remembers; flash is blank
    try expectEqual(@as(u32, 901), log.next_seq);
    try expectEqual(@as(u32, 901), log.oldest_seq);
    try expectEqual(@as(u32, 900), log.acked_through);
    try expectEqual(@as(u32, 0), t.cm_tlog_pending(&log));
    try expectEqual(@as(u32, 901), t.cm_tlog_append(&log));
}

test "the NVS floor wins over older records still in flash" {
    // NVS is newer than the data partition (say, an old image restored):
    // flash tops out at 10, but seqs up to 499 were already issued.
    var flash = SimFlash{};
    var log: t.Log = undefined;
    t.cm_tlog_init(&log, SimFlash.cap);
    var i: u32 = 0;
    while (i < 10) : (i += 1) _ = flash.appendSample(&log, 1, 1500);
    var again: t.Log = undefined;
    flash.recover(&again, 499, 500);
    try expectEqual(@as(u32, 500), again.next_seq);
    try expectEqual(@as(u32, 499), again.acked_through);
}

test "a persisted ack beyond the recovered log is clamped" {
    var flash = SimFlash{};
    var log: t.Log = undefined;
    t.cm_tlog_init(&log, SimFlash.cap);
    var i: u32 = 0;
    while (i < 5) : (i += 1) _ = flash.appendSample(&log, 1, 1500);
    var again: t.Log = undefined;
    flash.recover(&again, 77, 0);
    try expectEqual(@as(u32, 5), again.acked_through);
}

test "a torn head record is skipped and its seq burned, never rewritten" {
    var flash = SimFlash{};
    var log: t.Log = undefined;
    t.cm_tlog_init(&log, SimFlash.cap);
    var i: u32 = 0;
    while (i < 20) : (i += 1) _ = flash.appendSample(&log, 1, 1500);
    // Power fails while seq 21 is being programmed.
    const seq21 = t.cm_tlog_append(&log);
    const s = t.cm_tlog_slot_for_seq(seq21, log.capacity);
    flash.slot(s)[0] = 0x15; // first byte written, rest still erased

    var again: t.Log = undefined;
    flash.recover(&again, 0, 0);
    try expectEqual(@as(u32, 21), again.next_seq); // 21 is not a valid record
    // The firmware sees the slot is not erased and burns the seq: flash cannot
    // be reprogrammed without erasing the whole sector.
    try expect(!t.cm_tlog_record_is_erased(flash.slot(s)));
    try expectEqual(@as(u32, 21), t.cm_tlog_skip_seq(&again));
    try expectEqual(@as(u32, 22), again.next_seq);
    try expectEqual(@as(u32, 21), t.cm_tlog_pending(&again)); // 21 stays in the window, as lost
}

// ── Batch payload ───────────────────────────────────────────────────────

fn header(first: u32, boot: u32) t.BatchHeader {
    return .{
        .version = 0,
        .flags = 0,
        .count = 0,
        .first_seq = first,
        .boot_id = boot,
        .boot_now = 4,
        .uptime_now_s = 7200,
        .boot_epoch_s = 1790000000,
        .lost_through = 0,
        .sample_interval_s = 60,
        .policy_min_centi = -200,
        .policy_max_centi = 2800,
        .log_id = 0xA1B2C3D4,
    };
}

test "a batch encodes to the byte layout in the spec" {
    var p = [_]u8{0xEE} ** t.payload_size;
    const h = header(100, 3);
    t.cm_tlog_batch_begin(&p, &h);
    try expect(t.cm_tlog_batch_add(&p, &t.Record{ .seq = 100, .boot_id = 3, .uptime_s = 60, .centi_c = 2506, .flags = 0 }));
    try expect(t.cm_tlog_batch_add(&p, &t.Record{ .seq = 101, .boot_id = 3, .uptime_s = 120, .centi_c = -200, .flags = t.SF_POLICY_REJECT }));

    const want = [_]u8{
        0x00, // version
        0x00, // flags
        0x02, 0x00, // count = 2
        0x64, 0x00, 0x00, 0x00, // first_seq = 100
        0x03, 0x00, 0x00, 0x00, // boot_id = 3
        0x04, 0x00, 0x00, 0x00, // boot_now = 4
        0x20, 0x1C, 0x00, 0x00, // uptime_now_s = 7200
        0x80, 0x3B, 0xB1, 0x6A, // boot_epoch_s = 1790000000
        0x00, 0x00, 0x00, 0x00, // lost_through = 0
        0x3C, 0x00, 0x00, 0x00, // sample_interval_s = 60
        0x38, 0xFF, // policy_min_centi = -200
        0xF0, 0x0A, // policy_max_centi = 2800
        0xD4, 0xC3, 0xB2, 0xA1, // log_id
        // sample 0
        0x3C, 0x00, 0x00, 0x00, 0xCA, 0x09, 0x00, 0x00,
        // sample 1
        0x78, 0x00, 0x00, 0x00, 0x38, 0xFF, 0x01, 0x00,
    };
    try expectEqualSlices(u8, &want, p[0..want.len]);
    try expectEqual(@as(usize, 56), t.cm_tlog_batch_used_bytes(&p));
    // Everything past the samples is zeroed, not left as whatever was there.
    for (p[want.len..]) |b| try expectEqual(@as(u8, 0), b);
}

test "a batch round-trips through its decoder" {
    var p: [t.payload_size]u8 = undefined;
    const h = header(100, 3);
    t.cm_tlog_batch_begin(&p, &h);
    _ = t.cm_tlog_batch_add(&p, &t.Record{ .seq = 100, .boot_id = 3, .uptime_s = 60, .centi_c = 2506, .flags = 0 });
    _ = t.cm_tlog_batch_add(&p, &t.Record{ .seq = 101, .boot_id = 3, .uptime_s = 120, .centi_c = -200, .flags = 1 });

    var got: t.BatchHeader = undefined;
    try expect(t.cm_tlog_batch_decode_header(&p, p.len, &got));
    try expectEqual(@as(u16, 2), got.count);
    try expectEqual(@as(u32, 100), got.first_seq);
    try expectEqual(@as(u32, 1790000000), got.boot_epoch_s);
    try expectEqual(@as(i16, -200), got.policy_min_centi);
    try expectEqual(@as(u32, 0xA1B2C3D4), got.log_id);

    var r: t.Record = undefined;
    try expect(t.cm_tlog_batch_sample(&p, p.len, 1, &r));
    try expectEqual(@as(u32, 101), r.seq);
    try expectEqual(@as(u32, 3), r.boot_id);
    try expectEqual(@as(u32, 120), r.uptime_s);
    try expectEqual(@as(i16, -200), r.centi_c);
    try expectEqual(@as(u8, 1), r.flags);
    try expect(!t.cm_tlog_batch_sample(&p, p.len, 2, &r)); // only two samples
}

test "a batch stops at a boot boundary, so one header's clock covers every sample" {
    var p: [t.payload_size]u8 = undefined;
    t.cm_tlog_batch_begin(&p, &header(10, 3));
    try expect(t.cm_tlog_batch_add(&p, &t.Record{ .seq = 10, .boot_id = 3, .uptime_s = 1, .centi_c = 1, .flags = 0 }));
    try expect(!t.cm_tlog_batch_add(&p, &t.Record{ .seq = 11, .boot_id = 4, .uptime_s = 1, .centi_c = 1, .flags = 0 }));
    try expectEqual(@as(u16, 1), t.cm_tlog_batch_count(&p));
}

test "a batch refuses a gap in seq" {
    var p: [t.payload_size]u8 = undefined;
    t.cm_tlog_batch_begin(&p, &header(10, 3));
    try expect(!t.cm_tlog_batch_add(&p, &t.Record{ .seq = 11, .boot_id = 3, .uptime_s = 1, .centi_c = 1, .flags = 0 }));
    try expectEqual(@as(u16, 0), t.cm_tlog_batch_count(&p));
}

test "a batch holds 91 samples and refuses the 92nd" {
    try expectEqual(@as(u16, 91), t.batch_max_samples);
    var p: [t.payload_size]u8 = undefined;
    t.cm_tlog_batch_begin(&p, &header(1, 1));
    var s: u32 = 1;
    while (s <= 91) : (s += 1) try expect(t.cm_tlog_batch_add(&p, &t.Record{ .seq = s, .boot_id = 1, .uptime_s = s, .centi_c = 0, .flags = 0 }));
    try expect(!t.cm_tlog_batch_add(&p, &t.Record{ .seq = 92, .boot_id = 1, .uptime_s = 92, .centi_c = 0, .flags = 0 }));
    try expectEqual(@as(usize, t.payload_size), t.cm_tlog_batch_used_bytes(&p));
}

test "a lost record travels as a marked placeholder, keeping the window moving" {
    var p: [t.payload_size]u8 = undefined;
    t.cm_tlog_batch_begin(&p, &header(21, 1));
    try expect(t.cm_tlog_batch_add_lost(&p, 21));
    try expect(!t.cm_tlog_batch_add_lost(&p, 23)); // still must be contiguous
    var r: t.Record = undefined;
    try expect(t.cm_tlog_batch_sample(&p, p.len, 0, &r));
    try expectEqual(@as(u32, 21), r.seq);
    try expectEqual(t.temp_invalid, r.centi_c);
    try expectEqual(t.SF_RECORD_LOST | t.SF_SENSOR_ERROR, r.flags);
}

test "the batch decoder refuses what it cannot trust" {
    var p: [t.payload_size]u8 = undefined;
    t.cm_tlog_batch_begin(&p, &header(1, 1));
    _ = t.cm_tlog_batch_add(&p, &t.Record{ .seq = 1, .boot_id = 1, .uptime_s = 1, .centi_c = 0, .flags = 0 });
    var h: t.BatchHeader = undefined;

    try expect(!t.cm_tlog_batch_decode_header(&p, 47, &h)); // shorter than header + 1 sample
    try expect(t.cm_tlog_batch_decode_header(&p, 48, &h));

    var bad = p;
    bad[0] = 1; // unknown version
    try expect(!t.cm_tlog_batch_decode_header(&bad, bad.len, &h));

    bad = p;
    bad[2] = 92; // count beyond what a payload can hold
    try expect(!t.cm_tlog_batch_decode_header(&bad, bad.len, &h));

    try expect(!t.cm_tlog_batch_decode_header(null, 768, &h));
}

// ── Ack payload ─────────────────────────────────────────────────────────

test "an ack encodes to the byte layout in the spec and round-trips" {
    var p = [_]u8{0xEE} ** t.payload_size;
    const mac = [6]u8{ 0x58, 0xE6, 0xC5, 0x1A, 0x8B, 0x28 };
    t.cm_tlog_ack_encode(&p, &mac, 450, 1790003600);
    const want = [_]u8{
        0x00, 0x00, // version, reserved
        0x58, 0xE6, 0xC5, 0x1A, 0x8B, 0x28, // target mac
        0xC2, 0x01, 0x00, 0x00, // acked_through = 450
        0x90, 0x49, 0xB1, 0x6A, // host_unix_s = 1790003600
    };
    try expectEqualSlices(u8, &want, p[0..16]);
    for (p[16..]) |b| try expectEqual(@as(u8, 0), b);

    var got_mac: [6]u8 = undefined;
    var acked: u32 = 0;
    var host: u32 = 0;
    try expect(t.cm_tlog_ack_decode(&p, p.len, &got_mac, &acked, &host));
    try expectEqualSlices(u8, &mac, &got_mac);
    try expectEqual(@as(u32, 450), acked);
    try expectEqual(@as(u32, 1790003600), host);
}

test "the ack decoder refuses a short buffer or an unknown version" {
    var p: [t.payload_size]u8 = undefined;
    const mac = [6]u8{ 1, 2, 3, 4, 5, 6 };
    t.cm_tlog_ack_encode(&p, &mac, 1, 0);
    var m: [6]u8 = undefined;
    var a: u32 = 0;
    var h: u32 = 0;
    try expect(!t.cm_tlog_ack_decode(&p, 15, &m, &a, &h));
    p[0] = 9;
    try expect(!t.cm_tlog_ack_decode(&p, p.len, &m, &a, &h));
}

// ── Send scheduling ─────────────────────────────────────────────────────

test "the first pending sample goes out at once; nothing goes out when nothing is pending" {
    var s: t.Sched = undefined;
    t.cm_tlog_sched_init(&s);
    try expect(t.cm_tlog_sched_should_send(&s, 0, 1));
    try expect(!t.cm_tlog_sched_should_send(&s, 0, 0));
}

test "unanswered sends back off by doubling, up to a ceiling" {
    var s: t.Sched = undefined;
    t.cm_tlog_sched_init(&s);
    t.cm_tlog_sched_on_sent(&s, 1000, 60_000);
    try expect(!t.cm_tlog_sched_should_send(&s, 2999, 5));
    try expect(t.cm_tlog_sched_should_send(&s, 3000, 5)); // 2 s
    t.cm_tlog_sched_on_sent(&s, 3000, 60_000);
    try expect(!t.cm_tlog_sched_should_send(&s, 6999, 5));
    try expect(t.cm_tlog_sched_should_send(&s, 7000, 5)); // 4 s
    var now: u64 = 7000;
    var k: u32 = 0;
    while (k < 10) : (k += 1) {
        t.cm_tlog_sched_on_sent(&s, now, 60_000);
        now += 60_000;
    }
    try expectEqual(@as(u32, 60_000), s.backoff_ms);
}

test "an ack resets the backoff and releases the backlog immediately" {
    var s: t.Sched = undefined;
    t.cm_tlog_sched_init(&s);
    t.cm_tlog_sched_on_sent(&s, 0, 60_000);
    t.cm_tlog_sched_on_sent(&s, 2000, 60_000);
    t.cm_tlog_sched_on_ack(&s, 2500);
    try expect(t.cm_tlog_sched_should_send(&s, 2500, 40));
    try expectEqual(@as(u32, t.sched_min_backoff_ms), s.backoff_ms);
}

// ── Script numbers and the heat policy ──────────────────────────────────

fn push(v: i32) ![]const u8 {
    const S = struct {
        var buf: [8]u8 = undefined;
    };
    const n = t.cm_script_num_push(v, &S.buf, S.buf.len);
    try expect(n > 0);
    return S.buf[0..n];
}

test "script numbers use the small-int opcodes and minimal sign-magnitude pushes" {
    try expectEqualSlices(u8, &[_]u8{0x00}, try push(0));
    try expectEqualSlices(u8, &[_]u8{0x4f}, try push(-1));
    try expectEqualSlices(u8, &[_]u8{0x51}, try push(1));
    try expectEqualSlices(u8, &[_]u8{0x60}, try push(16));
    try expectEqualSlices(u8, &[_]u8{ 0x01, 0x11 }, try push(17));
    try expectEqualSlices(u8, &[_]u8{ 0x01, 0x7f }, try push(127));
    try expectEqualSlices(u8, &[_]u8{ 0x02, 0x80, 0x00 }, try push(128));
    try expectEqualSlices(u8, &[_]u8{ 0x02, 0x80, 0x80 }, try push(-128));
    try expectEqualSlices(u8, &[_]u8{ 0x01, 0x82 }, try push(-2));
    try expectEqualSlices(u8, &[_]u8{ 0x02, 0xf0, 0x0a }, try push(2800));
    try expectEqualSlices(u8, &[_]u8{ 0x02, 0xc8, 0x80 }, try push(-200));
    try expectEqualSlices(u8, &[_]u8{ 0x04, 0xff, 0xff, 0xff, 0x7f }, try push(std.math.maxInt(i32)));
    try expectEqualSlices(u8, &[_]u8{ 0x05, 0x00, 0x00, 0x00, 0x80, 0x80 }, try push(std.math.minInt(i32)));
}

test "a script number that does not fit the buffer writes nothing" {
    var buf: [2]u8 = undefined;
    try expectEqual(@as(usize, 0), t.cm_script_num_push(2800, &buf, 2));
    try expectEqual(@as(usize, 0), t.cm_script_num_push(2800, null, 8));
}

test "the policy lock accepts min through max inclusive: <min> <max+1> OP_WITHIN" {
    var buf: [16]u8 = undefined;
    const n = t.cm_tlog_policy_lock(-200, 2800, &buf, buf.len);
    try expectEqualSlices(u8, &[_]u8{ 0x02, 0xc8, 0x80, 0x02, 0xf1, 0x0a, 0xa5 }, buf[0..n]);
}

test "the policy unlock pushes the reading" {
    var buf: [8]u8 = undefined;
    const n = t.cm_tlog_policy_unlock(2506, &buf, buf.len);
    try expectEqualSlices(u8, &[_]u8{ 0x02, 0xca, 0x09 }, buf[0..n]);
}

test "a policy whose band is empty is refused" {
    var buf: [16]u8 = undefined;
    try expectEqual(@as(usize, 0), t.cm_tlog_policy_lock(3000, 2800, &buf, buf.len));
}
