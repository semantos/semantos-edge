const std = @import("std");
const testing = std.testing;

pub const Meter = extern struct {
    rate_msat_per_sec: u32,
    accrued_msat: u64,
    last_tick_ms: u64,
    running: bool,
};

pub export fn cm_meter_init(maybe_m: ?*Meter, rate_msat_per_sec: u32) callconv(.c) void {
    const m = maybe_m orelse return;
    m.* = std.mem.zeroes(Meter);
    m.rate_msat_per_sec = rate_msat_per_sec;
}

pub export fn cm_meter_start(maybe_m: ?*Meter, now_ms: u64) callconv(.c) void {
    const m = maybe_m orelse return;
    if (m.running) return;
    m.running = true;
    m.last_tick_ms = now_ms;
}

pub export fn cm_meter_tick(maybe_m: ?*Meter, now_ms: u64) callconv(.c) void {
    const m = maybe_m orelse return;
    if (!m.running) return;
    if (now_ms <= m.last_tick_ms) return;

    const elapsed_ms = now_ms - m.last_tick_ms;
    m.accrued_msat +|= (@as(u64, m.rate_msat_per_sec) * elapsed_ms) / 1000;
    m.last_tick_ms = now_ms;
}

pub export fn cm_meter_stop(maybe_m: ?*Meter, now_ms: u64) callconv(.c) void {
    const m = maybe_m orelse return;
    if (!m.running) return;
    cm_meter_tick(m, now_ms);
    m.running = false;
}

pub export fn cm_meter_consumed_sats(maybe_m: ?*const Meter) callconv(.c) u32 {
    const m = maybe_m orelse return 0;
    const sats = m.accrued_msat / 1000;
    return if (sats > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(sats);
}

pub export fn cm_meter_consumed_msat(maybe_m: ?*const Meter) callconv(.c) u64 {
    const m = maybe_m orelse return 0;
    return m.accrued_msat;
}

pub export fn cm_meter_authorized(
    maybe_m: ?*const Meter,
    paid_device_share: u32,
    tolerance_sats: u32,
) callconv(.c) bool {
    const m = maybe_m orelse return false;
    const consumed = @as(u64, cm_meter_consumed_sats(m));
    const allowed = @as(u64, paid_device_share) + @as(u64, tolerance_sats);
    return consumed <= allowed;
}

test "meter accrues while running and saturates sats at u32 max" {
    var m: Meter = undefined;
    cm_meter_init(&m, 2500);
    cm_meter_start(&m, 1000);
    cm_meter_tick(&m, 3000);
    try testing.expectEqual(@as(u64, 5000), cm_meter_consumed_msat(&m));
    try testing.expectEqual(@as(u32, 5), cm_meter_consumed_sats(&m));

    cm_meter_stop(&m, 4000);
    cm_meter_tick(&m, 5000);
    try testing.expectEqual(@as(u32, 7), cm_meter_consumed_sats(&m));

    m.accrued_msat = @as(u64, std.math.maxInt(u32)) * 1000 + 999_000;
    try testing.expectEqual(std.math.maxInt(u32), cm_meter_consumed_sats(&m));
}
