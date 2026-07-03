const std = @import("std");
const testing = std.testing;

pub const cell_size: usize = 1024;
pub const header_size: usize = 256;
pub const payload_size: usize = 768;
pub const version: u32 = 2;

pub const magic_1: u32 = 0xDEADBEEF;
pub const magic_2: u32 = 0xCAFEBABE;
pub const magic_3: u32 = 0x13371337;
pub const magic_4: u32 = 0x42424242;

pub const Off = struct {
    pub const magic: usize = 0;
    pub const linearity: usize = 16;
    pub const version: usize = 20;
    pub const flags: usize = 24;
    pub const ref_count: usize = 28;
    pub const type_hash: usize = 30;
    pub const owner_id: usize = 62;
    pub const timestamp: usize = 78;
    pub const cell_count: usize = 86;
    pub const payload_total: usize = 90;
    pub const parent_hash: usize = 96;
    pub const prev_state_hash: usize = 128;
    pub const domain_payload_root: usize = 224;
    pub const payload: usize = 256;
};

pub const Linearity = enum(u32) {
    linear = 1,
    affine = 2,
    relevant = 3,
    debug = 4,
};

pub const Cell = [cell_size]u8;

pub fn readU16(bytes: []const u8) u16 {
    std.debug.assert(bytes.len >= 2);
    return @as(u16, bytes[0]) | (@as(u16, bytes[1]) << 8);
}

pub fn readU32(bytes: []const u8) u32 {
    std.debug.assert(bytes.len >= 4);
    return @as(u32, bytes[0]) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

pub fn readU64(bytes: []const u8) u64 {
    std.debug.assert(bytes.len >= 8);
    var value: u64 = 0;
    for (bytes[0..8], 0..) |byte, i| {
        value |= @as(u64, byte) << @intCast(i * 8);
    }
    return value;
}

pub fn writeU16(bytes: []u8, value: u16) void {
    std.debug.assert(bytes.len >= 2);
    bytes[0] = @intCast(value & 0xff);
    bytes[1] = @intCast((value >> 8) & 0xff);
}

pub fn writeU32(bytes: []u8, value: u32) void {
    std.debug.assert(bytes.len >= 4);
    bytes[0] = @intCast(value & 0xff);
    bytes[1] = @intCast((value >> 8) & 0xff);
    bytes[2] = @intCast((value >> 16) & 0xff);
    bytes[3] = @intCast((value >> 24) & 0xff);
}

pub fn writeU64(bytes: []u8, value: u64) void {
    std.debug.assert(bytes.len >= 8);
    for (bytes[0..8], 0..) |*byte, i| {
        byte.* = @intCast((value >> @intCast(i * 8)) & 0xff);
    }
}

pub fn init(cell: *Cell) void {
    initBytes(cell[0..]);
}

pub fn initBytes(cell: []u8) void {
    std.debug.assert(cell.len >= cell_size);
    @memset(cell[0..cell_size], 0);
    writeU32(cell[Off.magic + 0 ..], magic_1);
    writeU32(cell[Off.magic + 4 ..], magic_2);
    writeU32(cell[Off.magic + 8 ..], magic_3);
    writeU32(cell[Off.magic + 12 ..], magic_4);
    setVersion(cell[0..], version);
}

pub fn isCell(buf_maybe: ?[]const u8) bool {
    const buf = buf_maybe orelse return false;
    if (buf.len < 16) return false;
    return readU32(buf[0..]) == magic_1 and
        readU32(buf[4..]) == magic_2 and
        readU32(buf[8..]) == magic_3 and
        readU32(buf[12..]) == magic_4;
}

pub export fn cm_cell_init(cell: ?[*]u8) callconv(.c) void {
    const ptr = cell orelse return;
    initBytes(ptr[0..cell_size]);
}

pub export fn cm_is_cell(buf: ?[*]const u8, buf_len: usize) callconv(.c) bool {
    const ptr = buf orelse return false;
    return isCell(ptr[0..buf_len]);
}

pub fn linearity(cell: []const u8) u32 {
    return readU32(cell[Off.linearity..]);
}

pub fn setLinearity(cell: []u8, value: u32) void {
    writeU32(cell[Off.linearity..], value);
}

pub fn cellVersion(cell: []const u8) u32 {
    return readU32(cell[Off.version..]);
}

pub fn setVersion(cell: []u8, value: u32) void {
    writeU32(cell[Off.version..], value);
}

pub fn flags(cell: []const u8) u32 {
    return readU32(cell[Off.flags..]);
}

pub fn setFlags(cell: []u8, value: u32) void {
    writeU32(cell[Off.flags..], value);
}

pub fn refCount(cell: []const u8) u16 {
    return readU16(cell[Off.ref_count..]);
}

pub fn setRefCount(cell: []u8, value: u16) void {
    writeU16(cell[Off.ref_count..], value);
}

pub fn timestampMs(cell: []const u8) u64 {
    return readU64(cell[Off.timestamp..]);
}

pub fn setTimestampMs(cell: []u8, value: u64) void {
    writeU64(cell[Off.timestamp..], value);
}

pub fn cellCount(cell: []const u8) u32 {
    return readU32(cell[Off.cell_count..]);
}

pub fn setCellCount(cell: []u8, value: u32) void {
    writeU32(cell[Off.cell_count..], value);
}

pub fn payloadTotal(cell: []const u8) u32 {
    return readU32(cell[Off.payload_total..]);
}

pub fn setPayloadTotal(cell: []u8, value: u32) void {
    writeU32(cell[Off.payload_total..], value);
}

pub fn typeHash(cell: []const u8) []const u8 {
    return cell[Off.type_hash..][0..32];
}

pub fn typeHashMut(cell: []u8) []u8 {
    return cell[Off.type_hash..][0..32];
}

pub fn ownerId(cell: []const u8) []const u8 {
    return cell[Off.owner_id..][0..16];
}

pub fn ownerIdMut(cell: []u8) []u8 {
    return cell[Off.owner_id..][0..16];
}

pub fn parentHash(cell: []const u8) []const u8 {
    return cell[Off.parent_hash..][0..32];
}

pub fn parentHashMut(cell: []u8) []u8 {
    return cell[Off.parent_hash..][0..32];
}

pub fn prevStateHash(cell: []const u8) []const u8 {
    return cell[Off.prev_state_hash..][0..32];
}

pub fn prevStateHashMut(cell: []u8) []u8 {
    return cell[Off.prev_state_hash..][0..32];
}

pub fn domainPayloadRoot(cell: []const u8) []const u8 {
    return cell[Off.domain_payload_root..][0..32];
}

pub fn domainPayloadRootMut(cell: []u8) []u8 {
    return cell[Off.domain_payload_root..][0..32];
}

pub fn payload(cell: []const u8) []const u8 {
    return cell[Off.payload..][0..payload_size];
}

pub fn payloadMut(cell: []u8) []u8 {
    return cell[Off.payload..][0..payload_size];
}

test "init zeros cell and writes magic plus version" {
    var cell: Cell = undefined;
    @memset(cell[0..], 0x77);

    init(&cell);

    try testing.expectEqual(@as(u8, 0xEF), cell[0]);
    try testing.expectEqual(@as(u8, 0xBE), cell[1]);
    try testing.expectEqual(@as(u8, 0xAD), cell[2]);
    try testing.expectEqual(@as(u8, 0xDE), cell[3]);
    try testing.expectEqual(@as(u8, 0xBE), cell[4]);
    try testing.expectEqual(@as(u8, 0xBA), cell[5]);
    try testing.expectEqual(@as(u8, 0xFE), cell[6]);
    try testing.expectEqual(@as(u8, 0xCA), cell[7]);
    try testing.expectEqual(@as(u8, 0x37), cell[8]);
    try testing.expectEqual(@as(u8, 0x13), cell[9]);
    try testing.expectEqual(@as(u8, 0x37), cell[10]);
    try testing.expectEqual(@as(u8, 0x13), cell[11]);
    try testing.expectEqual(@as(u8, 0x42), cell[12]);
    try testing.expectEqual(@as(u8, 0x42), cell[13]);
    try testing.expectEqual(@as(u8, 0x42), cell[14]);
    try testing.expectEqual(@as(u8, 0x42), cell[15]);

    try testing.expectEqual(version, cellVersion(cell[0..]));
    try testing.expectEqual(@as(u8, 0), cell[16]);
    try testing.expectEqual(@as(u8, 0), cell[Off.payload]);
    try testing.expectEqual(@as(u8, 0), cell[cell_size - 1]);
}

test "scalar setters land at canonical offsets and round-trip" {
    var cell: Cell = undefined;
    init(&cell);

    setLinearity(cell[0..], 0x11111111);
    setVersion(cell[0..], 0x22222222);
    setFlags(cell[0..], 0x33333333);
    setRefCount(cell[0..], 0x4444);
    setTimestampMs(cell[0..], 0x5555555555555555);
    setCellCount(cell[0..], 0x66666666);
    setPayloadTotal(cell[0..], 0x77777777);

    try testing.expectEqual(@as(u8, 0x11), cell[16]);
    try testing.expectEqual(@as(u8, 0x11), cell[19]);
    try testing.expectEqual(@as(u8, 0x22), cell[20]);
    try testing.expectEqual(@as(u8, 0x22), cell[23]);
    try testing.expectEqual(@as(u8, 0x33), cell[24]);
    try testing.expectEqual(@as(u8, 0x33), cell[27]);
    try testing.expectEqual(@as(u8, 0x44), cell[28]);
    try testing.expectEqual(@as(u8, 0x44), cell[29]);
    try testing.expectEqual(@as(u8, 0x55), cell[78]);
    try testing.expectEqual(@as(u8, 0x55), cell[85]);
    try testing.expectEqual(@as(u8, 0x66), cell[86]);
    try testing.expectEqual(@as(u8, 0x66), cell[89]);
    try testing.expectEqual(@as(u8, 0x77), cell[90]);
    try testing.expectEqual(@as(u8, 0x77), cell[93]);

    try testing.expectEqual(@as(u32, 0x11111111), linearity(cell[0..]));
    try testing.expectEqual(@as(u32, 0x22222222), cellVersion(cell[0..]));
    try testing.expectEqual(@as(u32, 0x33333333), flags(cell[0..]));
    try testing.expectEqual(@as(u16, 0x4444), refCount(cell[0..]));
    try testing.expectEqual(@as(u64, 0x5555555555555555), timestampMs(cell[0..]));
    try testing.expectEqual(@as(u32, 0x66666666), cellCount(cell[0..]));
    try testing.expectEqual(@as(u32, 0x77777777), payloadTotal(cell[0..]));
}

test "byte-field views point at canonical offsets" {
    var cell: Cell = undefined;
    init(&cell);

    var pattern_a: [32]u8 = undefined;
    var pattern_b: [16]u8 = undefined;
    var pattern_c: [32]u8 = undefined;
    var pattern_d: [32]u8 = undefined;
    var pattern_e: [32]u8 = undefined;

    for (&pattern_a, 0..) |*byte, i| byte.* = @intCast(0xA0 + i);
    for (&pattern_b, 0..) |*byte, i| byte.* = @intCast(0xB0 + i);
    for (&pattern_c, 0..) |*byte, i| byte.* = @intCast(0xC0 + i);
    for (&pattern_d, 0..) |*byte, i| byte.* = @intCast(0xD0 + i);
    for (&pattern_e, 0..) |*byte, i| byte.* = @intCast(0xE0 + i);

    @memcpy(typeHashMut(cell[0..]), pattern_a[0..]);
    @memcpy(ownerIdMut(cell[0..]), pattern_b[0..]);
    @memcpy(parentHashMut(cell[0..]), pattern_c[0..]);
    @memcpy(prevStateHashMut(cell[0..]), pattern_d[0..]);
    @memcpy(domainPayloadRootMut(cell[0..]), pattern_e[0..]);

    try testing.expectEqual(@as(u8, 0xA0), cell[30]);
    try testing.expectEqual(@as(u8, 0xA0 + 31), cell[61]);
    try testing.expectEqual(@as(u8, 0xB0), cell[62]);
    try testing.expectEqual(@as(u8, 0xB0 + 15), cell[77]);
    try testing.expectEqual(@as(u8, 0xC0), cell[96]);
    try testing.expectEqual(@as(u8, 0xC0 + 31), cell[127]);
    try testing.expectEqual(@as(u8, 0xD0), cell[128]);
    try testing.expectEqual(@as(u8, 0xD0 + 31), cell[159]);
    try testing.expectEqual(@as(u8, 0xE0), cell[224]);
    try testing.expectEqual(@as(u8, 0xE0 + 31), cell[255]);

    try testing.expectEqual(@intFromPtr(&cell[30]), @intFromPtr(typeHash(cell[0..]).ptr));
    try testing.expectEqual(@intFromPtr(&cell[62]), @intFromPtr(ownerId(cell[0..]).ptr));
    try testing.expectEqual(@intFromPtr(&cell[96]), @intFromPtr(parentHash(cell[0..]).ptr));
    try testing.expectEqual(@intFromPtr(&cell[128]), @intFromPtr(prevStateHash(cell[0..]).ptr));
    try testing.expectEqual(@intFromPtr(&cell[224]), @intFromPtr(domainPayloadRoot(cell[0..]).ptr));
    try testing.expectEqual(@intFromPtr(&cell[256]), @intFromPtr(payload(cell[0..]).ptr));

    try testing.expectEqualSlices(u8, pattern_a[0..], typeHash(cell[0..]));
    try testing.expectEqualSlices(u8, pattern_b[0..], ownerId(cell[0..]));
    try testing.expectEqualSlices(u8, pattern_c[0..], parentHash(cell[0..]));
    try testing.expectEqualSlices(u8, pattern_d[0..], prevStateHash(cell[0..]));
    try testing.expectEqualSlices(u8, pattern_e[0..], domainPayloadRoot(cell[0..]));
}

test "reserved regions remain zero after init and named writes" {
    var cell: Cell = undefined;
    init(&cell);

    setLinearity(cell[0..], 0xFFFFFFFF);
    setFlags(cell[0..], 0xFFFFFFFF);
    setRefCount(cell[0..], 0xFFFF);
    setTimestampMs(cell[0..], 0xFFFFFFFFFFFFFFFF);
    @memset(typeHashMut(cell[0..]), 0xFF);
    @memset(ownerIdMut(cell[0..]), 0xFF);
    @memset(parentHashMut(cell[0..]), 0xFF);
    @memset(prevStateHashMut(cell[0..]), 0xFF);
    @memset(domainPayloadRootMut(cell[0..]), 0xFF);

    try testing.expectEqual(@as(u8, 0), cell[94]);
    try testing.expectEqual(@as(u8, 0), cell[95]);
    for (cell[160..224]) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "isCell sniffs magic safely" {
    var cell: Cell = undefined;
    init(&cell);

    try testing.expect(isCell(cell[0..16]));
    try testing.expect(isCell(cell[0..]));

    var junk: [16]u8 = .{0} ** 16;
    try testing.expect(!isCell(junk[0..]));
    try testing.expect(!isCell(cell[0..8]));
    try testing.expect(!isCell(null));
}

test "payload writes land at byte 256 and preserve trailing bytes" {
    var cell: Cell = undefined;
    init(&cell);

    const p = payloadMut(cell[0..]);
    for (p[0..256], 0..) |*byte, i| {
        byte.* = @intCast(i ^ 0x5A);
    }
    setPayloadTotal(cell[0..], 256);

    try testing.expectEqual(@as(u8, 0 ^ 0x5A), cell[Off.payload]);
    try testing.expectEqual(@as(u8, 255 ^ 0x5A), cell[Off.payload + 255]);
    try testing.expectEqual(@as(u8, 0), cell[Off.payload + 256]);
    try testing.expectEqual(@as(u32, 256), payloadTotal(cell[0..]));
}
