//! M5: drive real ESP32-C6 boards from the Zig control plane.
//!
//!   zig build hw
//!
//! The same proof the TypeScript plane ran, with every byte produced here
//! instead: the fleet is derived, the certificate assembled, the cell minted and
//! signed, the frame CRC'd, and the serial I/O done from this process. Nothing
//! is borrowed from the TS side except the boards themselves.
//!
//! Three verdicts, and the third is the one that makes the first two mean
//! anything:
//!
//!   1. a cert the boards accept and install, echoing back the derived channel
//!      and edge public key
//!   2. the same cert with one byte flipped, refused
//!   3. the same cert signed by the key the firmware USED to trust, refused —
//!      without which "the board accepted our cert" is indistinguishable from
//!      "the board accepts whatever arrives"
//!
//! Two boards are required. Under `DEMO_SCRIPT_ONLY` the board you inject into
//! does not process the cell: it ack-blinks and rebroadcasts over ESP-NOW after
//! `DEMO_BROADCAST_DELAY_MS`, and the OTHER board verifies and installs. That
//! also puts a real radio hop in the path.

const std = @import("std");
const derive = @import("derive");
const identity = @import("identity");
const cert = @import("cert");
const domains = @import("domains");

/// Must match the anchor compiled into the boards — see `bun run fleet:anchor`
/// and `USE_FLEET_ANCHOR` in examples/mesh_demo/main/main.c.
const ROOT_EMAIL = "operator@fleet.example";
const ROOT_SALT = "demo-fleet-salt";

/// sign-cell-deck's demo key, the anchor the firmware carried before the fleet
/// root replaced it. Used only to prove the boards now refuse it.
const LEGACY_KEY_HEX = "0000000000000000000000000000000000000000000000000000000000000042";

const ansi_green = "\x1b[32m";
const ansi_red = "\x1b[31m";
const ansi_bold = "\x1b[1m";
const ansi_off = "\x1b[0m";

fn rule(title: []const u8) void {
    std.debug.print("\n{s}{s}{s}\n", .{ ansi_bold, title, ansi_off });
    std.debug.print("------------------------------------------------------------------------\n", .{});
}

/// The C6's native-USB CDC renames on every reset, so ports are discovered.
fn discoverPorts(allocator: std.mem.Allocator) ![2][]u8 {
    var dir = try std.fs.openDirAbsolute("/dev", .{ .iterate = true });
    defer dir.close();
    var found: std.ArrayList([]u8) = .empty;
    defer {
        for (found.items) |p| allocator.free(p);
        found.deinit(allocator);
    }
    var it = dir.iterate();
    while (try it.next()) |e| {
        if (!std.mem.startsWith(u8, e.name, "cu.usbmodem")) continue;
        try found.append(allocator, try std.fmt.allocPrint(allocator, "/dev/{s}", .{e.name}));
    }
    if (found.items.len < 2) return error.NeedTwoBoards;
    std.mem.sort([]u8, found.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    const a = try allocator.dupe(u8, found.items[0]);
    const b = try allocator.dupe(u8, found.items[1]);
    return .{ a, b };
}

/// Put a tty into raw mode. Shelling out to stty is what the repo's own bridge
/// does, and it keeps this free of a termios binding for one call.
fn setRaw(allocator: std.mem.Allocator, port: []const u8) !void {
    var child = std.process.Child.init(
        &.{ "stty", "-f", port, "115200", "raw", "-echo" },
        allocator,
    );
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    _ = try child.spawnAndWait();
}

/// Frame a cell+sig the way the firmware's inject parser reads it:
/// "IJ" <hex(cell || sig || crc32le)> "\n".
fn frameCell(
    allocator: std.mem.Allocator,
    cell: []const u8,
    sig: []const u8,
) ![]u8 {
    const body = try allocator.alloc(u8, cell.len + sig.len);
    defer allocator.free(body);
    @memcpy(body[0..cell.len], cell);
    @memcpy(body[cell.len..], sig);

    const crc = std.hash.Crc32.hash(body);
    var tail: [4]u8 = undefined;
    std.mem.writeInt(u32, &tail, crc, .little);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "IJ");
    const w = out.writer(allocator);
    for (body) |b| try w.print("{x:0>2}", .{b});
    for (tail) |b| try w.print("{x:0>2}", .{b});
    try out.append(allocator, '\n');
    return out.toOwnedSlice(allocator);
}

/// Write a frame in paced chunks — the console shares the USB-Serial-JTAG
/// endpoint and its RX ring is small, so a burst can outrun it.
fn inject(port: []const u8, frame: []const u8) !void {
    var attempt: usize = 0;
    while (attempt < 2) : (attempt += 1) {
        const f = try std.fs.openFileAbsolute(port, .{ .mode = .write_only });
        defer f.close();
        var off: usize = 0;
        while (off < frame.len) {
            const n = @min(@as(usize, 256), frame.len - off);
            try f.writeAll(frame[off .. off + n]);
            off += n;
            std.Thread.sleep(2 * std.time.ns_per_ms);
        }
        std.Thread.sleep(400 * std.time.ns_per_ms);
    }
}

const Watcher = struct {
    file: std.fs.File,
    buf: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    fn open(allocator: std.mem.Allocator, port: []const u8) !Watcher {
        // O_NONBLOCK at OPEN time, not after: opening a tty without it blocks
        // until carrier, which on a USB-CDC port that is not asserting DCD
        // simply never returns. And the flag's VALUE is platform-specific -
        // 0x4 on Darwin, 0o4000 on Linux - so it comes from std.posix.O rather
        // than a literal.
        const nonblock: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
        const fd = try std.posix.open(port, @bitCast(nonblock | @as(u32, @bitCast(std.posix.O{ .ACCMODE = .RDONLY }))), 0);
        const f = std.fs.File{ .handle = fd };
        return .{ .file = f, .buf = .empty, .allocator = allocator };
    }

    fn deinit(self: *Watcher) void {
        self.buf.deinit(self.allocator);
        self.file.close();
    }

    /// Drain whatever has arrived, without blocking.
    fn pump(self: *Watcher) !void {
        var chunk: [4096]u8 = undefined;
        while (true) {
            const n = self.file.read(&chunk) catch |err| switch (err) {
                error.WouldBlock => return,
                else => return err,
            };
            if (n == 0) return;
            try self.buf.appendSlice(self.allocator, chunk[0..n]);
        }
    }

    /// Wait for a line containing any needle. Returns the line, or null.
    fn await_(self: *Watcher, needles: []const []const u8, timeout_ms: u64) !?[]const u8 {
        const start = std.time.milliTimestamp();
        const from = self.buf.items.len;
        while (std.time.milliTimestamp() - start < @as(i64, @intCast(timeout_ms))) {
            try self.pump();
            var it = std.mem.splitScalar(u8, self.buf.items[from..], '\n');
            while (it.next()) |line| {
                for (needles) |n| {
                    if (std.mem.indexOf(u8, line, n) != null) {
                        return std.mem.trim(u8, line, " \r\n");
                    }
                }
            }
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
        return null;
    }
};

fn hexOf(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        _ = try std.fmt.bufPrint(out[i * 2 ..][0..2], "{x:0>2}", .{bytes[i]});
    }
    return out;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = gpa.allocator();

    std.debug.print(
        "\n{s}Fleet identity on real silicon - driven by the Zig control plane{s}\n",
        .{ ansi_bold, ansi_off },
    );

    const ports = try discoverPorts(a);
    defer {
        a.free(ports[0]);
        a.free(ports[1]);
    }
    const inject_port = ports[0];
    const watch_port = ports[1];
    std.debug.print("inject -> {s}   (relays over ESP-NOW)\n", .{inject_port});
    std.debug.print("watch  <- {s}   (verifies + installs)\n", .{watch_port});

    var failures: usize = 0;

    // ── 1. derive the fleet, entirely here ───────────────────────────────────
    rule("1. Provision a unit - every byte derived by this process");

    const root = try identity.rootIdentity(a, ROOT_EMAIL, ROOT_SALT);
    const operator_key = try derive.derivePrivateKeyAtPath(ROOT_EMAIL, ROOT_SALT, "root");
    const anchor = try derive.pubHex(operator_key);

    const zone = try identity.deriveChildIdentity(a, ROOT_EMAIL, ROOT_SALT, "root", "zone", domains.zone, 0);
    defer zone.deinit(a);
    const unit = try identity.deriveChildIdentity(a, ROOT_EMAIL, ROOT_SALT, zone.derivation_path, "device", domains.fleet_device, 0);
    defer unit.deinit(a);

    const channel = try cert.channelIdFor(&unit.cert_id);
    const edge_pub = try a.alloc(u8, 33);
    defer a.free(edge_pub);
    _ = try std.fmt.hexToBytes(edge_pub, &unit.public_key_hex);

    std.debug.print("  operator anchor  {s}\n", .{&anchor});
    std.debug.print("  root certId      {s}\n", .{&root.cert_id});
    std.debug.print("  device path      {s}\n", .{unit.derivation_path});
    std.debug.print("  device pubkey    {s}\n", .{&unit.public_key_hex});
    const chan_hex = try hexOf(a, &channel);
    defer a.free(chan_hex);
    std.debug.print("  channel          {s}\n", .{chan_hex});

    // ── 2. build and sign the cert ───────────────────────────────────────────
    const payload = try cert.buildPayload(edge_pub, &channel, cert.no_expiry, @intCast(std.time.milliTimestamp()));
    var anchor_bytes: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&anchor_bytes, &anchor);
    const cell = try cert.mintCell(
        cert.typeHash(cert.capability_v0_type_name),
        &payload,
        anchor_bytes[0..16],
        @intCast(std.time.milliTimestamp()),
        domains.fleet_device,
    );
    const sig = try cert.signCell(operator_key, &cell);
    std.debug.print("  cert payload     {d} bytes, cell {d} bytes, sig {d} bytes\n", .{ payload.len, cell.len, sig.len });

    try setRaw(a, inject_port);
    try setRaw(a, watch_port);
    var watcher = try Watcher.open(a, watch_port);
    defer watcher.deinit();
    std.Thread.sleep(600 * std.time.ns_per_ms);

    const accept_needles = [_][]const u8{ "CAP cert installed", "CAP cert install FAILED", "signature INVALID" };
    const reject_needles = [_][]const u8{ "signature INVALID", "CAP cert installed", "CAP cert install FAILED" };

    // ── 3. the board must accept it ──────────────────────────────────────────
    rule("2. Inject the cert - the board must accept and install it");
    {
        const frame = try frameCell(a, &cell, &sig);
        defer a.free(frame);
        try inject(inject_port, frame);
        const line = try watcher.await_(&accept_needles, 12_000);
        std.debug.print("  board said: {s}\n", .{line orelse "(nothing - timed out)"});
        if (line != null and std.mem.indexOf(u8, line.?, "CAP cert installed") != null) {
            const edge4 = try hexOf(a, edge_pub[0..4]);
            defer a.free(edge4);
            const chan4 = try hexOf(a, channel[0..4]);
            defer a.free(chan4);
            const echoed = std.mem.indexOf(u8, line.?, edge4) != null and
                std.mem.indexOf(u8, line.?, chan4) != null;
            std.debug.print("  {s}ACCEPTED{s} - echoed ch={s}... edge={s}... {s}\n", .{
                ansi_green, ansi_off, chan4, edge4,
                if (echoed) ansi_green ++ "(matches what Zig derived)" ++ ansi_off else ansi_red ++ "(MISMATCH)" ++ ansi_off,
            });
            if (!echoed) failures += 1;
        } else {
            std.debug.print("  {s}NOT ACCEPTED{s} - are the boards flashed with this fleet's anchor?\n", .{ ansi_red, ansi_off });
            failures += 1;
        }
    }

    // ── 4. a tampered cell must be refused ───────────────────────────────────
    rule("3. Flip one byte - the board must refuse it");
    {
        var tampered = cell;
        tampered[900] ^= 0x01;
        const frame = try frameCell(a, &tampered, &sig);
        defer a.free(frame);
        try inject(inject_port, frame);
        const line = try watcher.await_(&reject_needles, 12_000);
        std.debug.print("  board said: {s}\n", .{line orelse "(nothing - timed out)"});
        if (line != null and std.mem.indexOf(u8, line.?, "signature INVALID") != null) {
            std.debug.print("  {s}REJECTED{s} - the tamper did not survive cm_sig_verify\n", .{ ansi_green, ansi_off });
        } else {
            std.debug.print("  {s}NOT REJECTED{s}\n", .{ ansi_red, ansi_off });
            failures += 1;
        }
    }

    // ── 5. the old anchor must be refused ────────────────────────────────────
    rule("4. Sign with the OLD demo key - the board must refuse that too");
    {
        var legacy_bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&legacy_bytes, LEGACY_KEY_HEX);
        const legacy = try derive.ec.PrivateKey.fromBytes(legacy_bytes);
        const legacy_pub = try derive.pubHex(legacy);
        std.debug.print("  legacy signer pubkey  {s}\n", .{&legacy_pub});

        const legacy_sig = try cert.signCell(legacy, &cell);
        const frame = try frameCell(a, &cell, &legacy_sig);
        defer a.free(frame);
        try inject(inject_port, frame);
        const line = try watcher.await_(&reject_needles, 12_000);
        std.debug.print("  board said: {s}\n", .{line orelse "(nothing - timed out)"});
        if (line != null and std.mem.indexOf(u8, line.?, "signature INVALID") != null) {
            std.debug.print("  {s}REJECTED{s} - the boards trust the fleet root, not the key they shipped with\n", .{ ansi_green, ansi_off });
        } else {
            std.debug.print("  {s}NOT REJECTED{s} - the anchor did not actually change\n", .{ ansi_red, ansi_off });
            failures += 1;
        }
    }

    rule("Result");
    if (failures == 0) {
        std.debug.print(
            "  A Zig-derived device identity was verified and installed by an\n" ++
                "  ESP32-C6 over a real radio hop. A tampered copy was refused, and so\n" ++
                "  was the same cert signed by the key the firmware used to trust.\n" ++
                "  Derivation, certificate, signature and framing all came from this\n" ++
                "  process. The board holds no private key.\n\n",
            .{},
        );
    } else {
        std.debug.print("  {s}{d} step(s) did not behave as required.{s}\n\n", .{ ansi_red, failures, ansi_off });
        std.process.exit(1);
    }
}
