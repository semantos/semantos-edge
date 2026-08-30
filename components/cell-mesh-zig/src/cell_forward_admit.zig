//! Should this forward cell be acted on? The whole decision, in one place.
//!
//! The rules used to live in the demo app: which check runs before which, what
//! each failure means, and which of them may mutate channel state. That is
//! protocol — it decides who may act on a cell — and it was three hand-ordered
//! sequences in C, one per version, sharing no code and free to drift.
//!
//! ## What this owns, and what it does not
//!
//! It owns the ORDER and the VERDICT, and it performs the protocol-state
//! mutations that are part of admitting a cell: the capability lookup, the
//! BRC-108 cert_hash binding, the channel commitment. Those are all already Zig.
//!
//! It does not touch the device. Blinking an LED, queueing a rule, stashing a
//! cell for relay, writing a log line, reading a clock — those stay with the
//! caller, driven by the verdict and hop this returns. That keeps this module
//! free of ESP-IDF, which is the rule the whole component follows.
//!
//! ## The one thing that must be injected
//!
//! ECDSA verify. secp256k1 verification lives in mbedTLS on the device, so it
//! arrives as a function pointer. Everything else this needs — SHA-256, the
//! capability table, the channel state machine — is native here, so a host test
//! can drive the entire sequence with a stub verifier and no hardware at all.
//! That is the point of moving it: every refusal below used to need three boards
//! and a serial cable to observe.

const std = @import("std");
const wire = @import("cell_wire.zig");
const forward = @import("cell_forward.zig");
const forward_v1 = @import("cell_forward_v1.zig");
const forward_v2 = @import("cell_forward_v2.zig");
const channel = @import("cell_channel.zig");
const capability = @import("cell_capability.zig");

/// ECDSA verify over secp256k1. 33-byte compressed pubkey, 32-byte hash,
/// 64-byte r||s. Returns 0 on success, matching cm_sig_verify.
pub const SigVerifyFn = *const fn (
    pubkey: [*]const u8,
    msg_hash: [*]const u8,
    sig: [*]const u8,
) callconv(.c) c_int;

// ── Verdicts ────────────────────────────────────────────────────────────────
//
// One code per distinct refusal, so the caller can log exactly what it logged
// before. A migration that collapsed two failures into one code would lose a
// diagnostic, and these are the messages a hardware run is read through.

pub const admit_relay: c_int = 0;
pub const admit_deliver: c_int = 1;
/// Not addressed to us, or not from our predecessor. Silent by design: every
/// board hears every broadcast, so this is the common case, not an error.
pub const admit_ignore: c_int = -1;
pub const admit_bad_route: c_int = -2;
pub const admit_no_cert: c_int = -3;
pub const admit_sig_invalid: c_int = -4;
pub const admit_cert_hash_mismatch: c_int = -5;
pub const admit_channel_reject: c_int = -6;
pub const admit_no_grant: c_int = -7;
pub const admit_flow_binding: c_int = -8;

pub const Admit = extern struct {
    verdict: c_int,
    hop: u8,
    next_mac: [6]u8,
    /// True when F6 fired: the all-zero demo channel id was replaced by a real
    /// one. It is a device-state mutation driven by the wire, and the caller
    /// needs to be able to say so on a serial cable. Costs nothing — this byte
    /// was struct padding.
    adopted_channel_id: bool,
    /// The channel state machine's own code, when verdict is channel_reject.
    /// Carried so the caller's log can name the reason rather than "rejected".
    channel_rc: c_int,
};

fn fail(out: *Admit, verdict: c_int) c_int {
    out.verdict = verdict;
    return verdict;
}

/// SHA-256 over the whole cell — the same bytes cm_sig_hash_cell covers.
/// Done natively rather than called out: it is a hash, not a device service.
fn hashCell(cell: [*]const u8, out: *[32]u8) void {
    std.crypto.hash.sha2.Sha256.hash(cell[0..wire.cell_size], out, .{});
}

// ── forward.v0 ──────────────────────────────────────────────────────────────

/// v0 is authenticated against the operator anchor and authorised
/// device-scoped: it carries no channel_id, so there is nothing to look up a
/// per-channel grant with.
///
/// ⚠ The grant check runs BEFORE the signature, which is the reverse of the
/// order this had in C. Deliberate: cm_sig_verify is ~267 ms and the grant check
/// is a scan of four table entries, so an unprovisioned board no longer burns a
/// quarter-second on every v0 addressed to it.
///
/// Two honest consequences, neither of which the earlier wording admitted.
/// First, a cell failing BOTH now reports the grant, not the signature. Second,
/// refusal LATENCY now discloses whether this board holds a relay grant — an
/// unprovisioned board answers in microseconds, a provisioned one in ~267 ms.
/// That is a side channel, and it is the price of not being trivially
/// CPU-exhausted by a stranger. It fails closed either way.
///
/// The domain is also read from a header this function has not yet verified.
/// That is safe because it only ever NARROWS which grant can match: a forged
/// domain finds no grant, and a real one still has to survive the signature.
pub export fn cm_forward_v0_admit(
    maybe_cell: ?[*]const u8,
    maybe_sig: ?[*]const u8,
    maybe_fwd: ?*const forward.Forward,
    maybe_my_mac: ?[*]const u8,
    maybe_sender_mac: ?[*]const u8,
    maybe_anchor_pubkey: ?[*]const u8,
    maybe_caps: ?*const capability.CapTable,
    now_ms: u64,
    maybe_verify: ?SigVerifyFn,
    maybe_out: ?*Admit,
) callconv(.c) c_int {
    const out = maybe_out orelse return admit_ignore;
    out.* = std.mem.zeroes(Admit);
    const cell = maybe_cell orelse return fail(out, admit_ignore);
    const sig = maybe_sig orelse return fail(out, admit_ignore);
    const fwd = maybe_fwd orelse return fail(out, admit_ignore);
    const verify = maybe_verify orelse return fail(out, admit_sig_invalid);

    const loc = forward.cm_forward_locate(
        &fwd.segments, fwd.total_hops, maybe_my_mac, maybe_sender_mac,
        &out.hop, &out.next_mac,
    );
    if (loc == forward.locate_bad_route) return fail(out, admit_bad_route);
    if (loc < 0) return fail(out, admit_ignore);

    const domain = wire.flags(cell[0..wire.cell_size]);
    if (!capability.cm_cap_any_valid(maybe_caps, capability.route_fwd_v1, domain, now_ms)) {
        return fail(out, admit_no_grant);
    }

    var hash: [32]u8 = undefined;
    hashCell(cell, &hash);
    const anchor = maybe_anchor_pubkey orelse return fail(out, admit_sig_invalid);
    if (verify(anchor, &hash, sig) != 0) return fail(out, admit_sig_invalid);

    out.verdict = if (loc == forward.locate_relay) admit_relay else admit_deliver;
    return out.verdict;
}

// ── shared: the capability + binding + channel tail of v1 and v2 ────────────

/// Everything both v1 and v2 do once they know their hop: resolve the grant,
/// verify the signature against the key that grant names, check the BRC-108
/// binding, and apply the commitment.
///
/// `sig_cell` is the cell whose signature is being checked, which for v2 is
/// Cell A and not the cell that triggered the handler.
fn admitCapabilityTail(
    sig_cell: [*]const u8,
    sig: [*]const u8,
    commitment: *const channel.ChannelCommitment,
    domain: u32,
    caps: ?*capability.CapTable,
    chan: ?*channel.Channel,
    now_ms: u64,
    verify: SigVerifyFn,
    out: *Admit,
) c_int {
    // Cheapest first: a device with no grant for this channel has nothing to
    // verify against, and the verify is ~267 ms.
    const edge_pk = capability.cm_cap_lookup(
        caps, &commitment.channel_id, capability.route_fwd_v1, now_ms, domain,
    ) orelse return fail(out, admit_no_cert);

    var hash: [32]u8 = undefined;
    hashCell(sig_cell, &hash);
    if (verify(edge_pk, &hash, sig) != 0) return fail(out, admit_sig_invalid);

    // BRC-108: the commitment must name the cert that authorised the key.
    if (capability.cm_cap_cert_hash(
        caps, &commitment.channel_id, capability.route_fwd_v1, now_ms, domain,
    )) |stored| {
        if (!std.mem.eql(u8, stored[0..32], commitment.cert_hash[0..])) {
            return fail(out, admit_cert_hash_mismatch);
        }
    }

    if (chan) |c| {
        // F6: adopt a real channel id over the all-zero demo sentinel. Only
        // once, only from open, and only after the capability check above has
        // already proved a cert exists for that exact id.
        const zero16 = [_]u8{0} ** 16;
        if (c.state == channel.state_open and
            std.mem.eql(u8, c.channel_id[0..], zero16[0..]) and
            !std.mem.eql(u8, commitment.channel_id[0..], zero16[0..]))
        {
            @memcpy(c.channel_id[0..], commitment.channel_id[0..]);
            out.adopted_channel_id = true;
        }
        const crc = channel.cm_channel_apply_commitment(c, commitment, now_ms);
        if (crc != channel.ok) {
            out.channel_rc = crc;
            return fail(out, admit_channel_reject);
        }
    }
    return admit_relay; // caller overwrites with relay/deliver from locate
}

// ── forward.v1 ──────────────────────────────────────────────────────────────

pub export fn cm_forward_v1_admit(
    maybe_cell: ?[*]const u8,
    maybe_sig: ?[*]const u8,
    maybe_fv1: ?*const forward_v1.ForwardV1,
    maybe_my_mac: ?[*]const u8,
    maybe_sender_mac: ?[*]const u8,
    maybe_caps: ?*capability.CapTable,
    maybe_chan: ?*channel.Channel,
    now_ms: u64,
    maybe_verify: ?SigVerifyFn,
    maybe_out: ?*Admit,
) callconv(.c) c_int {
    const out = maybe_out orelse return admit_ignore;
    out.* = std.mem.zeroes(Admit);
    const cell = maybe_cell orelse return fail(out, admit_ignore);
    const sig = maybe_sig orelse return fail(out, admit_ignore);
    const fv1 = maybe_fv1 orelse return fail(out, admit_ignore);
    const verify = maybe_verify orelse return fail(out, admit_sig_invalid);

    const loc = forward.cm_forward_locate(
        &fv1.segments, fv1.total_hops, maybe_my_mac, maybe_sender_mac,
        &out.hop, &out.next_mac,
    );
    if (loc == forward.locate_bad_route) return fail(out, admit_bad_route);
    if (loc < 0) return fail(out, admit_ignore);

    // hop_commitments is indexed unbounded here on purpose, and it is only safe
    // because cm_forward_locate refuses total_hops > max_hops and never reports
    // a hop equal to max_hops. hop_commitments and segments are both max_hops
    // long. ReleaseSmall turns bounds checks off, so if that invariant ever
    // moves this becomes a silent out-of-bounds read — the C used to carry an
    // explicit `if (my_hop < CM_FORWARD_MAX_HOPS)` guard here.
    std.debug.assert(out.hop < forward.max_hops);
    const rc = admitCapabilityTail(
        cell, sig, &fv1.hop_commitments[out.hop], wire.flags(cell[0..wire.cell_size]),
        maybe_caps, maybe_chan, now_ms, verify, out,
    );
    if (rc < 0) return rc;

    out.verdict = if (loc == forward.locate_relay) admit_relay else admit_deliver;
    return out.verdict;
}

// ── forward.v2 ──────────────────────────────────────────────────────────────

/// `primary_cell` is Cell A: signed, and the source of BOTH the signature and
/// the capability domain. Cell B's header carries no signature and the flow_id
/// binding covers only its payload, so nothing here may be decided from it.
pub export fn cm_forward_v2_admit(
    maybe_primary_cell: ?[*]const u8,
    maybe_primary_sig: ?[*]const u8,
    maybe_pa: ?*const forward_v2.ForwardV2,
    maybe_routing_payload: ?[*]const u8,
    routing_payload_len: usize,
    maybe_pb: ?*const forward_v2.RoutingCont,
    maybe_my_mac: ?[*]const u8,
    maybe_sender_mac: ?[*]const u8,
    maybe_caps: ?*capability.CapTable,
    maybe_chan: ?*channel.Channel,
    now_ms: u64,
    maybe_verify: ?SigVerifyFn,
    maybe_out: ?*Admit,
) callconv(.c) c_int {
    const out = maybe_out orelse return admit_ignore;
    out.* = std.mem.zeroes(Admit);
    const primary_cell = maybe_primary_cell orelse return fail(out, admit_ignore);
    const primary_sig = maybe_primary_sig orelse return fail(out, admit_ignore);
    const pa = maybe_pa orelse return fail(out, admit_ignore);
    const pb = maybe_pb orelse return fail(out, admit_ignore);
    const verify = maybe_verify orelse return fail(out, admit_sig_invalid);

    const loc = forward.cm_forward_locate(
        &pb.segments, pa.total_hops, maybe_my_mac, maybe_sender_mac,
        &out.hop, &out.next_mac,
    );
    if (loc == forward.locate_bad_route) return fail(out, admit_bad_route);
    if (loc < 0) return fail(out, admit_ignore);

    // The binding, before anything expensive: Cell B's routing content must
    // hash to the flow_id the origin signed into Cell A.
    var want_flow: [16]u8 = undefined;
    if (forward_v2.cm_routing_cont_flow_id(
        maybe_routing_payload, routing_payload_len, &want_flow,
    ) != 0) return fail(out, admit_flow_binding);
    if (!std.mem.eql(u8, want_flow[0..], pa.flow_id[0..])) {
        return fail(out, admit_flow_binding);
    }

    // Same invariant as v1: locate guarantees hop < max_hops.
    std.debug.assert(out.hop < forward.max_hops);
    // Domain from Cell A — the signed half. See the note above.
    const rc = admitCapabilityTail(
        primary_cell, primary_sig, &pb.hop_commitments[out.hop],
        wire.flags(primary_cell[0..wire.cell_size]),
        maybe_caps, maybe_chan, now_ms, verify, out,
    );
    if (rc < 0) return rc;

    out.verdict = if (loc == forward.locate_relay) admit_relay else admit_deliver;
    return out.verdict;
}

// ── Tests ───────────────────────────────────────────────────────────────────
//
// Every refusal below used to be observable only on three boards with a serial
// cable attached. The signature verify is the only thing that could not run on a
// host, and it is a function pointer, so it becomes two lines of stub.

var stub_accepts: bool = true;
var stub_calls: usize = 0;
fn stubVerify(_: [*]const u8, _: [*]const u8, _: [*]const u8) callconv(.c) c_int {
    stub_calls += 1;
    return if (stub_accepts) 0 else -1;
}

const MAC_A = [6]u8{ 0xaa, 0, 0, 0, 0, 1 };
const MAC_B = [6]u8{ 0xbb, 0, 0, 0, 0, 2 };
const MAC_C = [6]u8{ 0xcc, 0, 0, 0, 0, 3 };
const DOMAIN_RELAY: u32 = 0x00f10001;
const DOMAIN_OTHER: u32 = 0x00f10002;

fn makeCell(domain: u32) [wire.cell_size]u8 {
    var c: [wire.cell_size]u8 = [_]u8{0} ** wire.cell_size;
    wire.cm_cell_init(&c);
    wire.setFlags(c[0..], domain);
    return c;
}

/// A cap table holding one grant for `channel_id` in `domain`.
///
/// Also copies the stored BRC-108 cert_hash into `out_cert_hash` when given, so
/// a test can build a commitment that actually binds — leaving it zeroed makes
/// every v1/v2 case fail at the binding instead of where it is aimed.
fn tableWithGrant(t: *capability.CapTable, channel_id: [16]u8, domain: u32) void {
    capability.cm_cap_table_init(t);
    var payload: [capability.payload_bytes]u8 = [_]u8{0} ** capability.payload_bytes;
    payload[0] = 0x02;
    @memcpy(payload[33..49], channel_id[0..]);
    wire.writeU64(payload[49..][0..8], std.math.maxInt(u64));
    payload[57] = capability.route_fwd_v1;
    _ = capability.cm_cap_install(t, &payload, payload.len, 0, domain);
}

/// The cert_hash the table stored for this grant, so a commitment can bind to it.
fn storedCertHash(t: *capability.CapTable, channel_id: [16]u8, domain: u32) [32]u8 {
    const p = capability.cm_cap_cert_hash(
        t, &channel_id, capability.route_fwd_v1, 0, domain,
    ).?;
    var out: [32]u8 = undefined;
    @memcpy(out[0..], p[0..32]);
    return out;
}

test "v0 admit: a board with no grant is refused before the 267ms verify" {
    const testing = std.testing;
    stub_accepts = true;
    stub_calls = 0;

    var fwd = std.mem.zeroes(forward.Forward);
    fwd.total_hops = 2;
    fwd.segments[0] = MAC_B;
    fwd.segments[1] = MAC_C;
    const cell = makeCell(DOMAIN_RELAY);
    const sig = [_]u8{0} ** 64;

    var caps: capability.CapTable = undefined;
    capability.cm_cap_table_init(&caps);   // empty — no grant
    var out: Admit = undefined;

    try testing.expectEqual(admit_no_grant, cm_forward_v0_admit(
        &cell, &sig, &fwd, &MAC_B, &MAC_A, &[_]u8{0} ** 33, &caps, 0, stubVerify, &out));
    // The point of the ordering: an unprovisioned board does not pay for a
    // signature verify it will discard.
    try testing.expectEqual(@as(usize, 0), stub_calls);
}

test "v0 admit: a bad signature is refused even with a grant" {
    const testing = std.testing;
    stub_accepts = false;
    stub_calls = 0;

    var fwd = std.mem.zeroes(forward.Forward);
    fwd.total_hops = 2;
    fwd.segments[0] = MAC_B;
    fwd.segments[1] = MAC_C;
    const cell = makeCell(DOMAIN_RELAY);
    const sig = [_]u8{0} ** 64;

    var caps: capability.CapTable = undefined;
    tableWithGrant(&caps, [_]u8{0} ** 16, DOMAIN_RELAY);
    var out: Admit = undefined;

    try testing.expectEqual(admit_sig_invalid, cm_forward_v0_admit(
        &cell, &sig, &fwd, &MAC_B, &MAC_A, &[_]u8{0} ** 33, &caps, 0, stubVerify, &out));
    try testing.expectEqual(@as(usize, 1), stub_calls);
}

test "v0 admit: the grant must be in the CELL's domain" {
    const testing = std.testing;
    stub_accepts = true;

    var fwd = std.mem.zeroes(forward.Forward);
    fwd.total_hops = 2;
    fwd.segments[0] = MAC_B;
    fwd.segments[1] = MAC_C;
    var caps: capability.CapTable = undefined;
    tableWithGrant(&caps, [_]u8{0} ** 16, DOMAIN_RELAY);
    var out: Admit = undefined;
    const sig = [_]u8{0} ** 64;

    const right = makeCell(DOMAIN_RELAY);
    try testing.expectEqual(admit_relay, cm_forward_v0_admit(
        &right, &sig, &fwd, &MAC_B, &MAC_A, &[_]u8{0} ** 33, &caps, 0, stubVerify, &out));

    // Same grant, cell declares another domain — the grant does not carry over.
    const wrong = makeCell(DOMAIN_OTHER);
    try testing.expectEqual(admit_no_grant, cm_forward_v0_admit(
        &wrong, &sig, &fwd, &MAC_B, &MAC_A, &[_]u8{0} ** 33, &caps, 0, stubVerify, &out));
}

test "v0 admit: relay names the next hop; the last hop delivers" {
    const testing = std.testing;
    stub_accepts = true;

    var fwd = std.mem.zeroes(forward.Forward);
    fwd.total_hops = 2;
    fwd.segments[0] = MAC_B;
    fwd.segments[1] = MAC_C;
    const cell = makeCell(DOMAIN_RELAY);
    const sig = [_]u8{0} ** 64;
    var caps: capability.CapTable = undefined;
    tableWithGrant(&caps, [_]u8{0} ** 16, DOMAIN_RELAY);
    var out: Admit = undefined;

    try testing.expectEqual(admit_relay, cm_forward_v0_admit(
        &cell, &sig, &fwd, &MAC_B, &MAC_A, &[_]u8{0} ** 33, &caps, 0, stubVerify, &out));
    try testing.expectEqual(@as(u8, 0), out.hop);
    try testing.expectEqualSlices(u8, MAC_C[0..], out.next_mac[0..]);

    // C, taking it from B — its predecessor.
    try testing.expectEqual(admit_deliver, cm_forward_v0_admit(
        &cell, &sig, &fwd, &MAC_C, &MAC_B, &[_]u8{0} ** 33, &caps, 0, stubVerify, &out));
    try testing.expectEqual(@as(u8, 1), out.hop);
}

test "v0 admit: the origin's broadcast does not reach the last hop first" {
    const testing = std.testing;
    stub_accepts = true;
    var fwd = std.mem.zeroes(forward.Forward);
    fwd.total_hops = 2;
    fwd.segments[0] = MAC_B;
    fwd.segments[1] = MAC_C;
    const cell = makeCell(DOMAIN_RELAY);
    const sig = [_]u8{0} ** 64;
    var caps: capability.CapTable = undefined;
    tableWithGrant(&caps, [_]u8{0} ** 16, DOMAIN_RELAY);
    var out: Admit = undefined;

    // C hears A directly. Silent ignore, not an error — every board hears this.
    try testing.expectEqual(admit_ignore, cm_forward_v0_admit(
        &cell, &sig, &fwd, &MAC_C, &MAC_A, &[_]u8{0} ** 33, &caps, 0, stubVerify, &out));
}

test "v1 admit: no cert for the channel refuses before verifying" {
    const testing = std.testing;
    stub_accepts = true;
    stub_calls = 0;

    var fv1 = std.mem.zeroes(forward_v1.ForwardV1);
    fv1.total_hops = 2;
    fv1.segments[0] = MAC_B;
    fv1.segments[1] = MAC_C;
    fv1.hop_commitments[0].channel_id = [_]u8{0xa5} ** 16;

    const cell = makeCell(DOMAIN_RELAY);
    const sig = [_]u8{0} ** 64;
    var caps: capability.CapTable = undefined;
    capability.cm_cap_table_init(&caps);
    var out: Admit = undefined;

    try testing.expectEqual(admit_no_cert, cm_forward_v1_admit(
        &cell, &sig, &fv1, &MAC_B, &MAC_A, &caps, null, 0, stubVerify, &out));
    try testing.expectEqual(@as(usize, 0), stub_calls);
}

test "v1 admit: the BRC-108 cert_hash binding is enforced" {
    const testing = std.testing;
    stub_accepts = true;
    const chid = [_]u8{0xa5} ** 16;

    var fv1 = std.mem.zeroes(forward_v1.ForwardV1);
    fv1.total_hops = 2;
    fv1.segments[0] = MAC_B;
    fv1.segments[1] = MAC_C;
    fv1.hop_commitments[0].channel_id = chid;
    fv1.hop_commitments[0].cert_hash = [_]u8{0xff} ** 32;  // not the stored one

    const cell = makeCell(DOMAIN_RELAY);
    const sig = [_]u8{0} ** 64;
    var caps: capability.CapTable = undefined;
    tableWithGrant(&caps, chid, DOMAIN_RELAY);
    var out: Admit = undefined;

    try testing.expectEqual(admit_cert_hash_mismatch, cm_forward_v1_admit(
        &cell, &sig, &fv1, &MAC_B, &MAC_A, &caps, null, 0, stubVerify, &out));
}

test "v2 admit: the capability domain comes from Cell A, never from Cell B" {
    const testing = std.testing;
    stub_accepts = true;
    const chid = [_]u8{0xa5} ** 16;

    // Cell B's routing payload, with a real flow_id derived from it.
    var pb_payload: [forward_v2.routing_used_bytes]u8 =
        [_]u8{0} ** forward_v2.routing_used_bytes;
    @memcpy(pb_payload[24..30], MAC_B[0..]);
    @memcpy(pb_payload[30..36], MAC_C[0..]);
    @memcpy(pb_payload[48..64], chid[0..]);
    var flow: [16]u8 = undefined;
    _ = forward_v2.cm_routing_cont_flow_id(&pb_payload, pb_payload.len, &flow);
    @memcpy(pb_payload[0..16], flow[0..]);

    var pb = std.mem.zeroes(forward_v2.RoutingCont);
    @memcpy(pb.flow_id[0..], flow[0..]);
    pb.segments[0] = MAC_B;
    pb.segments[1] = MAC_C;
    pb.hop_commitments[0].channel_id = chid;

    var pa = std.mem.zeroes(forward_v2.ForwardV2);
    pa.total_hops = 2;
    @memcpy(pa.flow_id[0..], flow[0..]);

    // Cell A on the relay rail. The grant is on the relay rail too.
    const cell_a = makeCell(DOMAIN_RELAY);
    const sig = [_]u8{0} ** 64;
    var caps: capability.CapTable = undefined;
    tableWithGrant(&caps, chid, DOMAIN_RELAY);
    pb.hop_commitments[0].cert_hash = storedCertHash(&caps, chid, DOMAIN_RELAY);
    var out: Admit = undefined;

    try testing.expectEqual(admit_relay, cm_forward_v2_admit(
        &cell_a, &sig, &pa, &pb_payload, pb_payload.len, &pb,
        &MAC_B, &MAC_A, &caps, null, 0, stubVerify, &out));

    // Now the attack: Cell A moved to another domain. There is no grant there,
    // so it must be refused — proving the domain is read from A. Cell B is not
    // even consulted for it.
    const cell_a_other = makeCell(DOMAIN_OTHER);
    try testing.expectEqual(admit_no_cert, cm_forward_v2_admit(
        &cell_a_other, &sig, &pa, &pb_payload, pb_payload.len, &pb,
        &MAC_B, &MAC_A, &caps, null, 0, stubVerify, &out));
}

test "v2 admit: tampering Cell B's routing breaks the flow_id binding" {
    const testing = std.testing;
    stub_accepts = true;
    const chid = [_]u8{0xa5} ** 16;

    var pb_payload: [forward_v2.routing_used_bytes]u8 =
        [_]u8{0} ** forward_v2.routing_used_bytes;
    @memcpy(pb_payload[24..30], MAC_B[0..]);
    @memcpy(pb_payload[30..36], MAC_C[0..]);
    @memcpy(pb_payload[48..64], chid[0..]);
    var flow: [16]u8 = undefined;
    _ = forward_v2.cm_routing_cont_flow_id(&pb_payload, pb_payload.len, &flow);
    @memcpy(pb_payload[0..16], flow[0..]);

    var pb = std.mem.zeroes(forward_v2.RoutingCont);
    @memcpy(pb.flow_id[0..], flow[0..]);
    pb.segments[0] = MAC_B;
    pb.segments[1] = MAC_C;
    pb.hop_commitments[0].channel_id = chid;

    var pa = std.mem.zeroes(forward_v2.ForwardV2);
    pa.total_hops = 2;
    @memcpy(pa.flow_id[0..], flow[0..]);

    // Raise hop 0's device_share AFTER the flow_id was fixed into Cell A. This
    // is the payment-inflation attack, and it needed three boards to observe.
    wire.writeU32(pb_payload[48 + 16 + 4 ..][0..4], 9999);

    const cell_a = makeCell(DOMAIN_RELAY);
    const sig = [_]u8{0} ** 64;
    var caps: capability.CapTable = undefined;
    tableWithGrant(&caps, chid, DOMAIN_RELAY);
    var out: Admit = undefined;

    try testing.expectEqual(admit_flow_binding, cm_forward_v2_admit(
        &cell_a, &sig, &pa, &pb_payload, pb_payload.len, &pb,
        &MAC_B, &MAC_A, &caps, null, 0, stubVerify, &out));
}
