const std = @import("std");
const wire = @import("cell_wire.zig");

const state_closed: c_int = 0;
const state_open: c_int = 1;
const state_active: c_int = 2;
const state_expired: c_int = 3;

const ok: c_int = 0;
const err_bad_state: c_int = -1;
const err_bad_id: c_int = -2;
const err_stale_seq: c_int = -3;
const err_non_mono: c_int = -4;
const err_overflow: c_int = -5;
const err_expired: c_int = -6;
const err_seq_match: c_int = -7;

pub const Channel = extern struct {
    state: c_int,
    channel_id: [16]u8,
    peer_pubkey: [33]u8,
    total_capacity: u32,
    open_locktime_ms: u64,
    current_seq: u32,
    device_share: u32,
    user_share: u32,
    expiry_ms: u64,
    commitments_received: u32,
    commitments_rejected: u32,
};

pub const ChannelOpen = extern struct {
    channel_id: [16]u8,
    peer_pubkey: [33]u8,
    initial_locktime_ms: u64,
    total_capacity: u32,
};

pub const ChannelCommitment = extern struct {
    channel_id: [16]u8,
    seq: u32,
    device_share: u32,
    user_share: u32,
    expiry_ms: u64,
    cert_hash: [32]u8,
};

pub const ChannelClose = extern struct {
    channel_id: [16]u8,
    final_seq: u32,
    final_device_share: u32,
};

pub export fn cm_channel_open_encode(maybe_in: ?*const ChannelOpen, maybe_out: ?[*]u8) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    @memcpy(out[0..16], in.channel_id[0..]);
    @memcpy(out[16..49], in.peer_pubkey[0..]);
    wire.writeU64(out[49..][0..8], in.initial_locktime_ms);
    wire.writeU32(out[57..][0..4], in.total_capacity);
    return 0;
}

pub export fn cm_channel_open_decode(maybe_in: ?[*]const u8, maybe_out: ?*ChannelOpen) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    @memcpy(out.channel_id[0..], in[0..16]);
    @memcpy(out.peer_pubkey[0..], in[16..49]);
    out.initial_locktime_ms = wire.readU64(in[49..][0..8]);
    out.total_capacity = wire.readU32(in[57..][0..4]);
    return 0;
}

pub export fn cm_channel_commitment_encode(
    maybe_in: ?*const ChannelCommitment,
    maybe_out: ?[*]u8,
) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    @memcpy(out[0..16], in.channel_id[0..]);
    wire.writeU32(out[16..][0..4], in.seq);
    wire.writeU32(out[20..][0..4], in.device_share);
    wire.writeU32(out[24..][0..4], in.user_share);
    wire.writeU64(out[28..][0..8], in.expiry_ms);
    @memcpy(out[36..68], in.cert_hash[0..]);
    return 0;
}

pub export fn cm_channel_commitment_decode(
    maybe_in: ?[*]const u8,
    maybe_out: ?*ChannelCommitment,
) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    @memcpy(out.channel_id[0..], in[0..16]);
    out.seq = wire.readU32(in[16..][0..4]);
    out.device_share = wire.readU32(in[20..][0..4]);
    out.user_share = wire.readU32(in[24..][0..4]);
    out.expiry_ms = wire.readU64(in[28..][0..8]);
    @memcpy(out.cert_hash[0..], in[36..68]);
    return 0;
}

pub export fn cm_channel_close_encode(maybe_in: ?*const ChannelClose, maybe_out: ?[*]u8) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    @memcpy(out[0..16], in.channel_id[0..]);
    wire.writeU32(out[16..][0..4], in.final_seq);
    wire.writeU32(out[20..][0..4], in.final_device_share);
    return 0;
}

pub export fn cm_channel_close_decode(maybe_in: ?[*]const u8, maybe_out: ?*ChannelClose) callconv(.c) c_int {
    const in = maybe_in orelse return -1;
    const out = maybe_out orelse return -1;
    @memcpy(out.channel_id[0..], in[0..16]);
    out.final_seq = wire.readU32(in[16..][0..4]);
    out.final_device_share = wire.readU32(in[20..][0..4]);
    return 0;
}

pub export fn cm_channel_init(maybe_c: ?*Channel) callconv(.c) void {
    const c = maybe_c orelse return;
    c.* = std.mem.zeroes(Channel);
    c.state = state_closed;
}

pub export fn cm_channel_apply_open(maybe_c: ?*Channel, maybe_op: ?*const ChannelOpen) callconv(.c) c_int {
    const c = maybe_c orelse return err_bad_state;
    const op = maybe_op orelse return err_bad_state;
    if (c.state != state_closed) return err_bad_state;

    c.channel_id = op.channel_id;
    c.peer_pubkey = op.peer_pubkey;
    c.total_capacity = op.total_capacity;
    c.open_locktime_ms = op.initial_locktime_ms;
    c.current_seq = 0;
    c.device_share = 0;
    c.user_share = 0;
    c.expiry_ms = 0;
    c.state = state_open;
    return ok;
}

pub export fn cm_channel_apply_commitment(
    maybe_c: ?*Channel,
    maybe_cm: ?*const ChannelCommitment,
    now_ms: u64,
) callconv(.c) c_int {
    const c = maybe_c orelse return err_bad_state;
    const cm = maybe_cm orelse return err_bad_state;
    if (c.state != state_open and c.state != state_active) {
        c.commitments_rejected +%= 1;
        return err_bad_state;
    }
    if (!std.mem.eql(u8, c.channel_id[0..], cm.channel_id[0..])) {
        c.commitments_rejected +%= 1;
        return err_bad_id;
    }
    if (cm.seq <= c.current_seq) {
        c.commitments_rejected +%= 1;
        return err_stale_seq;
    }
    if (cm.device_share < c.device_share) {
        c.commitments_rejected +%= 1;
        return err_non_mono;
    }
    if (@as(u64, cm.device_share) + @as(u64, cm.user_share) > @as(u64, c.total_capacity)) {
        c.commitments_rejected +%= 1;
        return err_overflow;
    }
    if (cm.expiry_ms <= now_ms) {
        c.commitments_rejected +%= 1;
        return err_expired;
    }

    c.current_seq = cm.seq;
    c.device_share = cm.device_share;
    c.user_share = cm.user_share;
    c.expiry_ms = cm.expiry_ms;
    c.commitments_received +%= 1;
    c.state = state_active;
    return ok;
}

pub export fn cm_channel_apply_close(maybe_c: ?*Channel, maybe_cl: ?*const ChannelClose) callconv(.c) c_int {
    const c = maybe_c orelse return err_bad_state;
    const cl = maybe_cl orelse return err_bad_state;
    if (c.state != state_active and c.state != state_expired) return err_bad_state;
    if (!std.mem.eql(u8, c.channel_id[0..], cl.channel_id[0..])) return err_bad_id;
    if (cl.final_seq != c.current_seq or cl.final_device_share != c.device_share) return err_seq_match;
    c.state = state_closed;
    return ok;
}

pub export fn cm_channel_tick_expiry(maybe_c: ?*Channel, now_ms: u64) callconv(.c) void {
    const c = maybe_c orelse return;
    if (c.state == state_active and now_ms > c.expiry_ms) {
        c.state = state_expired;
    }
}

pub export fn cm_channel_validate_utxo_ref(maybe_channel_id: ?[*]const u8, maybe_txid_display: ?[*]const u8) callconv(.c) bool {
    const channel_id = maybe_channel_id orelse return false;
    const txid_display = maybe_txid_display orelse return false;
    return std.mem.eql(u8, channel_id[0..16], txid_display[0..16]);
}
