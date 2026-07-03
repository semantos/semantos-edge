pub const cell_wire = @import("cell_wire.zig");
pub const cell_meter = @import("cell_meter.zig");
pub const cell_ring = @import("cell_ring.zig");
pub const cell_channel = @import("cell_channel.zig");
pub const cell_forward = @import("cell_forward.zig");
pub const cell_forward_v1 = @import("cell_forward_v1.zig");
pub const cell_forward_v2 = @import("cell_forward_v2.zig");
pub const cell_frame = @import("cell_frame.zig");
pub const cell_capability = @import("cell_capability.zig");
pub const cell_rules = @import("cell_rules.zig");
pub const cell_mnca = @import("cell_mnca.zig");

comptime {
    _ = cell_wire.cm_cell_init;
    _ = cell_wire.cm_is_cell;

    _ = cell_meter.cm_meter_init;
    _ = cell_meter.cm_meter_start;
    _ = cell_meter.cm_meter_tick;
    _ = cell_meter.cm_meter_stop;
    _ = cell_meter.cm_meter_consumed_sats;
    _ = cell_meter.cm_meter_consumed_msat;
    _ = cell_meter.cm_meter_authorized;

    _ = cell_ring.cm_ring_init;
    _ = cell_ring.cm_ring_push;
    _ = cell_ring.cm_ring_visit_newest_first;
    _ = cell_ring.cm_ring_count_recent;

    _ = cell_channel.cm_channel_open_encode;
    _ = cell_channel.cm_channel_open_decode;
    _ = cell_channel.cm_channel_commitment_encode;
    _ = cell_channel.cm_channel_commitment_decode;
    _ = cell_channel.cm_channel_close_encode;
    _ = cell_channel.cm_channel_close_decode;
    _ = cell_channel.cm_channel_init;
    _ = cell_channel.cm_channel_apply_open;
    _ = cell_channel.cm_channel_apply_commitment;
    _ = cell_channel.cm_channel_apply_close;
    _ = cell_channel.cm_channel_tick_expiry;
    _ = cell_channel.cm_channel_validate_utxo_ref;

    _ = cell_forward.cm_forward_encode;
    _ = cell_forward.cm_forward_decode;
    _ = cell_forward.cm_forward_step;

    _ = cell_forward_v1.cm_forward_v1_encode;
    _ = cell_forward_v1.cm_forward_v1_decode;
    _ = cell_forward_v1.cm_forward_v1_step;

    _ = cell_forward_v2.cm_forward_v2_encode;
    _ = cell_forward_v2.cm_forward_v2_decode;
    _ = cell_forward_v2.cm_routing_cont_encode;
    _ = cell_forward_v2.cm_routing_cont_decode;
    _ = cell_forward_v2.cm_forward_v2_step;

    _ = cell_frame.cm_frame_split;
    _ = cell_frame.cm_reasm_init;
    _ = cell_frame.cm_reasm_push;

    _ = cell_capability.cm_cap_table_init;
    _ = cell_capability.cm_cap_install;
    _ = cell_capability.cm_cap_lookup;
    _ = cell_capability.cm_cap_cert_hash;
    _ = cell_capability.cm_cap_evict_expired;
    _ = cell_capability.cm_cap_valid_count;

    _ = cell_rules.cm_rules_init;
    _ = cell_rules.cm_rules_install;
    _ = cell_rules.cm_rules_remove;
    _ = cell_rules.cm_rule_encode;
    _ = cell_rules.cm_rule_decode;
    _ = cell_rules.cm_rule_equals;
    _ = cell_rules.cm_rules_evaluate;

    _ = cell_mnca.CM_MNCA_DEFAULT_RULE;
    _ = cell_mnca.cm_mnca_tile_init_random;
    _ = cell_mnca.cm_mnca_step;
    _ = cell_mnca.cm_mnca_tile_encode;
    _ = cell_mnca.cm_mnca_tile_decode;
    _ = cell_mnca.cm_mnca_tile_hash;
    _ = cell_mnca.cm_mnca_quorum_init;
    _ = cell_mnca.cm_mnca_quorum_update;
}
