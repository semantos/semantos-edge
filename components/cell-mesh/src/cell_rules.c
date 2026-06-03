// cell_rules.c — fixed-vocabulary rules engine. Pure C, no I/O.

#include "cell_rules.h"
#include "cell_wire.h"

#include <string.h>

// ── Wire format offsets (match the layout documented in cell_rules.h) ─

#define R_OFF_VERSION              0u
#define R_OFF_TRIGGER_KIND         1u
#define R_OFF_TRIGGER_TYPE_HASH    2u
#define R_OFF_QUORUM_N             34u
#define R_OFF_QUORUM_WINDOW_MS     35u
#define R_OFF_QUORUM_DISTINCT      37u
#define R_OFF_EFFECT_KIND          38u
#define R_OFF_BLINK_DURATION_MS    39u
#define R_OFF_EMIT_TYPE_HASH       41u
#define R_OFF_EMIT_PAYLOAD_LEN     73u
#define R_OFF_EMIT_PAYLOAD         75u

int cm_rule_encode(const cm_rule_t *rule, uint8_t out_buf[CM_RULE_ENCODED_SIZE]) {
    if (!rule || !out_buf) return -1;

    memset(out_buf, 0, CM_RULE_ENCODED_SIZE);
    out_buf[R_OFF_VERSION]      = CM_RULE_SCHEMA_VERSION;
    out_buf[R_OFF_TRIGGER_KIND] = (uint8_t)rule->trigger_kind;
    memcpy(out_buf + R_OFF_TRIGGER_TYPE_HASH, rule->trigger_type_hash, 32);

    if (rule->trigger_kind == CM_TRIGGER_QUORUM) {
        out_buf[R_OFF_QUORUM_N] = rule->quorum_n;
        cm_write_u16(out_buf + R_OFF_QUORUM_WINDOW_MS, rule->quorum_window_ms);
        out_buf[R_OFF_QUORUM_DISTINCT] = rule->quorum_distinct_peers ? 1 : 0;
    }

    out_buf[R_OFF_EFFECT_KIND] = (uint8_t)rule->effect.kind;
    switch (rule->effect.kind) {
        case CM_EFFECT_BLINK:
            cm_write_u16(out_buf + R_OFF_BLINK_DURATION_MS, rule->effect.as.blink.duration_ms);
            break;
        case CM_EFFECT_EMIT:
            memcpy(out_buf + R_OFF_EMIT_TYPE_HASH, rule->effect.as.emit.type_hash, 32);
            cm_write_u16(out_buf + R_OFF_EMIT_PAYLOAD_LEN, rule->effect.as.emit.payload_len);
            if (rule->effect.as.emit.payload_len > 0
                && rule->effect.as.emit.payload_len <= 64) {
                memcpy(out_buf + R_OFF_EMIT_PAYLOAD,
                       rule->effect.as.emit.payload,
                       rule->effect.as.emit.payload_len);
            }
            break;
        case CM_EFFECT_NONE:
        default:
            break;
    }
    return 0;
}

int cm_rule_decode(const uint8_t buf[CM_RULE_ENCODED_SIZE], cm_rule_t *out_rule) {
    if (!buf || !out_rule) return -1;
    if (buf[R_OFF_VERSION] != CM_RULE_SCHEMA_VERSION) return -1;

    memset(out_rule, 0, sizeof(*out_rule));
    out_rule->occupied = false; // caller installs to set this

    uint8_t tk = buf[R_OFF_TRIGGER_KIND];
    if (tk != CM_TRIGGER_ON_TYPE && tk != CM_TRIGGER_QUORUM) return -1;
    out_rule->trigger_kind = (cm_trigger_kind_t)tk;

    memcpy(out_rule->trigger_type_hash, buf + R_OFF_TRIGGER_TYPE_HASH, 32);

    if (tk == CM_TRIGGER_QUORUM) {
        out_rule->quorum_n              = buf[R_OFF_QUORUM_N];
        out_rule->quorum_window_ms      = cm_read_u16(buf + R_OFF_QUORUM_WINDOW_MS);
        out_rule->quorum_distinct_peers = buf[R_OFF_QUORUM_DISTINCT] != 0;
    }

    uint8_t ek = buf[R_OFF_EFFECT_KIND];
    if (ek != CM_EFFECT_BLINK && ek != CM_EFFECT_EMIT) return -1;
    out_rule->effect.kind = (cm_effect_kind_t)ek;

    switch (ek) {
        case CM_EFFECT_BLINK:
            out_rule->effect.as.blink.duration_ms = cm_read_u16(buf + R_OFF_BLINK_DURATION_MS);
            break;
        case CM_EFFECT_EMIT:
            memcpy(out_rule->effect.as.emit.type_hash, buf + R_OFF_EMIT_TYPE_HASH, 32);
            out_rule->effect.as.emit.payload_len = cm_read_u16(buf + R_OFF_EMIT_PAYLOAD_LEN);
            if (out_rule->effect.as.emit.payload_len > 64) return -1;
            memcpy(out_rule->effect.as.emit.payload,
                   buf + R_OFF_EMIT_PAYLOAD,
                   out_rule->effect.as.emit.payload_len);
            break;
        default:
            return -1;
    }
    return 0;
}

bool cm_rule_equals(const cm_rule_t *a, const cm_rule_t *b) {
    if (!a || !b) return false;
    uint8_t buf_a[CM_RULE_ENCODED_SIZE], buf_b[CM_RULE_ENCODED_SIZE];
    if (cm_rule_encode(a, buf_a) != 0) return false;
    if (cm_rule_encode(b, buf_b) != 0) return false;
    return memcmp(buf_a, buf_b, CM_RULE_ENCODED_SIZE) == 0;
}

void cm_rules_init(cm_rules_t *rules) {
    if (!rules) return;
    memset(rules, 0, sizeof(*rules));
}

int cm_rules_install(cm_rules_t *rules, const cm_rule_t *rule) {
    if (!rules || !rule) return -1;
    if (rule->trigger_kind == CM_TRIGGER_NONE) return -1;
    if (rule->effect.kind  == CM_EFFECT_NONE)  return -1;

    for (size_t i = 0; i < CM_RULES_MAX; i++) {
        if (!rules->entries[i].occupied) {
            rules->entries[i] = *rule;
            rules->entries[i].occupied = true;
            return (int)i;
        }
    }
    return -1;
}

int cm_rules_remove(cm_rules_t *rules, size_t slot) {
    if (!rules || slot >= CM_RULES_MAX) return -1;
    rules->entries[slot].occupied = false;
    return 0;
}

static bool trigger_matches(const cm_rule_t *r,
                            const cm_ring_t *ring,
                            const uint8_t *cell,
                            uint64_t now_ms) {
    switch (r->trigger_kind) {
        case CM_TRIGGER_ON_TYPE:
            return memcmp(cm_type_hash(cell), r->trigger_type_hash, 32) == 0;

        case CM_TRIGGER_QUORUM: {
            if (!ring) return false;
            // The just-arrived cell must already be in the ring; the
            // caller is responsible for pushing before evaluating.
            // First the type must match — saves a ring scan on irrelevant cells.
            if (memcmp(cm_type_hash(cell), r->trigger_type_hash, 32) != 0) return false;
            size_t n = cm_ring_count_recent(ring,
                                            r->trigger_type_hash,
                                            now_ms,
                                            r->quorum_window_ms,
                                            r->quorum_distinct_peers);
            return n >= r->quorum_n;
        }

        case CM_TRIGGER_NONE:
        default:
            return false;
    }
}

size_t cm_rules_evaluate(cm_rules_t *rules,
                          const cm_ring_t *ring,
                          const uint8_t cell[CM_CELL_SIZE],
                          uint64_t now_ms,
                          cm_effect_t out_effects[CM_RULES_MAX]) {
    if (!rules || !cell || !out_effects) return 0;

    rules->total_evaluated++;

    size_t count = 0;
    for (size_t i = 0; i < CM_RULES_MAX; i++) {
        const cm_rule_t *r = &rules->entries[i];
        if (!r->occupied) continue;
        if (!trigger_matches(r, ring, cell, now_ms)) continue;
        out_effects[count++] = r->effect;
        rules->total_fired++;
    }
    return count;
}
