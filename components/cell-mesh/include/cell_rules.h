// cell_rules.h — match received cells against a small fixed-vocabulary
// rules table; emit effects for any rule that fires.
//
// v0 vocabulary (this file):
//   triggers: on_type (any cell with matching type_hash)
//   effects:  blink (drive an LED for N milliseconds)
//             emit  (broadcast a fresh cell with given type_hash)
//
// Quorum-shaped triggers (`when 2-of-3 distinct peers send type X
// within W ms`) layer in later — `cell_ring.cm_ring_count_recent`
// already provides the primitive; this header will grow a
// CM_TRIGGER_QUORUM variant when the third XIAO joins the demo.
//
// Pure C. No IDF dependency — host-testable. Effects are returned as
// values; the caller is responsible for actually dispatching them
// (toggling GPIO, broadcasting via cell_radio, etc.). This keeps the
// rules engine independent of any I/O.

#pragma once

#include "cell_wire.h"
#include "cell_ring.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── Trigger kinds ─────────────────────────────────────────────────────

typedef enum {
    CM_TRIGGER_NONE    = 0,
    CM_TRIGGER_ON_TYPE = 1,  // fire on any cell with `trigger_type_hash`
    CM_TRIGGER_QUORUM  = 2,  // fire when N peers send `trigger_type_hash` within window_ms
} cm_trigger_kind_t;

// ── Effect kinds ──────────────────────────────────────────────────────

typedef enum {
    CM_EFFECT_NONE  = 0,
    CM_EFFECT_BLINK = 1,  // drive LED for `as.blink.duration_ms`
    CM_EFFECT_EMIT  = 2,  // broadcast a new cell carrying `as.emit.type_hash`
} cm_effect_kind_t;

typedef struct {
    cm_effect_kind_t kind;
    union {
        struct {
            uint16_t duration_ms;
        } blink;
        struct {
            uint8_t type_hash[32];
            // Payload bytes for the emitted cell. payload_len is the
            // number of useful bytes (rest of CM_PAYLOAD_SIZE is zeroed).
            uint16_t payload_len;
            uint8_t  payload[64];   // small for demo purposes
        } emit;
    } as;
} cm_effect_t;

// ── Rule ──────────────────────────────────────────────────────────────

typedef struct {
    bool              occupied;
    cm_trigger_kind_t trigger_kind;
    uint8_t           trigger_type_hash[32];

    // ── Quorum-trigger parameters ────────────────────────────────────
    // Used only when trigger_kind == CM_TRIGGER_QUORUM. The evaluator
    // calls cm_ring_count_recent(ring, trigger_type_hash, now_ms,
    // quorum_window_ms, quorum_distinct_peers) and fires when count
    // >= quorum_n.
    uint8_t           quorum_n;               // threshold (e.g. 2 for "2-of-N")
    uint16_t          quorum_window_ms;       // observation window
    bool              quorum_distinct_peers;  // collapse duplicates from same peer

    cm_effect_t       effect;
} cm_rule_t;

// ── Rules table ───────────────────────────────────────────────────────

#define CM_RULES_MAX  8u

typedef struct {
    cm_rule_t entries[CM_RULES_MAX];
    uint32_t  total_evaluated;   // cells evaluated since init (telemetry)
    uint32_t  total_fired;       // effect-fires since init
} cm_rules_t;

void cm_rules_init(cm_rules_t *rules);

// Install a rule. Copies `rule` into the first free slot. Returns the
// slot index (0..CM_RULES_MAX-1) on success or -1 if the table is full.
int cm_rules_install(cm_rules_t *rules, const cm_rule_t *rule);

// Remove a rule by slot index. Returns 0 on success, -1 on bad index.
int cm_rules_remove(cm_rules_t *rules, size_t slot);

// ── Wire serialization (for rule-as-cell hot-swap) ───────────────────
//
// Rules can be carried in the payload of a `cellmesh.rule.v0` cell so
// the swarm can reconfigure itself from typed broadcasts (signed by an
// operator hat key in production; demo-keyed for v0). The wire layout
// is fixed-size — 139 bytes per rule. Schema version is byte 0 so we
// can bump it later without ambiguity.
//
// Layout (all multi-byte fields little-endian):
//
//   offset  size  field
//   0       1     schema_version (== 0x01)
//   1       1     trigger_kind (1=ON_TYPE, 2=QUORUM)
//   2       32    trigger_type_hash
//   34      1     quorum_n         (meaningful when trigger=QUORUM)
//   35      2     quorum_window_ms (meaningful when trigger=QUORUM)
//   37      1     quorum_distinct_peers (meaningful when trigger=QUORUM)
//   38      1     effect_kind (1=BLINK, 2=EMIT)
//   39      2     effect.blink.duration_ms (meaningful when effect=BLINK)
//   41      32    effect.emit.type_hash    (meaningful when effect=EMIT)
//   73      2     effect.emit.payload_len  (meaningful when effect=EMIT)
//   75      64    effect.emit.payload      (meaningful when effect=EMIT)

#define CM_RULE_ENCODED_SIZE     139u
#define CM_RULE_SCHEMA_VERSION   0x01u

// Serialize a rule into out_buf. occupied is NOT encoded (it's a
// runtime flag). Returns 0 on success, -1 on bad args.
int cm_rule_encode(const cm_rule_t *rule, uint8_t out_buf[CM_RULE_ENCODED_SIZE]);

// Deserialize from wire bytes. Result has occupied=false; the caller
// passes it to cm_rules_install which sets occupied=true. Returns 0
// on success, -1 on bad version / unknown trigger or effect kind.
int cm_rule_decode(const uint8_t buf[CM_RULE_ENCODED_SIZE], cm_rule_t *out_rule);

// Structural equality — byte-compare of the wire form. Useful for
// dedup when receiving a rule cell that was already installed.
// occupied is ignored.
bool cm_rule_equals(const cm_rule_t *a, const cm_rule_t *b);

// Evaluate every installed rule against `cell`. For each rule whose
// trigger matches, copies its effect into `out_effects[]` and increments
// the returned count.
//
// `ring` is optional and only consulted for CM_TRIGGER_QUORUM rules.
// Pass NULL to skip quorum evaluation (the call still works for
// CM_TRIGGER_ON_TYPE rules). Callers using quorum must push the cell
// into `ring` BEFORE this call so the just-arrived cell is counted.
//
// `now_ms` is the host monotonic time and is forwarded to
// cm_ring_count_recent for the window check; ignored when `ring` is NULL.
//
// Caller dispatches each emitted effect (toggling LED, broadcasting,
// etc.). Updates only the telemetry counters on `rules`.
size_t cm_rules_evaluate(cm_rules_t *rules,
                          const cm_ring_t *ring,
                          const uint8_t cell[CM_CELL_SIZE],
                          uint64_t now_ms,
                          cm_effect_t out_effects[CM_RULES_MAX]);

#ifdef __cplusplus
}
#endif
