// cell_forward_admit.h — should this forward cell be acted on?
//
// The whole decision for forward.v0/v1/v2: which check runs before which, what
// each failure means, and the protocol-state mutations that are part of
// admitting a cell (capability lookup, BRC-108 cert_hash binding, channel
// commitment). It used to be three hand-ordered sequences in the demo app,
// sharing no code and free to drift.
//
// This owns the ORDER and the VERDICT. It does not touch the device: blinking,
// queueing a rule, stashing a cell for relay, logging, reading a clock — those
// stay with the caller, driven by the verdict and hop returned here. That is
// what keeps the component free of any IDF dependency.
//
// ECDSA verify is injected, because secp256k1 verification lives in mbedTLS.
// Everything else is native Zig, so a host test drives the entire sequence with
// a stub verifier and no hardware.
//
// Zig-backed C ABI, no IDF dependency — host-testable.

#pragma once

#include "cell_wire.h"
#include "cell_forward.h"
#include "cell_forward_v1.h"
#include "cell_forward_v2.h"
#include "cell_channel.h"
#include "cell_capability.h"
#include "cell_sig.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── Verdicts ─────────────────────────────────────────────────────────────────
// One code per distinct refusal, so no diagnostic is lost in the move.

#define CM_ADMIT_RELAY                 0
#define CM_ADMIT_DELIVER               1
// Not addressed to us, or not from our predecessor. Silent by design — every
// board hears every broadcast, so this is the common case, not an error.
#define CM_ADMIT_IGNORE              (-1)
#define CM_ADMIT_BAD_ROUTE           (-2)
#define CM_ADMIT_NO_CERT             (-3)
#define CM_ADMIT_SIG_INVALID         (-4)
#define CM_ADMIT_CERT_HASH_MISMATCH  (-5)
#define CM_ADMIT_CHANNEL_REJECT      (-6)
#define CM_ADMIT_NO_GRANT            (-7)
#define CM_ADMIT_FLOW_BINDING        (-8)

typedef struct {
    int     verdict;
    uint8_t hop;
    uint8_t next_mac[6];
    bool    adopted_channel_id;  // F6 fired: the all-zero sentinel was replaced
    int     channel_rc;          // the channel machine's own code on CHANNEL_REJECT
} cm_admit_t;

/** ECDSA verify, injected. Matches cm_sig_verify: 0 on success. */
typedef int (*cm_sig_verify_fn)(const uint8_t *pubkey,
                                const uint8_t *msg_hash,
                                const uint8_t *sig);

/**
 * forward.v0 — authenticated against the operator anchor, authorised
 * device-scoped (it carries no channel_id, so there is nothing to key a
 * per-channel grant on).
 *
 * The grant check runs BEFORE the signature: cm_sig_verify is ~267 ms and the
 * grant check scans four entries, so an unprovisioned board does not pay for a
 * verify it will discard.
 */
int cm_forward_v0_admit(const uint8_t         *cell,
                        const uint8_t         *sig,
                        const cm_forward_t    *fwd,
                        const uint8_t         *my_mac,
                        const uint8_t         *sender_mac,
                        const uint8_t         *anchor_pubkey,
                        const cm_cap_table_t  *caps,
                        uint64_t               now_ms,
                        cm_sig_verify_fn       verify,
                        cm_admit_t            *out);

/** forward.v1 — per-channel capability, edge-key signature, cert_hash, channel. */
int cm_forward_v1_admit(const uint8_t          *cell,
                        const uint8_t          *sig,
                        const cm_forward_v1_t  *fv1,
                        const uint8_t          *my_mac,
                        const uint8_t          *sender_mac,
                        cm_cap_table_t         *caps,
                        cm_channel_t           *chan,
                        uint64_t                now_ms,
                        cm_sig_verify_fn        verify,
                        cm_admit_t             *out);

/**
 * forward.v2 — same, plus the Cell A <-> Cell B flow_id binding.
 *
 * `primary_cell` is Cell A: signed, and the source of BOTH the signature and
 * the capability domain. Cell B's header carries no signature and the binding
 * covers only its payload, so nothing here is decided from it.
 */
int cm_forward_v2_admit(const uint8_t             *primary_cell,
                        const uint8_t             *primary_sig,
                        const cm_forward_v2_t     *pa,
                        const uint8_t             *routing_payload,
                        size_t                     routing_payload_len,
                        const cm_routing_cont_t   *pb,
                        const uint8_t             *my_mac,
                        const uint8_t             *sender_mac,
                        cm_cap_table_t            *caps,
                        cm_channel_t              *chan,
                        uint64_t                   now_ms,
                        cm_sig_verify_fn           verify,
                        cm_admit_t                *out);

#ifdef __cplusplus
}
#endif
