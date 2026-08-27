// cell_capability.h — per-channel relay capability cert table.
//
// Implements the "capability hat" pattern for cell routing:
//
//   1. The bridge (master key holder) issues a `cellmesh.capability.v0` cert
//      cell, signed by the wallet master key, that grants a per-channel
//      relay key (edge_pubkey) authority to relay cellmesh.forward.v1 cells
//      on a given channel_id.
//
//   2. Devices install certs from received capability cells into this table.
//
//   3. Before accepting a forward.v1 cell, the device calls cm_cap_lookup()
//      with the cell's channel_id + route type + DOMAIN FLAG.  On a hit, the
//      caller uses the returned edge_pubkey to verify the cell signature.  On
//      a miss, the cell is rejected — no fallback to master key.
//
//   4. After sig-verify, the caller checks that commitment.cert_hash matches
//      the stored cert_hash for the same channel (BRC-108 binding).
//
// Capability cert payload layout (66 bytes):
//   Offset  Size  Field
//   0       33    edge_pubkey (compressed secp256k1)
//   33      16    channel_id
//   49       8    expiry_ms   (u64 LE)  — UINT64_MAX = no expiry
//   57       1    route_type  (CM_CAP_ROUTE_FWD_V1 = 0x01)
//   58       8    valid_from_ms (u64 LE) — UTC ms when cert was issued (BRC-52)
//
// cert_hash = SHA-256(payload[66]) — stored in cm_cap_entry_t and must match
// the cert_hash field carried in every cm_channel_commitment_t that uses this
// relay key.  This binds each payment hop to the specific cert (BRC-108).
//
// ── Domain enforcement (OP_CHECKDOMAINFLAG) ─────────────────────────────────
//
// The domain flag lives in the CELL HEADER at bytes 24-27 (CM_OFF_FLAGS), not
// in the 66-byte payload — the payload is full, every byte spoken for.  So a
// cert cell declares the domain it was issued in, and the table records it.
//
// Two checks, and they do different jobs:
//
//   BINDING (always on).  A cert issued in domain X authorises only cells that
//   declare domain X.  cm_cap_lookup takes the domain flag as part of the key,
//   so a mismatch is simply a miss and the caller's existing no-cert DROP
//   fires.  This is the predicate OP_CHECKDOMAINFLAG (opcode 198) enforces in
//   the cell engine: `actual_flag != expected_flag -> fail`, exact equality,
//   fail-closed.  The two are held together by a generated golden vector —
//   see test/vectors/domainflag_vectors.h, produced by running the real opcode
//   in the WASM engine this firmware embeds.
//
//   DEVICE POLICY (opt-in).  cm_cap_set_domain narrows which domain this
//   device will install certs for at all.  Without it a device installs any
//   operator-signed cert and merely binds each one; with it, a cert the
//   operator legitimately signed for another domain is refused outright.
//   Default after cm_cap_table_init is CM_CAP_DOMAIN_ANY, which preserves
//   pre-existing behaviour exactly — every cell minted before this existed
//   carries flag 0, and 0 binds to 0.
//
// Zig-backed C ABI, no IDF dependency — host-testable.

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── Constants ────────────────────────────────────────────────────────────────

/** Maximum capability cert entries in the static table. */
#define CM_CAP_TABLE_MAX  4u

/** route_type value for cellmesh.forward.v1 relay authority. */
#define CM_CAP_ROUTE_FWD_V1  0x01u

/** Expected byte length of a capability cert cell payload. */
#define CM_CAP_PAYLOAD_BYTES  66u

/**
 * No device domain policy: install certs from any domain, still bind each one.
 *
 * 0xFFFFFFFF sits outside every allocated band (well-known 0x01-0xff, extended
 * 0x100-0xffff, client-sovereign 0x10000-0xfffffffe in practice), so it cannot
 * be confused with a real flag.  cm_cap_table_init sets this EXPLICITLY rather
 * than letting it fall out of a memset — 0 is a real flag (it is what every
 * undeclared cell carries), so a zeroed field would silently mean "accept only
 * undeclared", which is a policy nobody chose.
 */
#define CM_CAP_DOMAIN_ANY  0xFFFFFFFFu

/** Offsets within the 66-byte payload (mirrored from capability-cert.ts). */
#define CM_CAP_OFF_EDGE_PUBKEY    0u   // 33 bytes
#define CM_CAP_OFF_CHANNEL_ID    33u   // 16 bytes
#define CM_CAP_OFF_EXPIRY_MS     49u   //  8 bytes LE u64
#define CM_CAP_OFF_ROUTE_TYPE    57u   //  1 byte
#define CM_CAP_OFF_VALID_FROM_MS 58u   //  8 bytes LE u64  (BRC-52 validFrom)

// ── Cert entry ───────────────────────────────────────────────────────────────

typedef struct {
    bool     valid;
    uint8_t  channel_id[16];
    uint8_t  edge_pubkey[33];   // compressed secp256k1 — the relay key
    uint8_t  route_type;        // CM_CAP_ROUTE_FWD_V1 = 0x01
    uint64_t expiry_ms;         // UINT64_MAX = no expiry (until RTC added)
    uint64_t valid_from_ms;     // UTC ms when cert was issued
    uint8_t  cert_hash[32];     // SHA-256(payload[66]) — for commitment binding
    uint32_t domain_flag;       // domain the cert was ISSUED in (cell hdr 24-27)
} cm_cap_entry_t;

// ── Table ────────────────────────────────────────────────────────────────────

typedef struct {
    cm_cap_entry_t entries[CM_CAP_TABLE_MAX];
    uint32_t required_domain_flag;  // CM_CAP_DOMAIN_ANY, or this device's domain
} cm_cap_table_t;

// Zero all entries and set required_domain_flag = CM_CAP_DOMAIN_ANY.
void cm_cap_table_init(cm_cap_table_t *t);

/**
 * Narrow which domain this device installs certs for.
 *
 * Call once after cm_cap_table_init, with the domain the device was
 * provisioned into.  A cert arriving in any other domain is then refused with
 * CM_CAP_ERR_WRONG_DOMAIN even though its operator signature is valid.
 */
void cm_cap_set_domain(cm_cap_table_t *t, uint32_t domain_flag);

/** The device's configured domain, or CM_CAP_DOMAIN_ANY. */
uint32_t cm_cap_get_domain(const cm_cap_table_t *t);

/**
 * The OP_CHECKDOMAINFLAG predicate (opcode 198), in native code.
 *
 * Exact equality, and deliberately a named function rather than an inline `==`
 * so a differential test can point at it.  test_cell_capability.c drives this
 * from a vector generated by running the actual opcode in the embedded WASM
 * cell engine; if the two ever disagree, this side is the one that is wrong.
 */
bool cm_domain_flag_matches(uint32_t actual, uint32_t expected);

// ── Install / lookup ─────────────────────────────────────────────────────────

// Result codes.
typedef enum {
    CM_CAP_OK              =  0,
    CM_CAP_ERR_BAD_PAYLOAD = -1,  // payload too short / bad field
    CM_CAP_ERR_EXPIRED     = -2,  // expiry_ms already past at install time
    CM_CAP_ERR_TABLE_FULL  = -3,  // no free slot and no matching existing entry
    CM_CAP_ERR_WRONG_DOMAIN = -4, // cert's domain is not this device's domain
} cm_cap_rc_t;

/**
 * Install a capability cert from a received cert cell payload.
 *
 * `payload` is the raw 66-byte payload region of a `cellmesh.capability.v0`
 * cell.  The caller has already verified the cell signature against the
 * master wallet pubkey before calling this.
 *
 * `domain_flag` is the CELL's header flag — `cm_flags(cell)` — NOT anything
 * read out of the payload.  Pass it from the same cert cell whose signature
 * you just verified, or the recorded domain is unauthenticated.
 *
 * If an entry for (channel_id, route_type, domain_flag) already exists it is
 * overwritten.  A cert for the same channel in a DIFFERENT domain is a
 * different grant: it takes its own slot rather than replacing this one.
 * If no entry exists and the table is full, returns CM_CAP_ERR_TABLE_FULL.
 *
 * `now_ms` is the device monotonic clock (esp_log_timestamp()).  Expiry is
 * checked against now_ms; UINT64_MAX in expiry_ms means the cert never
 * expires (correct until the device gains RTC/NTP).
 *
 * Returns CM_CAP_OK on success.
 */
cm_cap_rc_t cm_cap_install(cm_cap_table_t *t,
                            const uint8_t  *payload,
                            size_t          payload_len,
                            uint64_t        now_ms,
                            uint32_t        domain_flag);

/**
 * Look up the edge_pubkey for a (channel_id, route_type, domain_flag) triple.
 *
 * `domain_flag` is the header flag of the cell being AUTHORISED. A cell that
 * declares a domain the cert was not issued for does not match — this is the
 * OP_CHECKDOMAINFLAG binding, and a mismatch surfaces as an ordinary miss so
 * the caller's existing no-cert DROP handles it.
 *
 * Returns a pointer into the table entry's edge_pubkey (33 bytes) if a
 * valid, non-expired cert exists.  Returns NULL if no matching cert is found
 * or the cert has expired.  Expired entries are lazily invalidated.
 */
const uint8_t *cm_cap_lookup(cm_cap_table_t *t,
                              const uint8_t   channel_id[16],
                              uint8_t         route_type,
                              uint64_t        now_ms,
                              uint32_t        domain_flag);

/**
 * Return the cert_hash for a (channel_id, route_type) pair.
 *
 * Must only be called after a successful cm_cap_lookup for the same key —
 * the entry is guaranteed live.  Returns NULL if no valid entry.
 *
 * Used by the forward.v1 handler to verify commitment.cert_hash matches
 * the cert that authorised the relay key (BRC-108 binding).
 */
const uint8_t *cm_cap_cert_hash(cm_cap_table_t *t,
                                 const uint8_t   channel_id[16],
                                 uint8_t         route_type,
                                 uint64_t        now_ms,
                                 uint32_t        domain_flag);

/**
 * Scan the table and invalidate any entries whose expiry_ms <= now_ms.
 * Call from a periodic tick (e.g. every 10 s) to keep the table clean.
 */
void cm_cap_evict_expired(cm_cap_table_t *t, uint64_t now_ms);

/**
 * Does this device hold ANY live relay grant on this route type and domain?
 *
 * forward.v0 carries no channel_id and no commitments, so a per-channel
 * capability check is not available to it without a wire change. This is the
 * device-scoped alternative: has the operator granted this device the right to
 * relay at all, in this domain?
 *
 * Strictly weaker than cm_cap_lookup and must not be described as equivalent —
 * it says "provisioned to relay", not "may relay THIS channel". It is still the
 * difference between a provisioned relay and any board in radio range.
 */
bool cm_cap_any_valid(const cm_cap_table_t *t,
                      uint8_t               route_type,
                      uint32_t              domain_flag,
                      uint64_t              now_ms);

/** Return the number of valid (non-expired) entries. */
int cm_cap_valid_count(const cm_cap_table_t *t, uint64_t now_ms);

#ifdef __cplusplus
}
#endif
