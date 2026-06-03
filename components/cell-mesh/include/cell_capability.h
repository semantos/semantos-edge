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
//      with the cell's channel_id + route type.  On a hit, the caller uses
//      the returned edge_pubkey to verify the cell signature.  On a miss,
//      the cell is rejected — no fallback to master key.
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
// Pure C, no IDF dependency — host-testable.

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
} cm_cap_entry_t;

// ── Table ────────────────────────────────────────────────────────────────────

typedef struct {
    cm_cap_entry_t entries[CM_CAP_TABLE_MAX];
} cm_cap_table_t;

// Zero all entries.
void cm_cap_table_init(cm_cap_table_t *t);

// ── Install / lookup ─────────────────────────────────────────────────────────

// Result codes.
typedef enum {
    CM_CAP_OK              =  0,
    CM_CAP_ERR_BAD_PAYLOAD = -1,  // payload too short / bad field
    CM_CAP_ERR_EXPIRED     = -2,  // expiry_ms already past at install time
    CM_CAP_ERR_TABLE_FULL  = -3,  // no free slot and no matching existing entry
} cm_cap_rc_t;

/**
 * Install a capability cert from a received cert cell payload.
 *
 * `payload` is the raw 66-byte payload region of a `cellmesh.capability.v0`
 * cell.  The caller has already verified the cell signature against the
 * master wallet pubkey before calling this.
 *
 * If an entry for (channel_id, route_type) already exists it is overwritten.
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
                            uint64_t        now_ms);

/**
 * Look up the edge_pubkey for a (channel_id, route_type) pair.
 *
 * Returns a pointer into the table entry's edge_pubkey (33 bytes) if a
 * valid, non-expired cert exists.  Returns NULL if no matching cert is found
 * or the cert has expired.  Expired entries are lazily invalidated.
 */
const uint8_t *cm_cap_lookup(cm_cap_table_t *t,
                              const uint8_t   channel_id[16],
                              uint8_t         route_type,
                              uint64_t        now_ms);

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
                                 uint64_t        now_ms);

/**
 * Scan the table and invalidate any entries whose expiry_ms <= now_ms.
 * Call from a periodic tick (e.g. every 10 s) to keep the table clean.
 */
void cm_cap_evict_expired(cm_cap_table_t *t, uint64_t now_ms);

/** Return the number of valid (non-expired) entries. */
int cm_cap_valid_count(const cm_cap_table_t *t, uint64_t now_ms);

#ifdef __cplusplus
}
#endif
