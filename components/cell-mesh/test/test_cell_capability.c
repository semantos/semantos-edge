/**
 * test_cell_capability.c — host tests for the capability cert table.
 *
 * Tests cm_cap_install / cm_cap_lookup / cm_cap_cert_hash /
 * cm_cap_evict_expired without any IDF or hardware dependency.
 *
 * Compile + run (no IDF needed):
 *   cc -I ../include test_cell_capability.c ../src/cell_capability.c \
 *      -o test_cell_capability && ./test_cell_capability
 */

#include "cell_capability.h"
#include "vectors/domainflag_vectors.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

static int s_pass = 0;
static int s_fail = 0;

#define CHECK(cond, label) do {                                              \
    if (cond) { printf("  PASS %s\n", label); s_pass++; }                   \
    else       { printf("  FAIL %s  (line %d)\n", label, __LINE__); s_fail++; } \
} while (0)

// ── Test vectors ─────────────────────────────────────────────────────────────

static const uint8_t CHANNEL_ID_A[16] = {
    0xab,0xcd,0xef,0x01, 0x23,0x45,0x67,0x89,
    0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
};
static const uint8_t CHANNEL_ID_B[16] = {
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
};
static const uint8_t ZERO_CHANNEL_ID[16] = { 0 };

static const uint8_t EDGE_PK_A[33] = {
    0x02,
    0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c, 0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14, 0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c, 0x1d,0x1e,0x1f,
};
static const uint8_t EDGE_PK_B[33] = {
    0x03,
    0xf0,0xe1,0xd2,0xc3, 0xb4,0xa5,0x96,0x87,
    0x78,0x69,0x5a,0x4b, 0x3c,0x2d,0x1e,0x0f,
    0x10,0x21,0x32,0x43, 0x54,0x65,0x76,0x87,
    0x98,0xa9,0xba,0xcb, 0xdc,0xed,0xfe,
};

// Helper: build a canonical CM_CAP_PAYLOAD_BYTES-byte cert payload.
static void make_payload(uint8_t out[CM_CAP_PAYLOAD_BYTES],
                         const uint8_t edge_pk[33],
                         const uint8_t channel_id[16],
                         uint64_t expiry_ms,
                         uint8_t route_type,
                         uint64_t valid_from_ms)
{
    memset(out, 0, CM_CAP_PAYLOAD_BYTES);
    memcpy(out + CM_CAP_OFF_EDGE_PUBKEY, edge_pk,    33);
    memcpy(out + CM_CAP_OFF_CHANNEL_ID,  channel_id, 16);
    for (int i = 0; i < 8; i++) out[CM_CAP_OFF_EXPIRY_MS    + i] = (uint8_t)(expiry_ms     >> (i * 8));
    out[CM_CAP_OFF_ROUTE_TYPE] = route_type;
    for (int i = 0; i < 8; i++) out[CM_CAP_OFF_VALID_FROM_MS + i] = (uint8_t)(valid_from_ms >> (i * 8));
}

// UINT64_MAX sentinel = no-expiry (bridge writes this until device has RTC).
#define NO_EXPIRY UINT64_MAX

// The domain every pre-existing test operates in. 0 is what a cell minted
// before the flag was ever written carries, so passing it here keeps every
// original assertion meaning exactly what it meant before domains existed.
#define DOM_UNDECLARED 0u

// Two real domains, from tools/fleet-zig/src/domains.zig.
#define DOM_DEVICE 0x00f10001u
#define DOM_MEMBER 0x00f10002u

// ── T1: table init ────────────────────────────────────────────────────────────

static void test_table_init(void) {
    printf("\n[T1] cm_cap_table_init\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    CHECK(cm_cap_valid_count(&t, 0) == 0, "empty table: 0 valid entries");
    cm_cap_table_init(NULL);   // must not crash
    CHECK(true, "init(NULL) does not crash");
}

// ── T2: install and lookup ────────────────────────────────────────────────────

static void test_install_and_lookup(void) {
    printf("\n[T2] install + lookup\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);

    uint8_t p[CM_CAP_PAYLOAD_BYTES];
    make_payload(p, EDGE_PK_A, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 1000ULL);
    cm_cap_rc_t rc = cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
    CHECK(rc == CM_CAP_OK, "install: CM_CAP_OK");
    CHECK(cm_cap_valid_count(&t, 0) == 1, "1 valid entry after install");

    const uint8_t *found = cm_cap_lookup(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED);
    CHECK(found != NULL, "lookup: entry found");
    CHECK(memcmp(found, EDGE_PK_A, 33) == 0, "lookup: edge_pubkey matches EDGE_PK_A");

    // Wrong channel_id → miss
    CHECK(cm_cap_lookup(&t, CHANNEL_ID_B, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED) == NULL,
          "lookup: wrong channel_id → miss");
    // Wrong route_type → miss
    CHECK(cm_cap_lookup(&t, CHANNEL_ID_A, 0x02, 0, DOM_UNDECLARED) == NULL,
          "lookup: wrong route_type → miss");
}

// ── T3: expiry rejection ──────────────────────────────────────────────────────

static void test_expiry_rejection(void) {
    printf("\n[T3] expiry handling\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    uint8_t p[CM_CAP_PAYLOAD_BYTES];

    // Install with expiry in the past → CM_CAP_ERR_EXPIRED
    make_payload(p, EDGE_PK_A, CHANNEL_ID_A, 1000, CM_CAP_ROUTE_FWD_V1, 500ULL);
    cm_cap_rc_t rc = cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 2000 /* now > expiry */, DOM_UNDECLARED);
    CHECK(rc == CM_CAP_ERR_EXPIRED, "past expiry → CM_CAP_ERR_EXPIRED");
    CHECK(cm_cap_valid_count(&t, 0) == 0, "no entry added for expired cert");

    // UINT64_MAX = no-expiry → always OK regardless of now_ms
    make_payload(p, EDGE_PK_A, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 0ULL);
    rc = cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 999999999999ULL, DOM_UNDECLARED);
    CHECK(rc == CM_CAP_OK, "UINT64_MAX expiry installs even with large now_ms");
    CHECK(cm_cap_lookup(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 999999999999ULL, DOM_UNDECLARED) != NULL,
          "UINT64_MAX expiry cert never expires");
}

// ── T4: lazy eviction ────────────────────────────────────────────────────────

static void test_cert_eviction(void) {
    printf("\n[T4] lazy eviction on lookup + explicit evict\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    uint8_t p[CM_CAP_PAYLOAD_BYTES];

    make_payload(p, EDGE_PK_A, CHANNEL_ID_A, 5000, CM_CAP_ROUTE_FWD_V1, 0ULL);
    cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
    CHECK(cm_cap_valid_count(&t, 0) == 1, "cert valid at t=0");

    CHECK(cm_cap_lookup(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 4999, DOM_UNDECLARED) != NULL,
          "lookup at t=4999 (before expiry) → hit");
    CHECK(cm_cap_lookup(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 5001, DOM_UNDECLARED) == NULL,
          "lookup at t=5001 (after expiry) → miss (lazy evict)");
    CHECK(cm_cap_valid_count(&t, 5001) == 0, "valid_count == 0 after expiry");

    // Re-install and explicit evict.
    make_payload(p, EDGE_PK_A, CHANNEL_ID_A, 8000, CM_CAP_ROUTE_FWD_V1, 0ULL);
    cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
    CHECK(cm_cap_valid_count(&t, 7999) == 1, "re-installed cert valid");
    cm_cap_evict_expired(&t, 8001);
    CHECK(cm_cap_valid_count(&t, 8001) == 0, "explicit evict removes entry");
}

// ── T5: table full ────────────────────────────────────────────────────────────

static void test_table_full(void) {
    printf("\n[T5] table full\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    uint8_t p[CM_CAP_PAYLOAD_BYTES];
    uint8_t ch[16] = { 0 };

    for (int i = 0; i < (int)CM_CAP_TABLE_MAX; i++) {
        ch[0] = (uint8_t)i;
        make_payload(p, EDGE_PK_A, ch, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 0ULL);
        cm_cap_rc_t rc = cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
        CHECK(rc == CM_CAP_OK, i == 0 ? "slot 0 filled"
                              : i == 1 ? "slot 1 filled"
                              : i == 2 ? "slot 2 filled"
                              :          "slot 3 filled");
    }
    CHECK(cm_cap_valid_count(&t, 0) == CM_CAP_TABLE_MAX, "all 4 slots occupied");

    ch[0] = 0xff;
    make_payload(p, EDGE_PK_B, ch, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 0ULL);
    cm_cap_rc_t rc = cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
    CHECK(rc == CM_CAP_ERR_TABLE_FULL, "5th distinct cert → CM_CAP_ERR_TABLE_FULL");
}

// ── T6: overwrite and cert_hash changes ──────────────────────────────────────

static void test_overwrite(void) {
    printf("\n[T6] overwrite existing entry — cert_hash updates\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    uint8_t p[CM_CAP_PAYLOAD_BYTES];

    make_payload(p, EDGE_PK_A, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 1000ULL);
    cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);

    const uint8_t *hash_a = cm_cap_cert_hash(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED);
    CHECK(hash_a != NULL, "cert_hash: non-NULL after install");
    uint8_t saved_hash_a[32];
    memcpy(saved_hash_a, hash_a, 32);

    // Overwrite with EDGE_PK_B (key rotation) — cert_hash must change.
    make_payload(p, EDGE_PK_B, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 2000ULL);
    cm_cap_rc_t rc = cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
    CHECK(rc == CM_CAP_OK, "overwrite returns CM_CAP_OK");
    CHECK(cm_cap_valid_count(&t, 0) == 1, "still 1 entry after overwrite");
    CHECK(memcmp(cm_cap_lookup(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED),
                 EDGE_PK_B, 33) == 0,
          "edge_pubkey updated to EDGE_PK_B after overwrite");

    const uint8_t *hash_b = cm_cap_cert_hash(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED);
    CHECK(hash_b != NULL, "cert_hash non-NULL after overwrite");
    CHECK(memcmp(hash_b, saved_hash_a, 32) != 0,
          "cert_hash differs after key rotation");
}

// ── T7: cert_hash consistency ─────────────────────────────────────────────────

static void test_cert_hash(void) {
    printf("\n[T7] cert_hash — same payload gives same hash; different payload differs\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    uint8_t p[CM_CAP_PAYLOAD_BYTES];

    // Install CHANNEL_ID_A.
    make_payload(p, EDGE_PK_A, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 42ULL);
    cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
    const uint8_t *ha = cm_cap_cert_hash(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED);
    CHECK(ha != NULL, "cert_hash A: non-NULL");
    uint8_t hash_a[32]; memcpy(hash_a, ha, 32);

    // Install same payload for CHANNEL_ID_B (same cert bytes except channel_id) → different hash.
    make_payload(p, EDGE_PK_A, CHANNEL_ID_B, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 42ULL);
    cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
    const uint8_t *hb = cm_cap_cert_hash(&t, CHANNEL_ID_B, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED);
    CHECK(hb != NULL, "cert_hash B: non-NULL");
    CHECK(memcmp(hash_a, hb, 32) != 0, "different channel_id → different cert_hash");

    // Reinstall CHANNEL_ID_A with identical bytes → same hash.
    cm_cap_table_t t2; cm_cap_table_init(&t2);
    make_payload(p, EDGE_PK_A, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 42ULL);
    cm_cap_install(&t2, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
    const uint8_t *ha2 = cm_cap_cert_hash(&t2, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED);
    CHECK(ha2 != NULL && memcmp(ha2, hash_a, 32) == 0,
          "identical payload → identical cert_hash (deterministic)");
}

// ── T8: validFrom field stored correctly ─────────────────────────────────────

static void test_valid_from(void) {
    printf("\n[T8] valid_from_ms field stored and accessible via entry\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    uint8_t p[CM_CAP_PAYLOAD_BYTES];
    const uint64_t ISSUE_TIME = 1748905600000ULL;  // example UTC ms

    make_payload(p, EDGE_PK_A, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, ISSUE_TIME);
    cm_cap_rc_t rc = cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
    CHECK(rc == CM_CAP_OK, "install with validFrom: CM_CAP_OK");

    // Access via internal entry (white-box — valid_from_ms field).
    const cm_cap_entry_t *e = &t.entries[0];
    CHECK(e->valid && e->valid_from_ms == ISSUE_TIME,
          "valid_from_ms stored correctly in entry");
}

// ── T9: bad payload ───────────────────────────────────────────────────────────

static void test_bad_payload(void) {
    printf("\n[T9] bad payload handling\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    uint8_t p[CM_CAP_PAYLOAD_BYTES - 1];
    memset(p, 0, sizeof(p));

    cm_cap_rc_t rc = cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES - 1, 0, DOM_UNDECLARED);
    CHECK(rc == CM_CAP_ERR_BAD_PAYLOAD, "short payload → CM_CAP_ERR_BAD_PAYLOAD");

    rc = cm_cap_install(&t, NULL, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
    CHECK(rc == CM_CAP_ERR_BAD_PAYLOAD, "NULL payload → CM_CAP_ERR_BAD_PAYLOAD");

    CHECK(cm_cap_lookup(&t, NULL, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED) == NULL,
          "lookup(NULL channel_id) → NULL");
    CHECK(cm_cap_cert_hash(&t, NULL, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED) == NULL,
          "cert_hash(NULL channel_id) → NULL");
}

// ── T10: zero channel_id (demo channel) ──────────────────────────────────────

static void test_zero_channel_id(void) {
    printf("\n[T10] zero channel_id (demo channel)\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    uint8_t p[CM_CAP_PAYLOAD_BYTES];

    make_payload(p, EDGE_PK_A, ZERO_CHANNEL_ID, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 0ULL);
    cm_cap_rc_t rc = cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED);
    CHECK(rc == CM_CAP_OK, "zero channel_id cert installs OK");

    const uint8_t *found = cm_cap_lookup(&t, ZERO_CHANNEL_ID, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED);
    CHECK(found != NULL && memcmp(found, EDGE_PK_A, 33) == 0,
          "zero channel_id cert looks up correctly");

    CHECK(cm_cap_cert_hash(&t, ZERO_CHANNEL_ID, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED) != NULL,
          "cert_hash for zero channel_id is non-NULL");
}

// ── T11: the predicate IS the opcode ─────────────────────────────────────────

static void test_domain_predicate_matches_opcode(void) {
    printf("\n[T11] cm_domain_flag_matches vs the real OP_CHECKDOMAINFLAG\n");

    // Every row of this table came out of the WASM cell engine this firmware
    // embeds, by executing <cell> <expected_flag> OP_CHECKDOMAINFLAG and
    // recording what it did. So this is not "does the C agree with my reading
    // of plexus.zig" — it is "does the C agree with the binary that ships".
    int mismatches = 0;
    for (int i = 0; i < CM_DOMAINFLAG_VECTOR_COUNT; i++) {
        const cm_domainflag_vector_t *v = &CM_DOMAINFLAG_VECTORS[i];
        if (cm_domain_flag_matches(v->actual, v->expected) != v->accept) {
            printf("    DIVERGES: %s  engine=%s native=%s\n", v->label,
                   v->accept ? "accept" : "reject",
                   v->accept ? "reject" : "accept");
            mismatches++;
        }
    }
    CHECK(mismatches == 0, "native predicate agrees with the engine on all rows");
    CHECK(CM_DOMAINFLAG_VECTOR_COUNT >= 64, "vector is the full ordered-pair matrix");

    // The table must actually contain refusals, or agreeing with it proves
    // nothing — a predicate that always returns true would pass an all-accept
    // table. Guard against a generator that silently emits a degenerate matrix.
    int accepts = 0, rejects = 0;
    for (int i = 0; i < CM_DOMAINFLAG_VECTOR_COUNT; i++) {
        if (CM_DOMAINFLAG_VECTORS[i].accept) accepts++; else rejects++;
    }
    CHECK(accepts > 0 && rejects > accepts, "vector has both accepts and (more) rejects");
}

// ── T12: domain binds authority ──────────────────────────────────────────────

static void test_domain_binding(void) {
    printf("\n[T12] a cert issued in one domain does not authorise another\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    CHECK(cm_cap_get_domain(&t) == CM_CAP_DOMAIN_ANY,
          "init leaves the device domain OPEN, not zero");

    uint8_t p[CM_CAP_PAYLOAD_BYTES];
    make_payload(p, EDGE_PK_A, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 1000ULL);
    CHECK(cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_DEVICE) == CM_CAP_OK,
          "install a cert in the device domain");

    // Same channel, same route, same everything — only the cell's declared
    // domain differs. This is the whole point.
    CHECK(cm_cap_lookup(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_DEVICE) != NULL,
          "device-domain cell: authorised");
    CHECK(cm_cap_lookup(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_MEMBER) == NULL,
          "member-domain cell: REFUSED by the same cert");
    CHECK(cm_cap_lookup(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_UNDECLARED) == NULL,
          "undeclared cell: REFUSED — no wildcard, 0 is a domain like any other");

    // cert_hash follows the same key, or the BRC-108 binding could be read
    // across a domain boundary the pubkey lookup just refused.
    CHECK(cm_cap_cert_hash(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_DEVICE) != NULL,
          "cert_hash: device domain resolves");
    CHECK(cm_cap_cert_hash(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_MEMBER) == NULL,
          "cert_hash: member domain REFUSED");
}

// ── T13: two domains coexist without overwriting ─────────────────────────────

static void test_domain_separate_grants(void) {
    printf("\n[T13] same channel in two domains = two grants, not one\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    uint8_t pa[CM_CAP_PAYLOAD_BYTES], pb[CM_CAP_PAYLOAD_BYTES];
    make_payload(pa, EDGE_PK_A, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 1000ULL);
    make_payload(pb, EDGE_PK_B, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 1000ULL);

    CHECK(cm_cap_install(&t, pa, CM_CAP_PAYLOAD_BYTES, 0, DOM_DEVICE) == CM_CAP_OK,
          "install device-domain grant");
    CHECK(cm_cap_install(&t, pb, CM_CAP_PAYLOAD_BYTES, 0, DOM_MEMBER) == CM_CAP_OK,
          "install member-domain grant on the SAME channel");
    CHECK(cm_cap_valid_count(&t, 0) == 2, "two entries, not one overwritten");

    const uint8_t *a = cm_cap_lookup(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_DEVICE);
    const uint8_t *b = cm_cap_lookup(&t, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_MEMBER);
    CHECK(a && memcmp(a, EDGE_PK_A, 33) == 0, "device domain still resolves to EDGE_PK_A");
    CHECK(b && memcmp(b, EDGE_PK_B, 33) == 0, "member domain resolves to EDGE_PK_B");

    // Renewal within a domain must still overwrite rather than consume a slot.
    make_payload(pa, EDGE_PK_B, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 2000ULL);
    CHECK(cm_cap_install(&t, pa, CM_CAP_PAYLOAD_BYTES, 0, DOM_DEVICE) == CM_CAP_OK,
          "renew the device-domain grant");
    CHECK(cm_cap_valid_count(&t, 0) == 2, "renewal overwrote in place — still 2 entries");
}

// ── T14: device domain policy ────────────────────────────────────────────────

static void test_device_domain_policy(void) {
    printf("\n[T14] a device refuses a valid cert from the wrong domain\n");

    cm_cap_table_t t;
    cm_cap_table_init(&t);
    cm_cap_set_domain(&t, DOM_DEVICE);
    CHECK(cm_cap_get_domain(&t) == DOM_DEVICE, "device domain is set");

    uint8_t p[CM_CAP_PAYLOAD_BYTES];
    make_payload(p, EDGE_PK_A, CHANNEL_ID_A, NO_EXPIRY, CM_CAP_ROUTE_FWD_V1, 1000ULL);

    CHECK(cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_MEMBER) == CM_CAP_ERR_WRONG_DOMAIN,
          "member-domain cert: REFUSED at install");
    CHECK(cm_cap_valid_count(&t, 0) == 0, "nothing was written by the refused install");
    CHECK(cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_UNDECLARED) == CM_CAP_ERR_WRONG_DOMAIN,
          "undeclared cert: also REFUSED — a provisioned device wants a domain");
    CHECK(cm_cap_install(&t, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_DEVICE) == CM_CAP_OK,
          "device-domain cert: accepted");
    CHECK(cm_cap_valid_count(&t, 0) == 1, "exactly one entry");

    // CM_CAP_DOMAIN_ANY restores the pre-domain behaviour: install anything,
    // still bind each cert to the domain it was issued in.
    cm_cap_table_t open;
    cm_cap_table_init(&open);
    CHECK(cm_cap_install(&open, p, CM_CAP_PAYLOAD_BYTES, 0, DOM_MEMBER) == CM_CAP_OK,
          "DOMAIN_ANY table installs a member cert");
    CHECK(cm_cap_lookup(&open, CHANNEL_ID_A, CM_CAP_ROUTE_FWD_V1, 0, DOM_DEVICE) == NULL,
          "...but it still does not authorise a device-domain cell");
}

// ── T15: bit-31 flags are not usable ─────────────────────────────────────────

static void test_bit31_flags_are_a_hazard(void) {
    printf("\n[T15] flags with bit 31 set are refused by allocation policy\n");

    // The native predicate is a plain u32 compare and handles these fine — it
    // is the SCRIPT encoding that breaks (bit 31 reads as a sign bit, so a
    // 4-byte push of 0x80000000 is script-number negative zero). This test
    // pins the native side's honesty: it must NOT quietly agree with the
    // engine's misreading, because then the divergence would be invisible.
    CHECK(cm_domain_flag_matches(0x80000000u, 0x80000000u), "native: 0x80000000 == itself");
    CHECK(!cm_domain_flag_matches(0x00000000u, 0x80000000u), "native: 0 != 0x80000000");
    CHECK(!cm_domain_flag_matches(0x00000000u, 0xffffffffu), "native: 0 != 0xffffffff");

    // The engine, handed a raw 4-byte LE push, gets the last two WRONG. That
    // is exactly why domains.zig refuses to allocate above 0x7fffffff and why
    // no such flag appears in the generated vector.
    for (int i = 0; i < CM_DOMAINFLAG_VECTOR_COUNT; i++) {
        if (CM_DOMAINFLAG_VECTORS[i].actual   > 0x7fffffffu ||
            CM_DOMAINFLAG_VECTORS[i].expected > 0x7fffffffu) {
            CHECK(false, "vector must not contain a bit-31 flag");
            return;
        }
    }
    CHECK(true, "vector contains no bit-31 flag");
}

// ── main ─────────────────────────────────────────────────────────────────────

int main(void) {
    printf("=== test_cell_capability ===\n");
    test_table_init();
    test_install_and_lookup();
    test_expiry_rejection();
    test_cert_eviction();
    test_table_full();
    test_overwrite();
    test_cert_hash();
    test_valid_from();
    test_bad_payload();
    test_zero_channel_id();
    test_domain_predicate_matches_opcode();
    test_domain_binding();
    test_domain_separate_grants();
    test_device_domain_policy();
    test_bit31_flags_are_a_hazard();
    printf("\n=== %d passed, %d failed ===\n", s_pass, s_fail);
    return s_fail ? 1 : 0;
}
