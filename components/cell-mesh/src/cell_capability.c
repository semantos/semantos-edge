/**
 * cell_capability.c — per-channel relay capability cert table.
 *
 * Pure C, no IDF dependency — host-testable.
 */

#include "cell_capability.h"
#include "cell_wire.h"   // cm_read_u64

#include <string.h>

// ── Helpers ──────────────────────────────────────────────────────────────────

static uint64_t read_u64_le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (i * 8);
    return v;
}

// Pure-C SHA-256 for cert_hash — same portable implementation used by cell_mnca.c.
// Avoids mbedTLS dependency so the module is host-testable without IDF.
static void sha256_cert(const uint8_t *data, size_t len, uint8_t out[32]) {
    // Use the same portable SHA-256 from cell_mnca.c via a forward-declared helper.
    // We re-implement the small K+H tables inline to avoid a separate header.
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
        0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
        0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
        0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
        0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
        0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    };
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    };
    uint8_t  block[64];
    uint64_t bit_len = (uint64_t)len * 8;
    size_t   off     = 0;
    int      final   = 0;

    while (!final) {
        size_t chunk = len - off;
        if (chunk >= 64) {
            memcpy(block, data + off, 64);
            off += 64;
        } else {
            memcpy(block, data + off, chunk);
            block[chunk] = 0x80;
            memset(block + chunk + 1, 0, 63 - chunk);
            if (chunk < 56) {
                // Length fits in this block.
                for (int i = 0; i < 8; i++)
                    block[56 + i] = (uint8_t)(bit_len >> (56 - 8 * i));
                final = 1;
            } else {
                // Need an extra block for length.
                final = 2;
            }
            off = len;
        }
        // Process block.
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
                   ((uint32_t)block[i*4+2]<<8)|block[i*4+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = (w[i-15]>>7|(w[i-15]<<25))^(w[i-15]>>18|(w[i-15]<<14))^(w[i-15]>>3);
            uint32_t s1 = (w[i-2]>>17|(w[i-2]<<15))^(w[i-2]>>19|(w[i-2]<<13))^(w[i-2]>>10);
            w[i] = w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1=(e>>6|(e<<26))^(e>>11|(e<<21))^(e>>25|(e<<7));
            uint32_t ch=(e&f)^(~e&g);
            uint32_t tmp1=hh+S1+ch+K[i]+w[i];
            uint32_t S0=(a>>2|(a<<30))^(a>>13|(a<<19))^(a>>22|(a<<10));
            uint32_t maj=(a&b)^(a&c)^(b&c);
            uint32_t tmp2=S0+maj;
            hh=g; g=f; f=e; e=d+tmp1; d=c; c=b; b=a; a=tmp1+tmp2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;

        if (final == 2) {
            // Extra block: zeros + length.
            memset(block, 0, 56);
            for (int i = 0; i < 8; i++)
                block[56 + i] = (uint8_t)(bit_len >> (56 - 8 * i));
            final = 1;
            /* loop continues to process this extra block */
            continue;
        }
    }
    for (int i = 0; i < 8; i++) {
        out[i*4+0] = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >>  8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

// ── API ──────────────────────────────────────────────────────────────────────

void cm_cap_table_init(cm_cap_table_t *t) {
    if (!t) return;
    memset(t, 0, sizeof(*t));
}

cm_cap_rc_t cm_cap_install(cm_cap_table_t *t,
                            const uint8_t  *payload,
                            size_t          payload_len,
                            uint64_t        now_ms)
{
    if (!t || !payload) return CM_CAP_ERR_BAD_PAYLOAD;
    if (payload_len < CM_CAP_PAYLOAD_BYTES) return CM_CAP_ERR_BAD_PAYLOAD;

    const uint8_t *edge_pubkey   = payload + CM_CAP_OFF_EDGE_PUBKEY;
    const uint8_t *channel_id    = payload + CM_CAP_OFF_CHANNEL_ID;
    uint64_t       expiry_ms     = read_u64_le(payload + CM_CAP_OFF_EXPIRY_MS);
    uint8_t        route_type    = payload[CM_CAP_OFF_ROUTE_TYPE];
    uint64_t       valid_from_ms = read_u64_le(payload + CM_CAP_OFF_VALID_FROM_MS);

    // UINT64_MAX = no-expiry sentinel (used until device has RTC/NTP).
    // For any other value, reject if already past.
    if (expiry_ms != UINT64_MAX && expiry_ms <= now_ms) return CM_CAP_ERR_EXPIRED;

    // Compute cert_hash = SHA-256(payload[CM_CAP_PAYLOAD_BYTES]).
    uint8_t cert_hash[32];
    sha256_cert(payload, CM_CAP_PAYLOAD_BYTES, cert_hash);

    // Look for an existing slot with the same (channel_id, route_type) to
    // overwrite, or a free slot.
    int free_slot = -1;
    for (int i = 0; i < (int)CM_CAP_TABLE_MAX; i++) {
        cm_cap_entry_t *e = &t->entries[i];
        if (!e->valid || (e->expiry_ms != UINT64_MAX && e->expiry_ms <= now_ms)) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (memcmp(e->channel_id, channel_id, 16) == 0 &&
            e->route_type == route_type) {
            // Overwrite existing entry for this (channel_id, route_type).
            memcpy(e->edge_pubkey, edge_pubkey,  33);
            memcpy(e->cert_hash,   cert_hash,    32);
            e->expiry_ms     = expiry_ms;
            e->valid_from_ms = valid_from_ms;
            return CM_CAP_OK;
        }
    }

    if (free_slot < 0) return CM_CAP_ERR_TABLE_FULL;

    cm_cap_entry_t *e = &t->entries[free_slot];
    e->valid         = true;
    e->route_type    = route_type;
    e->expiry_ms     = expiry_ms;
    e->valid_from_ms = valid_from_ms;
    memcpy(e->channel_id,  channel_id,  16);
    memcpy(e->edge_pubkey, edge_pubkey, 33);
    memcpy(e->cert_hash,   cert_hash,   32);
    return CM_CAP_OK;
}

// ── Shared entry finder (const) ───────────────────────────────────────────────

static const cm_cap_entry_t *find_entry(cm_cap_table_t *t,
                                         const uint8_t   channel_id[16],
                                         uint8_t         route_type,
                                         uint64_t        now_ms)
{
    if (!t || !channel_id) return NULL;
    for (int i = 0; i < (int)CM_CAP_TABLE_MAX; i++) {
        cm_cap_entry_t *e = &t->entries[i];
        if (!e->valid) continue;
        if (e->expiry_ms != UINT64_MAX && e->expiry_ms <= now_ms) {
            e->valid = false;   // lazy eviction
            continue;
        }
        if (e->route_type != route_type) continue;
        if (memcmp(e->channel_id, channel_id, 16) != 0) continue;
        return e;
    }
    return NULL;
}

const uint8_t *cm_cap_lookup(cm_cap_table_t *t,
                              const uint8_t   channel_id[16],
                              uint8_t         route_type,
                              uint64_t        now_ms)
{
    const cm_cap_entry_t *e = find_entry(t, channel_id, route_type, now_ms);
    return e ? e->edge_pubkey : NULL;
}

const uint8_t *cm_cap_cert_hash(cm_cap_table_t *t,
                                 const uint8_t   channel_id[16],
                                 uint8_t         route_type,
                                 uint64_t        now_ms)
{
    const cm_cap_entry_t *e = find_entry(t, channel_id, route_type, now_ms);
    return e ? e->cert_hash : NULL;
}

void cm_cap_evict_expired(cm_cap_table_t *t, uint64_t now_ms) {
    if (!t) return;
    for (int i = 0; i < (int)CM_CAP_TABLE_MAX; i++) {
        cm_cap_entry_t *e = &t->entries[i];
        if (e->valid && e->expiry_ms != UINT64_MAX && e->expiry_ms <= now_ms)
            e->valid = false;
    }
}

int cm_cap_valid_count(const cm_cap_table_t *t, uint64_t now_ms) {
    if (!t) return 0;
    int n = 0;
    for (int i = 0; i < (int)CM_CAP_TABLE_MAX; i++) {
        const cm_cap_entry_t *e = &t->entries[i];
        if (e->valid && (e->expiry_ms == UINT64_MAX || e->expiry_ms > now_ms)) n++;
    }
    return n;
}
