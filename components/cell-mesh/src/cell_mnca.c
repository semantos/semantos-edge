/**
 * cell_mnca.c — MNCA tile compute + incentive quorum.
 * Pure C, no IDF dependency — host-testable.
 */

#include "cell_mnca.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// ── Reference rule ─────────────────────────────────────────────────────────────
// Conway-like: birth at 3, survive at 2-3, integer state (grow +64 / decay -64).
// rule_id[4] = { 'M','N','C','A' } (ASCII, identifies this rule family).
const cm_mnca_rule_t CM_MNCA_DEFAULT_RULE = {
    .alive_threshold = 128,
    .inner_radius    = 1,
    .birth_lo        = 3,
    .birth_hi        = 3,
    .survive_lo      = 2,
    .survive_hi      = 3,
    .grow_step       = 64,
    .decay_step      = 64,
    .rule_id         = { 'M', 'N', 'C', 'A' },
};

// ── Tile helpers ───────────────────────────────────────────────────────────────

void cm_mnca_tile_init_random(cm_mnca_tile_t *t, uint16_t x, uint16_t y, uint32_t seed) {
    if (!t) return;
    t->x          = x;
    t->y          = y;
    t->generation = 0;
    // LCG: simple deterministic "random" seed-based init.
    uint32_t s = seed ^ 0xdeadbeef;
    for (size_t i = 0; i < CM_MNCA_TILE_CELLS; i++) {
        s = s * 1664525u + 1013904223u;
        t->state[i] = (uint8_t)(s >> 16);
    }
}

static int count_alive(const uint8_t *cells, int w, int h, int cx, int cy,
                       int radius, uint8_t thresh) {
    int n = 0;
    for (int dy = -radius; dy <= radius; dy++) {
        for (int dx = -radius; dx <= radius; dx++) {
            if (dx == 0 && dy == 0) continue;
            int nx = cx + dx, ny = cy + dy;
            if (nx < 0 || nx >= w || ny < 0 || ny >= h) continue;
            if (cells[ny * w + nx] >= thresh) n++;
        }
    }
    return n;
}

static uint8_t clamp_u8(int v) {
    return v < 0 ? 0 : v > 255 ? 255 : (uint8_t)v;
}

int cm_mnca_step(const cm_mnca_tile_t *cur, cm_mnca_tile_t *next,
                  const cm_mnca_rule_t *rule) {
    if (!cur || !next || !rule) return -1;
    *next = *cur;
    next->generation = cur->generation + 1;
    const int W = CM_MNCA_TILE_W, H = CM_MNCA_TILE_H;
    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            uint8_t self   = cur->state[y * W + x];
            int     alive  = count_alive(cur->state, W, H, x, y,
                                         rule->inner_radius, rule->alive_threshold);
            bool    is_alive = (self >= rule->alive_threshold);
            int     delta;
            if (is_alive) {
                delta = (alive >= rule->survive_lo && alive <= rule->survive_hi)
                       ? rule->grow_step : -(int)rule->decay_step;
            } else {
                delta = (alive >= rule->birth_lo && alive <= rule->birth_hi)
                       ? rule->grow_step : -(int)rule->decay_step;
            }
            next->state[y * W + x] = clamp_u8((int)self + delta);
        }
    }
    return 0;
}

// ── Payload encode / decode ────────────────────────────────────────────────────

static void write_u16_le(uint8_t *p, uint16_t v) { p[0] = v & 0xff; p[1] = v >> 8; }
static void write_u32_le(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}
static uint16_t read_u16_le(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

size_t cm_mnca_tile_encode(const cm_mnca_tile_t *t, const cm_mnca_rule_t *rule,
                            uint8_t out[CM_PAYLOAD_SIZE]) {
    if (!t || !out) return 0;
    memset(out, 0, CM_PAYLOAD_SIZE);
    write_u16_le(out + CM_MNCA_TILE_V0_OFF_X,       t->x);
    write_u16_le(out + CM_MNCA_TILE_V0_OFF_Y,       t->y);
    write_u32_le(out + CM_MNCA_TILE_V0_OFF_GEN,     t->generation);
    if (rule) memcpy(out + CM_MNCA_TILE_V0_OFF_RULE_ID, rule->rule_id, 4);
    write_u32_le(out + CM_MNCA_TILE_V0_OFF_STATE_LEN, (uint32_t)CM_MNCA_TILE_CELLS);
    memcpy(out + CM_MNCA_TILE_V0_OFF_STATE, t->state, CM_MNCA_TILE_CELLS);
    return CM_MNCA_TILE_V0_HDR_BYTES + CM_MNCA_TILE_CELLS;
}

int cm_mnca_tile_decode(const uint8_t *payload, size_t payload_len, cm_mnca_tile_t *out) {
    if (!payload || !out) return -1;
    if (payload_len < CM_MNCA_TILE_V0_HDR_BYTES) return -1;
    uint32_t state_len = read_u32_le(payload + CM_MNCA_TILE_V0_OFF_STATE_LEN);
    if ((size_t)(CM_MNCA_TILE_V0_HDR_BYTES + state_len) > payload_len) return -1;
    if (state_len != CM_MNCA_TILE_CELLS) return -1;  // expect 8×8 in this impl
    out->x          = read_u16_le(payload + CM_MNCA_TILE_V0_OFF_X);
    out->y          = read_u16_le(payload + CM_MNCA_TILE_V0_OFF_Y);
    out->generation = read_u32_le(payload + CM_MNCA_TILE_V0_OFF_GEN);
    memcpy(out->state, payload + CM_MNCA_TILE_V0_OFF_STATE, CM_MNCA_TILE_CELLS);
    return 0;
}

// ── SHA-256 (pure C — no mbedTLS, for host-testability) ──────────────────────
// This is a compact self-contained SHA-256 implementation used ONLY by the
// quorum hash path in host tests.  The firmware can replace with mbedtls_sha256.

static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
    0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
    0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
    0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
    0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
    0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u,
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define S0(x) (ROTR(x,2)  ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x) (ROTR(x,6)  ^ ROTR(x,11) ^ ROTR(x,25))
#define G0(x) (ROTR(x,7)  ^ ROTR(x,18) ^ ((x) >> 3))
#define G1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))

static void sha256_block(uint32_t H[8], const uint8_t block[64]) {
    uint32_t W[64], a,b,c,d,e,f,g,h,T1,T2;
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[4*i+0]<<24)|((uint32_t)block[4*i+1]<<16)
              |((uint32_t)block[4*i+2]<<8)|(uint32_t)block[4*i+3];
    }
    for (int i = 16; i < 64; i++) W[i] = G1(W[i-2])+W[i-7]+G0(W[i-15])+W[i-16];
    a=H[0];b=H[1];c=H[2];d=H[3];e=H[4];f=H[5];g=H[6];h=H[7];
    for (int i = 0; i < 64; i++) {
        T1 = h + S1(e) + CH(e,f,g) + K256[i] + W[i];
        T2 = S0(a) + MAJ(a,b,c);
        h=g;g=f;f=e;e=d+T1;d=c;c=b;b=a;a=T1+T2;
    }
    H[0]+=a;H[1]+=b;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h;
}

void cm_mnca_tile_hash(const cm_mnca_tile_t *t, uint8_t out_hash[32]) {
    if (!t || !out_hash) return;
    const uint8_t *data = t->state;
    uint32_t len = CM_MNCA_TILE_CELLS;
    uint32_t H[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u,
    };
    uint8_t block[64];
    uint32_t pos = 0;
    while (pos < len) {
        uint32_t copy = len - pos;
        if (copy > 64) copy = 64;
        if (copy < 64) {
            memcpy(block, data + pos, copy);
            block[copy] = 0x80;
            memset(block + copy + 1, 0, 64 - copy - 1);
            if (copy < 56) {
                uint64_t bitlen = (uint64_t)len * 8;
                for (int i = 0; i < 8; i++) block[63-i] = (uint8_t)(bitlen >> (8*i));
                sha256_block(H, block);
            } else {
                sha256_block(H, block);
                memset(block, 0, 56);
                uint64_t bitlen = (uint64_t)len * 8;
                for (int i = 0; i < 8; i++) block[63-i] = (uint8_t)(bitlen >> (8*i));
                sha256_block(H, block);
            }
            break;
        }
        memcpy(block, data + pos, 64);
        sha256_block(H, block);
        pos += 64;
    }
    if (len == 0) {
        memset(block, 0, 64); block[0] = 0x80;
        uint64_t bitlen = 0;
        for (int i = 0; i < 8; i++) block[63-i] = 0;
        sha256_block(H, block);
    }
    for (int i = 0; i < 8; i++) {
        out_hash[4*i+0] = (uint8_t)(H[i]>>24);
        out_hash[4*i+1] = (uint8_t)(H[i]>>16);
        out_hash[4*i+2] = (uint8_t)(H[i]>>8);
        out_hash[4*i+3] = (uint8_t)(H[i]);
    }
}

// ── Quorum table ───────────────────────────────────────────────────────────────

void cm_mnca_quorum_init(cm_mnca_quorum_t *q) {
    if (!q) return;
    memset(q, 0, sizeof(*q));
}

cm_mnca_quorum_rc_t cm_mnca_quorum_update(cm_mnca_quorum_t *q,
                                           uint16_t x, uint16_t y, uint32_t generation,
                                           const uint8_t tile_hash[32],
                                           const uint8_t sender_mac[6],
                                           uint64_t now_ms) {
    if (!q || !tile_hash || !sender_mac) return CM_MNCA_QUORUM_PENDING;

    // Evict stale slots.
    for (int i = 0; i < (int)CM_MNCA_QUORUM_SLOTS; i++) {
        cm_mnca_quorum_slot_t *s = &q->slots[i];
        if (s->valid && (now_ms - s->first_seen_ms) > CM_MNCA_QUORUM_TTL_MS)
            s->valid = false;
    }

    // Find an existing slot for (x, y, generation) or claim a free one.
    cm_mnca_quorum_slot_t *slot = NULL;
    int free_idx = -1;
    for (int i = 0; i < (int)CM_MNCA_QUORUM_SLOTS; i++) {
        cm_mnca_quorum_slot_t *s = &q->slots[i];
        if (!s->valid) { if (free_idx < 0) free_idx = i; continue; }
        if (s->x == x && s->y == y && s->generation == generation) { slot = s; break; }
    }
    if (!slot) {
        if (free_idx < 0) return CM_MNCA_QUORUM_PENDING;  // no room
        slot = &q->slots[free_idx];
        slot->valid        = true;
        slot->x            = x;
        slot->y            = y;
        slot->generation   = generation;
        slot->seen_count   = 0;
        slot->first_seen_ms = now_ms;
    }

    // Ignore duplicate sender for same (x, y, gen) — replay protection.
    for (uint8_t j = 0; j < slot->seen_count; j++) {
        if (memcmp(slot->sender_mac[j], sender_mac, 6) == 0) return CM_MNCA_QUORUM_PENDING;
    }

    // Record this observation.
    uint8_t idx = slot->seen_count;
    if (idx >= CM_MNCA_QUORUM_K + 1) return CM_MNCA_QUORUM_PENDING;  // overflow guard
    memcpy(slot->tile_hash[idx], tile_hash, 32);
    memcpy(slot->sender_mac[idx], sender_mac, 6);
    slot->seen_count++;

    // Check if K entries share the same hash.
    for (uint8_t a = 0; a < slot->seen_count; a++) {
        uint8_t match = 1;
        for (uint8_t b = a + 1; b < slot->seen_count; b++) {
            if (memcmp(slot->tile_hash[a], slot->tile_hash[b], 32) == 0) {
                match++;
            }
        }
        if (match >= CM_MNCA_QUORUM_K) {
            slot->valid = false;  // fire-once — invalidate
            return CM_MNCA_QUORUM_HIT;
        }
    }
    return CM_MNCA_QUORUM_PENDING;
}
