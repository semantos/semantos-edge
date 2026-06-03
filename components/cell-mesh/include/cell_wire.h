// cell_wire.h — canonical cell wire-format accessors.
//
// The cell IS the wire format. A cell is uint8_t[1024] (CM_CELL_SIZE), and
// every field is read or written in-place at its canonical offset (mirroring
// core/protocol-types/src/constants.ts HeaderOffsets, byte-for-byte).
//
// Layout (CM_CELL_SIZE = 1024 bytes total):
//   [   0..255 ] header   (CM_HEADER_SIZE = 256)
//   [ 256..1023] payload  (CM_PAYLOAD_SIZE = 768)
//
// There is NO parallel struct representation. Do not introduce one — see
// memory `cell_is_the_wire_format`. All accessors are zero-copy: scalar
// getters return values; byte-field getters return pointers into the cell
// bytes themselves.

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CM_CELL_SIZE     1024u
#define CM_HEADER_SIZE    256u
#define CM_PAYLOAD_SIZE   768u
#define CM_VERSION          2u

// Magic bytes (4× u32 LE at offset 0).
#define CM_MAGIC_1   0xDEADBEEFu
#define CM_MAGIC_2   0xCAFEBABEu
#define CM_MAGIC_3   0x13371337u
#define CM_MAGIC_4   0x42424242u

// Canonical byte offsets (from constants.ts HeaderOffsets).
#define CM_OFF_MAGIC                   0u
#define CM_OFF_LINEARITY              16u
#define CM_OFF_VERSION                20u
#define CM_OFF_FLAGS                  24u
#define CM_OFF_REF_COUNT              28u
#define CM_OFF_TYPE_HASH              30u
#define CM_OFF_OWNER_ID               62u
#define CM_OFF_TIMESTAMP              78u
#define CM_OFF_CELL_COUNT             86u
#define CM_OFF_PAYLOAD_TOTAL          90u
#define CM_OFF_PARENT_HASH            96u
#define CM_OFF_PREV_STATE_HASH       128u
#define CM_OFF_DOMAIN_PAYLOAD_ROOT   224u
#define CM_OFF_PAYLOAD               256u

// Linearity codes — match Linearity enum in constants.ts.
typedef enum {
    CM_LINEARITY_LINEAR   = 1,
    CM_LINEARITY_AFFINE   = 2,
    CM_LINEARITY_RELEVANT = 3,
    CM_LINEARITY_DEBUG    = 4,
} cm_linearity_t;

// ── Low-level LE reads/writes ────────────────────────────────────────

static inline uint16_t cm_read_u16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static inline uint32_t cm_read_u32(const uint8_t *p) {
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}
static inline uint64_t cm_read_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (i * 8);
    return v;
}
static inline void cm_write_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}
static inline void cm_write_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}
static inline void cm_write_u64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (i * 8)) & 0xff);
}

// ── Cell lifecycle ───────────────────────────────────────────────────

// Zero a cell and write magic + version. Caller fills the rest in-place
// via the field setters. Use this whenever minting a fresh cell.
void cm_cell_init(uint8_t cell[CM_CELL_SIZE]);

// Magic-only validity check on any buffer ≥16 bytes. Cheap sniff for
// candidate cells coming off the radio before committing to handling.
bool cm_is_cell(const uint8_t *buf, size_t buf_len);

// ── Typed scalar accessors ───────────────────────────────────────────
// All read/write in-place on the canonical bytes. No shadow state.

static inline uint32_t cm_linearity(const uint8_t *cell) {
    return cm_read_u32(cell + CM_OFF_LINEARITY);
}
static inline void cm_set_linearity(uint8_t *cell, uint32_t v) {
    cm_write_u32(cell + CM_OFF_LINEARITY, v);
}

static inline uint32_t cm_version(const uint8_t *cell) {
    return cm_read_u32(cell + CM_OFF_VERSION);
}
static inline void cm_set_version(uint8_t *cell, uint32_t v) {
    cm_write_u32(cell + CM_OFF_VERSION, v);
}

static inline uint32_t cm_flags(const uint8_t *cell) {
    return cm_read_u32(cell + CM_OFF_FLAGS);
}
static inline void cm_set_flags(uint8_t *cell, uint32_t v) {
    cm_write_u32(cell + CM_OFF_FLAGS, v);
}

static inline uint16_t cm_ref_count(const uint8_t *cell) {
    return cm_read_u16(cell + CM_OFF_REF_COUNT);
}
static inline void cm_set_ref_count(uint8_t *cell, uint16_t v) {
    cm_write_u16(cell + CM_OFF_REF_COUNT, v);
}

static inline uint64_t cm_timestamp_ms(const uint8_t *cell) {
    return cm_read_u64(cell + CM_OFF_TIMESTAMP);
}
static inline void cm_set_timestamp_ms(uint8_t *cell, uint64_t v) {
    cm_write_u64(cell + CM_OFF_TIMESTAMP, v);
}

static inline uint32_t cm_cell_count(const uint8_t *cell) {
    return cm_read_u32(cell + CM_OFF_CELL_COUNT);
}
static inline void cm_set_cell_count(uint8_t *cell, uint32_t v) {
    cm_write_u32(cell + CM_OFF_CELL_COUNT, v);
}

static inline uint32_t cm_payload_total(const uint8_t *cell) {
    return cm_read_u32(cell + CM_OFF_PAYLOAD_TOTAL);
}
static inline void cm_set_payload_total(uint8_t *cell, uint32_t v) {
    cm_write_u32(cell + CM_OFF_PAYLOAD_TOTAL, v);
}

// ── Byte-field views ─────────────────────────────────────────────────
// Return pointers into the cell bytes. Zero-copy: writes update the cell
// directly, reads view the canonical layout.

static inline const uint8_t *cm_type_hash(const uint8_t *cell)            { return cell + CM_OFF_TYPE_HASH; }
static inline       uint8_t *cm_type_hash_mut(uint8_t *cell)              { return cell + CM_OFF_TYPE_HASH; }

static inline const uint8_t *cm_owner_id(const uint8_t *cell)             { return cell + CM_OFF_OWNER_ID; }
static inline       uint8_t *cm_owner_id_mut(uint8_t *cell)               { return cell + CM_OFF_OWNER_ID; }

static inline const uint8_t *cm_parent_hash(const uint8_t *cell)          { return cell + CM_OFF_PARENT_HASH; }
static inline       uint8_t *cm_parent_hash_mut(uint8_t *cell)            { return cell + CM_OFF_PARENT_HASH; }

static inline const uint8_t *cm_prev_state_hash(const uint8_t *cell)      { return cell + CM_OFF_PREV_STATE_HASH; }
static inline       uint8_t *cm_prev_state_hash_mut(uint8_t *cell)        { return cell + CM_OFF_PREV_STATE_HASH; }

static inline const uint8_t *cm_domain_payload_root(const uint8_t *cell)  { return cell + CM_OFF_DOMAIN_PAYLOAD_ROOT; }
static inline       uint8_t *cm_domain_payload_root_mut(uint8_t *cell)    { return cell + CM_OFF_DOMAIN_PAYLOAD_ROOT; }

static inline const uint8_t *cm_payload(const uint8_t *cell)              { return cell + CM_OFF_PAYLOAD; }
static inline       uint8_t *cm_payload_mut(uint8_t *cell)                { return cell + CM_OFF_PAYLOAD; }

#ifdef __cplusplus
}
#endif
