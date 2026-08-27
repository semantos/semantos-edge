/*
 * domainflag_vectors.h — GENERATED. Do not hand-edit.
 *
 * Produced by test/vectors/gen-domainflag-vectors.mjs, which runs the REAL
 * OP_CHECKDOMAINFLAG (opcode 198) inside the WASM cell engine this firmware
 * embeds — components/semantos/wasm/cell-engine-embedded.wasm — over the
 * canonical script <cell> <expected_flag> OP_CHECKDOMAINFLAG.
 *
 * accept = the engine returned 0. reject = the engine returned 28
 * (domain_flag_mismatch). Nothing here is asserted from a spec or a comment;
 * every row is an observation of the binary that ships.
 *
 * 64 rows, 8 flags, every ordered pair.
 *
 * ⚠ ENCODING, measured not assumed: the opcode reads the expected flag as a BSV
 * SCRIPT NUMBER, not a raw u32. Bit 7 of the top byte is the SIGN. A 4-byte LE
 * push of 0x80000000 is 00 00 00 80 = script-number negative zero, and the
 * engine compares it as 0 — so a cell declaring domain 0 ACCEPTS against it.
 * Confirmed against the live engine for 0x80000000, 0xffffffff and 0xfffffffe:
 * in every case the zero cell was accepted AND the matching cell was rejected.
 * Domain flags must therefore stay below 0x80000000; domains.zig enforces it.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t    actual;
    uint32_t    expected;
    bool        accept;
    const char *label;
} cm_domainflag_vector_t;

#define CM_DOMAINFLAG_VECTOR_COUNT 64

static const cm_domainflag_vector_t CM_DOMAINFLAG_VECTORS[CM_DOMAINFLAG_VECTOR_COUNT] = {
    { 0x00000000u, 0x00000000u, true , "UNDECLARED vs UNDECLARED" },
    { 0x00000000u, 0x0000000eu, false, "UNDECLARED vs ZONE" },
    { 0x00000000u, 0x00000006u, false, "UNDECLARED vs CHILD_CREATE" },
    { 0x00000000u, 0x00000080u, false, "UNDECLARED vs PAD_BOUNDARY" },
    { 0x00000000u, 0x00f10001u, false, "UNDECLARED vs FLEET_DEVICE" },
    { 0x00000000u, 0x00f10002u, false, "UNDECLARED vs ORG_MEMBER" },
    { 0x00000000u, 0x00f10003u, false, "UNDECLARED vs NEIGHBOUR" },
    { 0x00000000u, 0x7fffffffu, false, "UNDECLARED vs SAFE_MAX" },
    { 0x0000000eu, 0x00000000u, false, "ZONE vs UNDECLARED" },
    { 0x0000000eu, 0x0000000eu, true , "ZONE vs ZONE" },
    { 0x0000000eu, 0x00000006u, false, "ZONE vs CHILD_CREATE" },
    { 0x0000000eu, 0x00000080u, false, "ZONE vs PAD_BOUNDARY" },
    { 0x0000000eu, 0x00f10001u, false, "ZONE vs FLEET_DEVICE" },
    { 0x0000000eu, 0x00f10002u, false, "ZONE vs ORG_MEMBER" },
    { 0x0000000eu, 0x00f10003u, false, "ZONE vs NEIGHBOUR" },
    { 0x0000000eu, 0x7fffffffu, false, "ZONE vs SAFE_MAX" },
    { 0x00000006u, 0x00000000u, false, "CHILD_CREATE vs UNDECLARED" },
    { 0x00000006u, 0x0000000eu, false, "CHILD_CREATE vs ZONE" },
    { 0x00000006u, 0x00000006u, true , "CHILD_CREATE vs CHILD_CREATE" },
    { 0x00000006u, 0x00000080u, false, "CHILD_CREATE vs PAD_BOUNDARY" },
    { 0x00000006u, 0x00f10001u, false, "CHILD_CREATE vs FLEET_DEVICE" },
    { 0x00000006u, 0x00f10002u, false, "CHILD_CREATE vs ORG_MEMBER" },
    { 0x00000006u, 0x00f10003u, false, "CHILD_CREATE vs NEIGHBOUR" },
    { 0x00000006u, 0x7fffffffu, false, "CHILD_CREATE vs SAFE_MAX" },
    { 0x00000080u, 0x00000000u, false, "PAD_BOUNDARY vs UNDECLARED" },
    { 0x00000080u, 0x0000000eu, false, "PAD_BOUNDARY vs ZONE" },
    { 0x00000080u, 0x00000006u, false, "PAD_BOUNDARY vs CHILD_CREATE" },
    { 0x00000080u, 0x00000080u, true , "PAD_BOUNDARY vs PAD_BOUNDARY" },
    { 0x00000080u, 0x00f10001u, false, "PAD_BOUNDARY vs FLEET_DEVICE" },
    { 0x00000080u, 0x00f10002u, false, "PAD_BOUNDARY vs ORG_MEMBER" },
    { 0x00000080u, 0x00f10003u, false, "PAD_BOUNDARY vs NEIGHBOUR" },
    { 0x00000080u, 0x7fffffffu, false, "PAD_BOUNDARY vs SAFE_MAX" },
    { 0x00f10001u, 0x00000000u, false, "FLEET_DEVICE vs UNDECLARED" },
    { 0x00f10001u, 0x0000000eu, false, "FLEET_DEVICE vs ZONE" },
    { 0x00f10001u, 0x00000006u, false, "FLEET_DEVICE vs CHILD_CREATE" },
    { 0x00f10001u, 0x00000080u, false, "FLEET_DEVICE vs PAD_BOUNDARY" },
    { 0x00f10001u, 0x00f10001u, true , "FLEET_DEVICE vs FLEET_DEVICE" },
    { 0x00f10001u, 0x00f10002u, false, "FLEET_DEVICE vs ORG_MEMBER" },
    { 0x00f10001u, 0x00f10003u, false, "FLEET_DEVICE vs NEIGHBOUR" },
    { 0x00f10001u, 0x7fffffffu, false, "FLEET_DEVICE vs SAFE_MAX" },
    { 0x00f10002u, 0x00000000u, false, "ORG_MEMBER vs UNDECLARED" },
    { 0x00f10002u, 0x0000000eu, false, "ORG_MEMBER vs ZONE" },
    { 0x00f10002u, 0x00000006u, false, "ORG_MEMBER vs CHILD_CREATE" },
    { 0x00f10002u, 0x00000080u, false, "ORG_MEMBER vs PAD_BOUNDARY" },
    { 0x00f10002u, 0x00f10001u, false, "ORG_MEMBER vs FLEET_DEVICE" },
    { 0x00f10002u, 0x00f10002u, true , "ORG_MEMBER vs ORG_MEMBER" },
    { 0x00f10002u, 0x00f10003u, false, "ORG_MEMBER vs NEIGHBOUR" },
    { 0x00f10002u, 0x7fffffffu, false, "ORG_MEMBER vs SAFE_MAX" },
    { 0x00f10003u, 0x00000000u, false, "NEIGHBOUR vs UNDECLARED" },
    { 0x00f10003u, 0x0000000eu, false, "NEIGHBOUR vs ZONE" },
    { 0x00f10003u, 0x00000006u, false, "NEIGHBOUR vs CHILD_CREATE" },
    { 0x00f10003u, 0x00000080u, false, "NEIGHBOUR vs PAD_BOUNDARY" },
    { 0x00f10003u, 0x00f10001u, false, "NEIGHBOUR vs FLEET_DEVICE" },
    { 0x00f10003u, 0x00f10002u, false, "NEIGHBOUR vs ORG_MEMBER" },
    { 0x00f10003u, 0x00f10003u, true , "NEIGHBOUR vs NEIGHBOUR" },
    { 0x00f10003u, 0x7fffffffu, false, "NEIGHBOUR vs SAFE_MAX" },
    { 0x7fffffffu, 0x00000000u, false, "SAFE_MAX vs UNDECLARED" },
    { 0x7fffffffu, 0x0000000eu, false, "SAFE_MAX vs ZONE" },
    { 0x7fffffffu, 0x00000006u, false, "SAFE_MAX vs CHILD_CREATE" },
    { 0x7fffffffu, 0x00000080u, false, "SAFE_MAX vs PAD_BOUNDARY" },
    { 0x7fffffffu, 0x00f10001u, false, "SAFE_MAX vs FLEET_DEVICE" },
    { 0x7fffffffu, 0x00f10002u, false, "SAFE_MAX vs ORG_MEMBER" },
    { 0x7fffffffu, 0x00f10003u, false, "SAFE_MAX vs NEIGHBOUR" },
    { 0x7fffffffu, 0x7fffffffu, true , "SAFE_MAX vs SAFE_MAX" },
};
