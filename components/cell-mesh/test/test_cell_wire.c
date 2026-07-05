// test_cell_wire.c — host-side smoke test for the cell wire accessors.
//
// Verifies the canonical 1024-byte cell layout in-place: fields written via
// accessors land at the right offsets, and fields at canonical offsets read
// back through accessors faithfully. There is no parallel struct — every
// test operates on uint8_t[1024] directly.
//
// Run through the Zig C-ABI harness:
//   ../cell-mesh-zig/run-c-abi-tests.sh

#include "cell_wire.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); fails++; } \
    else         { printf("ok:   %s\n", msg); } \
} while (0)

int main(void) {
    int fails = 0;

    // ── Test 1: cm_cell_init zeros + writes magic + version ─────────
    {
        uint8_t cell[CM_CELL_SIZE];
        memset(cell, 0x77, sizeof(cell));  // poison

        cm_cell_init(cell);

        // Magic bytes (4× u32 LE at offset 0).
        CHECK(cell[0]  == 0xEF && cell[1]  == 0xBE && cell[2]  == 0xAD && cell[3]  == 0xDE, "magic1 at offset 0");
        CHECK(cell[4]  == 0xBE && cell[5]  == 0xBA && cell[6]  == 0xFE && cell[7]  == 0xCA, "magic2 at offset 4");
        CHECK(cell[8]  == 0x37 && cell[9]  == 0x13 && cell[10] == 0x37 && cell[11] == 0x13, "magic3 at offset 8");
        CHECK(cell[12] == 0x42 && cell[13] == 0x42 && cell[14] == 0x42 && cell[15] == 0x42, "magic4 at offset 12");

        // Version set to CM_VERSION at offset 20.
        CHECK(cm_version(cell) == CM_VERSION, "init sets version=CM_VERSION");

        // Everything outside magic+version is zeroed.
        CHECK(cell[16] == 0 && cell[17] == 0 && cell[18] == 0 && cell[19] == 0, "linearity zeroed");
        CHECK(cell[CM_OFF_PAYLOAD] == 0 && cell[CM_CELL_SIZE - 1] == 0,         "payload region zeroed");
    }

    // ── Test 2: scalar setters land at canonical offsets ─────────────
    {
        uint8_t cell[CM_CELL_SIZE];
        cm_cell_init(cell);

        cm_set_linearity(cell,     0x11111111);
        cm_set_version(cell,       0x22222222);
        cm_set_flags(cell,         0x33333333);
        cm_set_ref_count(cell,     0x4444);
        cm_set_timestamp_ms(cell,  0x5555555555555555ULL);
        cm_set_cell_count(cell,    0x66666666);
        cm_set_payload_total(cell, 0x77777777);

        CHECK(cell[16] == 0x11 && cell[19] == 0x11, "linearity at offset 16 (LE u32)");
        CHECK(cell[20] == 0x22 && cell[23] == 0x22, "version at offset 20 (LE u32)");
        CHECK(cell[24] == 0x33 && cell[27] == 0x33, "flags at offset 24 (LE u32)");
        CHECK(cell[28] == 0x44 && cell[29] == 0x44, "ref_count at offset 28 (LE u16)");
        CHECK(cell[78] == 0x55 && cell[85] == 0x55, "timestamp at offset 78 (LE u64)");
        CHECK(cell[86] == 0x66 && cell[89] == 0x66, "cell_count at offset 86 (LE u32)");
        CHECK(cell[90] == 0x77 && cell[93] == 0x77, "payload_total at offset 90 (LE u32)");

        // And they round-trip through accessors.
        CHECK(cm_linearity(cell)     == 0x11111111,         "linearity round-trips via accessor");
        CHECK(cm_version(cell)       == 0x22222222,         "version round-trips via accessor");
        CHECK(cm_flags(cell)         == 0x33333333,         "flags round-trips via accessor");
        CHECK(cm_ref_count(cell)     == 0x4444,             "ref_count round-trips via accessor");
        CHECK(cm_timestamp_ms(cell)  == 0x5555555555555555ULL, "timestamp_ms round-trips via accessor");
        CHECK(cm_cell_count(cell)    == 0x66666666,         "cell_count round-trips via accessor");
        CHECK(cm_payload_total(cell) == 0x77777777,         "payload_total round-trips via accessor");
    }

    // ── Test 3: byte-field views point at canonical offsets ─────────
    {
        uint8_t cell[CM_CELL_SIZE];
        cm_cell_init(cell);

        uint8_t pattern_a[32]; for (int i = 0; i < 32; i++) pattern_a[i] = 0xA0 + i;
        uint8_t pattern_b[16]; for (int i = 0; i < 16; i++) pattern_b[i] = 0xB0 + i;
        uint8_t pattern_c[32]; for (int i = 0; i < 32; i++) pattern_c[i] = 0xC0 + i;
        uint8_t pattern_d[32]; for (int i = 0; i < 32; i++) pattern_d[i] = 0xD0 + i;
        uint8_t pattern_e[32]; for (int i = 0; i < 32; i++) pattern_e[i] = 0xE0 + i;

        memcpy(cm_type_hash_mut(cell),           pattern_a, 32);
        memcpy(cm_owner_id_mut(cell),            pattern_b, 16);
        memcpy(cm_parent_hash_mut(cell),         pattern_c, 32);
        memcpy(cm_prev_state_hash_mut(cell),     pattern_d, 32);
        memcpy(cm_domain_payload_root_mut(cell), pattern_e, 32);

        CHECK(cell[30]  == 0xA0 && cell[61]  == 0xA0 + 31, "type_hash written at offset 30");
        CHECK(cell[62]  == 0xB0 && cell[77]  == 0xB0 + 15, "owner_id written at offset 62");
        CHECK(cell[96]  == 0xC0 && cell[127] == 0xC0 + 31, "parent_hash written at offset 96");
        CHECK(cell[128] == 0xD0 && cell[159] == 0xD0 + 31, "prev_state_hash written at offset 128");
        CHECK(cell[224] == 0xE0 && cell[255] == 0xE0 + 31, "domain_payload_root written at offset 224");

        // Reads via const accessors must point at the SAME bytes (zero copy).
        CHECK(cm_type_hash(cell)           == cell + 30,  "type_hash view is zero-copy into cell");
        CHECK(cm_owner_id(cell)            == cell + 62,  "owner_id view is zero-copy into cell");
        CHECK(cm_parent_hash(cell)         == cell + 96,  "parent_hash view is zero-copy into cell");
        CHECK(cm_prev_state_hash(cell)     == cell + 128, "prev_state_hash view is zero-copy into cell");
        CHECK(cm_domain_payload_root(cell) == cell + 224, "domain_payload_root view is zero-copy into cell");
        CHECK(cm_payload(cell)             == cell + 256, "payload view is zero-copy into cell");

        CHECK(memcmp(cm_type_hash(cell),           pattern_a, 32) == 0, "type_hash content matches");
        CHECK(memcmp(cm_owner_id(cell),            pattern_b, 16) == 0, "owner_id content matches");
        CHECK(memcmp(cm_parent_hash(cell),         pattern_c, 32) == 0, "parent_hash content matches");
        CHECK(memcmp(cm_prev_state_hash(cell),     pattern_d, 32) == 0, "prev_state_hash content matches");
        CHECK(memcmp(cm_domain_payload_root(cell), pattern_e, 32) == 0, "domain_payload_root content matches");
    }

    // ── Test 4: reserved regions remain zero after init ─────────────
    // Bytes 94-95 and 160-223 are reserved per the canonical layout.
    {
        uint8_t cell[CM_CELL_SIZE];
        cm_cell_init(cell);

        // Set every named field; ensure reserved zones still read zero.
        cm_set_linearity(cell, 0xFFFFFFFF);
        cm_set_flags(cell,     0xFFFFFFFF);
        cm_set_ref_count(cell, 0xFFFF);
        cm_set_timestamp_ms(cell,  0xFFFFFFFFFFFFFFFFULL);
        memset(cm_type_hash_mut(cell),           0xFF, 32);
        memset(cm_owner_id_mut(cell),            0xFF, 16);
        memset(cm_parent_hash_mut(cell),         0xFF, 32);
        memset(cm_prev_state_hash_mut(cell),     0xFF, 32);
        memset(cm_domain_payload_root_mut(cell), 0xFF, 32);

        CHECK(cell[94] == 0 && cell[95] == 0, "reserved bytes 94-95 stay zero");
        int reserved_160_223_zero = 1;
        for (int i = 160; i < 224; i++) if (cell[i] != 0) { reserved_160_223_zero = 0; break; }
        CHECK(reserved_160_223_zero, "reserved bytes 160-223 stay zero");
    }

    // ── Test 5: cm_is_cell sniff ────────────────────────────────────
    {
        uint8_t cell[CM_CELL_SIZE];
        cm_cell_init(cell);
        CHECK(cm_is_cell(cell, 16)         == true,  "is_cell accepts freshly init'd cell");
        CHECK(cm_is_cell(cell, CM_CELL_SIZE) == true, "is_cell accepts full-cell buffer");

        uint8_t junk[16] = {0};
        CHECK(cm_is_cell(junk, 16) == false, "is_cell rejects all-zero");

        CHECK(cm_is_cell(cell, 8)  == false, "is_cell rejects short buffer");
        CHECK(cm_is_cell(NULL, 16) == false, "is_cell rejects NULL");
    }

    // ── Test 6: writes-into-payload land at byte 256+ ───────────────
    {
        uint8_t cell[CM_CELL_SIZE];
        cm_cell_init(cell);

        uint8_t *p = cm_payload_mut(cell);
        for (size_t i = 0; i < 256; i++) p[i] = (uint8_t)(i ^ 0x5A);
        cm_set_payload_total(cell, 256);

        CHECK(cell[CM_OFF_PAYLOAD]       == (0 ^ 0x5A),    "payload[0] at byte 256");
        CHECK(cell[CM_OFF_PAYLOAD + 255] == (255 ^ 0x5A),  "payload[255] at byte 511");
        CHECK(cell[CM_OFF_PAYLOAD + 256] == 0,             "payload region beyond write stays zero");
        CHECK(cm_payload_total(cell) == 256,               "payload_total reflects what was written");
    }

    if (fails == 0) {
        printf("\nAll tests passed.\n");
        return 0;
    } else {
        printf("\n%d test(s) failed.\n", fails);
        return 1;
    }
}
