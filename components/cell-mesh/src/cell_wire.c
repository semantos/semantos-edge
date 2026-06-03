// cell_wire.c — cell lifecycle helpers. The cell IS the wire format;
// everything else is inline accessors in cell_wire.h.

#include "cell_wire.h"

void cm_cell_init(uint8_t cell[CM_CELL_SIZE]) {
    memset(cell, 0, CM_CELL_SIZE);
    cm_write_u32(cell + CM_OFF_MAGIC +  0, CM_MAGIC_1);
    cm_write_u32(cell + CM_OFF_MAGIC +  4, CM_MAGIC_2);
    cm_write_u32(cell + CM_OFF_MAGIC +  8, CM_MAGIC_3);
    cm_write_u32(cell + CM_OFF_MAGIC + 12, CM_MAGIC_4);
    cm_set_version(cell, CM_VERSION);
}

bool cm_is_cell(const uint8_t *buf, size_t buf_len) {
    if (!buf || buf_len < 16) return false;
    return cm_read_u32(buf +  0) == CM_MAGIC_1
        && cm_read_u32(buf +  4) == CM_MAGIC_2
        && cm_read_u32(buf +  8) == CM_MAGIC_3
        && cm_read_u32(buf + 12) == CM_MAGIC_4;
}
