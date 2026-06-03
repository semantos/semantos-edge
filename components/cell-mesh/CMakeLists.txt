# cell-mesh — radio-mesh + rules + effects layer on top of the semantos
# cell-engine component. Encodes/decodes the canonical 1024-byte cell wire
# format (mirrors core/protocol-types), ships cells over ESP-NOW, signs
# and verifies them with ECDSA-secp256k1.
#
# Pure C. The cell-engine WASM kernel is only consulted when a cell
# carries a script that needs to execute; the radio + sig hot path lives
# entirely in this component.

set(CELL_MESH_SRCS
    "src/cell_wire.c"
    "src/cell_ring.c"
    "src/cell_frame.c"
    "src/cell_sig.c"
    "src/cell_radio.c"
    "src/cell_rules.c"
    "src/cell_channel.c"
    "src/cell_meter.c"
    "src/cell_forward.c"
    "src/cell_forward_v1.c"
    "src/cell_forward_v2.c"
    "src/cell_capability.c"
    "src/cell_mnca.c"
)

idf_component_register(
    SRCS ${CELL_MESH_SRCS}
    INCLUDE_DIRS "include"
    REQUIRES
        mbedtls
        esp_wifi
        esp_event
        esp_netif
        nvs_flash
        # esp_now ships inside esp_wifi as of IDF 5.x; if your IDF splits
        # it into a separate component, append `esp_now` here. The semantos
        # cell-engine component is NOT required here — apps that want both
        # cell-mesh radio AND on-device cell-engine verification add both
        # to their own REQUIRES (e.g. the hello_cell + mesh combination).
)
