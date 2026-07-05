# cell-mesh — Zig mesh/state core behind the stable cm_* C ABI, plus the
# ESP-IDF-facing transport/signature glue needed to ship cells over ESP-NOW.

set(CELL_MESH_SRCS
    "src/cell_sig.c"
    "src/cell_radio.c"
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

find_program(ZIG_EXECUTABLE zig)
if(NOT ZIG_EXECUTABLE)
    message(FATAL_ERROR
        "cell-mesh uses the Zig core. Install Zig 0.15+ and make `zig` available on PATH.")
endif()

idf_build_get_property(CELL_MESH_IDF_TARGET IDF_TARGET)
if(CELL_MESH_IDF_TARGET MATCHES "^esp32(c2|c3|c5|c6|c61|h2|p4)$")
    set(CELL_MESH_ZIG_TARGET "riscv32-freestanding-none")
    set(CELL_MESH_ZIG_CPU "generic_rv32+a+c+m+zicsr+zifencei")
else()
    message(FATAL_ERROR
        "cell-mesh now links the Zig core and is currently mapped for ESP32 RISC-V targets. "
        "Target '${CELL_MESH_IDF_TARGET}' needs a Zig target mapping before building this component.")
endif()

set(CELL_MESH_ZIG_DIR "${CMAKE_CURRENT_LIST_DIR}/../cell-mesh-zig")
set(CELL_MESH_ZIG_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/zig-prefix")
set(CELL_MESH_ZIG_CACHE "${CMAKE_CURRENT_BINARY_DIR}/zig-cache")
set(CELL_MESH_ZIG_GLOBAL_CACHE "${CMAKE_BINARY_DIR}/zig-global-cache")
set(CELL_MESH_ZIG_LIB "${CELL_MESH_ZIG_PREFIX}/lib/libcell_mesh_zig.a")

file(GLOB CELL_MESH_ZIG_INPUTS CONFIGURE_DEPENDS
    "${CELL_MESH_ZIG_DIR}/build.zig"
    "${CELL_MESH_ZIG_DIR}/src/*.zig"
)

add_custom_command(
    OUTPUT "${CELL_MESH_ZIG_LIB}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory
            "${CELL_MESH_ZIG_PREFIX}" "${CELL_MESH_ZIG_CACHE}" "${CELL_MESH_ZIG_GLOBAL_CACHE}"
    COMMAND "${ZIG_EXECUTABLE}" build
            -Dtarget=${CELL_MESH_ZIG_TARGET}
            -Dcpu=${CELL_MESH_ZIG_CPU}
            -Doptimize=ReleaseSmall
            --prefix "${CELL_MESH_ZIG_PREFIX}"
            --cache-dir "${CELL_MESH_ZIG_CACHE}"
            --global-cache-dir "${CELL_MESH_ZIG_GLOBAL_CACHE}"
    WORKING_DIRECTORY "${CELL_MESH_ZIG_DIR}"
    DEPENDS ${CELL_MESH_ZIG_INPUTS}
    COMMENT "Building Zig cell-mesh core for ${CELL_MESH_IDF_TARGET}"
    VERBATIM
)

add_custom_target(cell_mesh_zig_core DEPENDS "${CELL_MESH_ZIG_LIB}")
add_prebuilt_library(cell_mesh_zig "${CELL_MESH_ZIG_LIB}")
add_dependencies(${COMPONENT_LIB} cell_mesh_zig_core)
target_link_libraries(${COMPONENT_LIB} PUBLIC cell_mesh_zig)
