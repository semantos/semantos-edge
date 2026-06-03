cmake_minimum_required(VERSION 3.16)

# Point ESP-IDF at our component directory so it picks up cell-mesh.
# We deliberately do NOT include the full semantos component (WAMR) —
# cold chain only needs cell_wire.h, SHA-256, WiFi, and NVS.  This
# keeps the firmware well under the C6's 329 KB SRAM ceiling.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(cold_chain)
