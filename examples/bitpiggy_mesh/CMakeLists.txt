cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")
# Whitelist of components mesh_demo pulls in. `semantos` is the BSV-
# script cell-engine (Zig kernel compiled to WASM, hosted by WAMR).
# Brings ~250 KB of WAMR + the 29 KB WASM blob; that's why we bumped
# the app partition to 2 MB in partitions.csv.
set(COMPONENTS main cell-mesh semantos)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(bitpiggy_mesh)
