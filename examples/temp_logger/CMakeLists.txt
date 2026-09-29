cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")
# cell-mesh for the radio and the templog core; semantos for the cell engine
# that runs the heat policy.
set(COMPONENTS main cell-mesh semantos)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(temp_logger)
