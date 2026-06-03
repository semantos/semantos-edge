cmake_minimum_required(VERSION 3.16)

# Point ESP-IDF at our component directory so it picks up the semantos
# component alongside any managed components you install.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(hello_cell)
