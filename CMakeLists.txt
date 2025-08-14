cmake_minimum_required(VERSION 3.16)
project(wa_proxy)

option(DEBUG "Enable debug mode" OFF)

include(ExternalProject)
# if no cdt root is given use default path
if(CDT_ROOT STREQUAL "" OR NOT CDT_ROOT)
   find_package(cdt)
endif()
set(ADDITIONAL_FLAGS "")
if(DEBUG)
    set(ADDITIONAL_FLAGS "-DDEBUG")
    message(STATUS "Debug mode enabled")
endif()

ExternalProject_Add(
   wa_proxy_project
   SOURCE_DIR ${CMAKE_SOURCE_DIR}/src
   BINARY_DIR ${CMAKE_BINARY_DIR}/wa_proxy
   CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release
              -DCMAKE_TOOLCHAIN_FILE=${CDT_ROOT}/lib/cmake/cdt/CDTWasmToolchain.cmake
              -DCMAKE_CXX_FLAGS=${ADDITIONAL_FLAGS}
   UPDATE_COMMAND ""
   PATCH_COMMAND ""
   TEST_COMMAND ""
   INSTALL_COMMAND ""
   BUILD_ALWAYS 1
)
