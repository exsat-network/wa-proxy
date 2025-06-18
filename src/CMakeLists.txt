cmake_minimum_required(VERSION 3.16)
project(wa_proxy)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(cdt)

set(SOURCES, "")

list(APPEND SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/actions.cpp
)

add_compile_definitions(ANTELOPE)
add_compile_definitions(PROJECT_VERSION="0.1.0")

add_contract( waproxy_contract wa_proxy ${SOURCES})

target_include_directories( wa_proxy PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_include_directories( wa_proxy PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/rapidjson/include
)

target_ricardian_directory( wa_proxy ${CMAKE_CURRENT_SOURCE_DIR}/../ricardian )

target_compile_options(wa_proxy PUBLIC --no-missing-ricardian-clause )
