cmake_minimum_required(VERSION 3.21)
project(aes_crypto)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(SOURCES_LIST main.c crypto.c user_menu.c pass_manager.c)
add_executable(aes_crypto ${SOURCES_LIST})

set_property(TARGET aes_crypto PROPERTY C_STANDARD 11)

find_package(OpenSSL REQUIRED)
find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} crypto ssl ${CURSES_LIBRARY} menu panel)