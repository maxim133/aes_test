cmake_minimum_required(VERSION 3.21)
project(aes_crypto)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(OpenSSL REQUIRED)
find_package(Curses REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})

add_library(encrypt pass_manager.c crypto.c)

set(SOURCES_LIST main.c crypto.c user_menu.c pass_manager.c)
add_executable(aes_crypto ${SOURCES_LIST})

add_executable(encrypt_test tests/encryption_test.c)
target_link_libraries(encrypt_test PRIVATE encrypt crypto ssl)

set_property(TARGET aes_crypto PROPERTY C_STANDARD 11)

target_link_libraries(${PROJECT_NAME} crypto ssl ${CURSES_LIBRARY} menu panel)

enable_testing()
add_test(
  NAME encrypt_test
  COMMAND $<TARGET_FILE:encrypt_test>
  )