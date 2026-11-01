cmake_minimum_required(VERSION 3.20)
project(sqlite3_murmur_tool C CXX RC)
if(NOT WIN32)
  message(FATAL_ERROR "Use the root Makefile for the Linux build")
endif()
get_filename_component(ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601
  SQLITE_ENABLE_FTS5 SQLITE_THREADSAFE=1 SQLITE_ENABLE_PREUPDATE_HOOK=1 ZSTD_DISABLE_ASM=1)
add_compile_options(-ffunction-sections -fdata-sections)
file(GLOB ZSTD "${ROOT}/deps/zstd/*.c")
file(GLOB_RECURSE AEGIS "${ROOT}/deps/aegis/src/*.c")
# This CLI uses the native storage part of libmurmur. Replication/transport
# objects, which neither shell references, are omitted from this archive.
add_library(murmur-storage STATIC
  "${ROOT}/libmurmur.c" "${ROOT}/deps/sqlite/sqlite3.c"
  "${ROOT}/deps/murmur/public.cc" "${ROOT}/deps/murmur/open.cc"
  "${ROOT}/deps/murmur/vfs.cc" "${ROOT}/deps/murmur/store.cc"
  "${ROOT}/deps/murmur/db.cc" "${ROOT}/deps/murmur/cache.cc"
  "${ROOT}/deps/codec/codec.cc" "${ROOT}/deps/codec/aesgcm.cc"
  "${ROOT}/deps/keyring/keyring.cc" "${ROOT}/deps/keyring/sha256.c"
  "${ROOT}/deps/keyring/hkdf.c" "${ROOT}/deps/keyring/crc32c.c"
  "${ROOT}/deps/argon2/argon2.c" "${ROOT}/deps/argon2/core.c"
  "${ROOT}/deps/argon2/ref.c" "${ROOT}/deps/argon2/encoding.c"
  "${ROOT}/deps/argon2/thread.c" "${ROOT}/deps/argon2/blake2/blake2b.c"
  ${ZSTD} ${AEGIS})
target_include_directories(murmur-storage PUBLIC "${ROOT}" "${ROOT}/deps/sqlite"
  "${ROOT}/deps/codec" "${ROOT}/deps/keyring" "${ROOT}/deps/murmur"
  "${ROOT}/deps/zstd" "${ROOT}/deps/argon2" "${ROOT}/deps/aegis/src/include"
  "${ROOT}/deps/aws-lc/include" "${ROOT}/deps/rocksdb/include")
set_source_files_properties("${ROOT}/deps/murmur/public.cc" PROPERTIES COMPILE_DEFINITIONS MURMUR_STORAGE_ONLY)
add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/shell.c"
  COMMAND patch --batch --fuzz=0 --output=${CMAKE_CURRENT_BINARY_DIR}/shell.c
    "${ROOT}/deps/sqlite/shell.c" "${CMAKE_CURRENT_SOURCE_DIR}/shell.patch"
  DEPENDS "${ROOT}/deps/sqlite/shell.c" shell.patch VERBATIM)
add_library(murmur-shell OBJECT "${CMAKE_CURRENT_BINARY_DIR}/shell.c")
target_compile_definitions(murmur-shell PRIVATE main=murmur_sqlite_shell_main
  SQLITE_SHELL_INIT_PROC=murmur_tool_init)
target_include_directories(murmur-shell PRIVATE "${ROOT}/deps/sqlite" "${CMAKE_CURRENT_SOURCE_DIR}")
add_executable(sqlite3-murmur tool.c win64.rc $<TARGET_OBJECTS:murmur-shell>)
target_include_directories(sqlite3-murmur PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_options(sqlite3-murmur PRIVATE -static -Wl,--gc-sections)
target_link_libraries(sqlite3-murmur PRIVATE murmur-storage
  "${ROOT}/build/win64/rocksdb/librocksdb.a"
  "${ROOT}/build/win64/aws-lc/crypto/libcrypto.a"
  bcrypt crypt32 ws2_32 rpcrt4 shlwapi)
