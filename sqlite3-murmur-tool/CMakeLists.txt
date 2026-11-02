cmake_minimum_required(VERSION 3.20)
if(NOT TARGET murmur::murmur)
  project(sqlite3_murmur_tool C CXX)
  # Keep configuring this directory supported; the root owns the full library.
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/.." "${CMAKE_CURRENT_BINARY_DIR}/libmurmur")
  return()
endif()
get_filename_component(ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
find_program(MURMUR_PATCH patch REQUIRED)
add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/shell.c"
  COMMAND "${MURMUR_PATCH}" --batch --fuzz=0 --output=${CMAKE_CURRENT_BINARY_DIR}/shell.c
    "${ROOT}/deps/sqlite/shell.c" "${CMAKE_CURRENT_SOURCE_DIR}/shell.patch"
  DEPENDS "${ROOT}/deps/sqlite/shell.c" shell.patch VERBATIM)
add_library(murmur-shell OBJECT "${CMAKE_CURRENT_BINARY_DIR}/shell.c")
target_compile_definitions(murmur-shell PRIVATE main=murmur_sqlite_shell_main
  SQLITE_SHELL_INIT_PROC=murmur_tool_init SQLITE_ENABLE_FTS5)
target_include_directories(murmur-shell PRIVATE "${ROOT}/deps/sqlite" "${CMAKE_CURRENT_SOURCE_DIR}")
add_executable(sqlite3-murmur tool.c admin.c $<TARGET_OBJECTS:murmur-shell>)
if(WIN32)
  # Ship a standalone executable without MinGW runtime DLLs.
  target_link_options(sqlite3-murmur PRIVATE -static -static-libgcc -static-libstdc++)
  enable_language(RC)
  target_sources(sqlite3-murmur PRIVATE win64.rc)
endif()
target_include_directories(sqlite3-murmur PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}"
  "${ROOT}/deps" "${ROOT}/deps/keyring")
target_link_libraries(sqlite3-murmur PRIVATE murmur::murmur)
