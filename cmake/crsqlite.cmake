set(MURMUR_CRSQL_ARCHIVE "" CACHE FILEPATH "Optional prebuilt target-specific isolated cr-sqlite core")
if(MURMUR_CRSQL_ARCHIVE)
  if(NOT EXISTS "${MURMUR_CRSQL_ARCHIVE}")
    message(FATAL_ERROR "MURMUR_CRSQL_ARCHIVE does not exist: ${MURMUR_CRSQL_ARCHIVE}")
  endif()
else()
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  find_program(MURMUR_CARGO cargo REQUIRED)
  if(WIN32)
    set(crsql_rust_target x86_64-pc-windows-gnu)
  else()
    set(crsql_rust_target x86_64-unknown-linux-gnu)
  endif()
  set(MURMUR_CRSQL_ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/crsqlite/libcrsql_bundle_isolated.a")
  file(GLOB_RECURSE crsql_rust_sources CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/deps/crsqlite/rs/*.rs"
    "${PROJECT_SOURCE_DIR}/deps/crsqlite/rs/*.toml"
    "${PROJECT_SOURCE_DIR}/deps/crsqlite/rs/*.lock"
    "${PROJECT_SOURCE_DIR}/deps/crsqlite/rs/*.h")
  add_custom_command(OUTPUT "${MURMUR_CRSQL_ARCHIVE}"
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tools/build_crsqlite.py"
      --cargo "${MURMUR_CARGO}" --cc "${CMAKE_C_COMPILER}" --target "${crsql_rust_target}"
      --target-dir "${CMAKE_CURRENT_BINARY_DIR}/crsqlite/cargo"
      --nm "${CMAKE_NM}" --objcopy "${CMAKE_OBJCOPY}" --output "${MURMUR_CRSQL_ARCHIVE}"
    DEPENDS ${crsql_rust_sources} "${PROJECT_SOURCE_DIR}/deps/crsqlite/UPSTREAM.json"
      "${PROJECT_SOURCE_DIR}/tools/build_crsqlite.py" VERBATIM)
  add_custom_target(murmur-crsqlite-build DEPENDS "${MURMUR_CRSQL_ARCHIVE}")
endif()
add_library(murmur-crsqlite-core STATIC IMPORTED GLOBAL)
set_target_properties(murmur-crsqlite-core PROPERTIES IMPORTED_LOCATION "${MURMUR_CRSQL_ARCHIVE}")
if(TARGET murmur-crsqlite-build)
  add_dependencies(murmur-crsqlite-core murmur-crsqlite-build)
endif()
add_executable(murmur-test-crsqlite tests/native/crsqlite_upstream.c
  deps/sqlite/sqlite3.c deps/crsqlite/wrapper_tu.c deps/murmur/crsqlite_ingest.c
  deps/murmur/msgcodec.c deps/murmur/member.c)
target_include_directories(murmur-test-crsqlite PRIVATE deps/sqlite deps/crsqlite/include deps/murmur)
target_compile_definitions(murmur-test-crsqlite PRIVATE SQLITE_CORE SQLITE_THREADSAFE=1)
target_link_libraries(murmur-test-crsqlite PRIVATE murmur-crsqlite-core Threads::Threads ${CMAKE_DL_LIBS})
if(WIN32)
  target_link_libraries(murmur-test-crsqlite PRIVATE ws2_32 bcrypt userenv)
else()
  target_link_libraries(murmur-test-crsqlite PRIVATE m)
endif()
add_test(NAME crsqlite-upstream COMMAND murmur-test-crsqlite)
