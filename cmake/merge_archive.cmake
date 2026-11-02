# GNU ar's MRI parser does not support spaces in archive paths, even quoted.
# Use fixed relative names inside a staging directory; retain every member.
set(stage "${ARCHIVE}.merge-work")
file(MAKE_DIRECTORY "${stage}")
file(COPY_FILE "${ARCHIVE}" "${stage}/native.a")
file(COPY_FILE "${ROCKSDB}" "${stage}/rocksdb.a")
file(COPY_FILE "${CRYPTO}" "${stage}/crypto.a")
file(COPY_FILE "${CRSQL}" "${stage}/crsql.a")
file(WRITE "${stage}/merge.mri" "create merged.a\naddlib native.a\naddlib rocksdb.a\naddlib crypto.a\naddlib crsql.a\nsave\nend\n")
execute_process(COMMAND "${AR}" -M INPUT_FILE "${stage}/merge.mri"
  WORKING_DIRECTORY "${stage}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Archive merge failed: ${result}")
endif()
file(RENAME "${stage}/merged.a" "${ARCHIVE}")
file(REMOVE_RECURSE "${stage}")
