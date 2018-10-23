set(TESTS test_rfc5444_reader_blockcb
          test_rfc5444_reader_dropcontext
          test_rfc5444_writer_fragmentation
          test_rfc5444_writer_ifspecific
          test_rfc5444_writer_mandatory
          test_rfc5444
          )
set (LIBS oonf_librfc5444 oonf_libcommon)

#include_directories(${CMAKE_SOURCE_DIR}/src-plugins/subsystems)
foreach(TEST ${TESTS})
    oonf_create_test(${TEST} "${TEST}.c" "${LIBS}")
endforeach(TEST)

add_subdirectory(interop2010)
add_subdirectory(special)
