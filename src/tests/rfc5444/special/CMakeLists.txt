set(TESTS test_nhdp_1
          test_nhdp_2
          test_nhdp_3
          test_olsrv2_1
          )
set (LIBS oonf_libcommon oonf_librfc5444)

#include_directories(${CMAKE_SOURCE_DIR}/src-plugins/subsystems)
foreach(TEST ${TESTS})
    oonf_create_test(${TEST} "${TEST}.c" "${LIBS}")
endforeach(TEST)
