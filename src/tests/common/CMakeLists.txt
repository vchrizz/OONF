# just run all of these tests
set(TESTS test_common_avl
          test_common_bitstream
          test_common_isonumber
          test_common_list
          test_common_netaddr
          test_common_string
          test_common_regex
          )
set (LIBS oonf_libcommon)

foreach(TEST ${TESTS})
    oonf_create_test("${TEST}" "${TEST}.c" "${LIBS}")
endforeach(TEST)
