set(TESTS test_config_list
          test_config_validation
          test_config_mapping
          test_config_cmd
          test_config_default
          test_config_delta
          )
set (LIBS oonf_libconfig oonf_libcommon)

foreach(TEST ${TESTS})
    oonf_create_test("${TEST}" "${TEST}.c" "${LIBS}")
endforeach(TEST)
