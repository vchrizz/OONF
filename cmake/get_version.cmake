#!/bin/cmake
IF(EXISTS "${VERSION_SOURCE_DIR}/version.cmake")
  # preconfigured version data
  FILE (COPY ${VERSION_SOURCE_DIR}/version.cmake DESTINATION ${PROJECT_BINARY_DIR})
ELSEIF(NOT OONF_LIB_GIT OR NOT OONF_VERSION)
  # look for git executable
  SET(found_git false) 
  find_program(found_git git)

  SET(OONF_LIB_GIT "cannot read git repository")

  IF(NOT ${found_git} STREQUAL "found_git-NOTFOUND")
    # get git description WITH dirty flag
    execute_process(COMMAND git describe --always --long --tags --dirty --match "v[0-9]*"
      WORKING_DIRECTORY ${VERSION_SOURCE_DIR}
      OUTPUT_VARIABLE LIB_GIT OUTPUT_STRIP_TRAILING_WHITESPACE)

    # get tag name
    execute_process(COMMAND git describe --abbrev=0 --match "v[0-9]*"
      WORKING_DIRECTORY ${VERSION_SOURCE_DIR} RESULT_VARIABLE result
      OUTPUT_VARIABLE VERSION_TAG OUTPUT_STRIP_TRAILING_WHITESPACE)

    IF(NOT ${result} STREQUAL "0")
        SET(VERSION_TAG "")
    ENDIF()

    IF(NOT ${VERSION_SOURCE_DIR} STREQUAL ${VERSION_SOURCE_SUB_DIR})
        # get git description for submodule WITH dirty flag
        execute_process(COMMAND git describe --always --long --tags --dirty --match "v[0-9]*"
          WORKING_DIRECTORY ${VERSION_SOURCE_SUB_DIR}
          OUTPUT_VARIABLE LIB_SUB_GIT OUTPUT_STRIP_TRAILING_WHITESPACE)

        # get tag name for submodule
        execute_process(COMMAND git describe --abbrev=0 --match "v[0-9]*"
          WORKING_DIRECTORY ${VERSION_SOURCE_SUB_DIR} RESULT_VARIABLE result
          OUTPUT_VARIABLE VERSION_SUB_TAG OUTPUT_STRIP_TRAILING_WHITESPACE)

        IF(NOT ${result} STREQUAL "0")
            SET(VERSION_SUB_TAG "v0.1")
        ENDIF()

        SET(LIB_GIT "${LIB_GIT}_sub_${LIB_SUB_GIT}")
    ENDIF()

    IF("${VERSION_TAG}" STREQUAL "")
        SET(VERSION_TAG "${VERSION_SUB_TAG}")
    ENDIF()

    # strip "v" from tag
    string(SUBSTRING ${VERSION_TAG} 1 -1 VERSION)

  ENDIF()
  
  message ("Git commit: ${LIB_GIT}, Git version: ${VERSION}")
  configure_file (${VERSION_CMAKE_IN} ${PROJECT_BINARY_DIR}/version.cmake)
ENDIF()
