# make sure that oonf_libdata is rebuild everytimes 
SET(GEN_DATA_C ${PROJECT_BINARY_DIR}/oonf_libdata.c)
configure_file (${CMAKE_CURRENT_SOURCE_DIR}/oonf_libdata.c.in ${GEN_DATA_C})

SET(OONF_CORE_SRCS oonf_cfg.c
                   oonf_logging.c
                   oonf_logging_cfg.c
                   oonf_main.c
                   oonf_subsystem.c
                   ${GEN_DATA_C})

SET(OONF_CORE_INCLUDES oonf_appdata.h
                       oonf_cfg.h
                       oonf_logging.h
                       oonf_logging_cfg.h
                       oonf_main.h
                       oonf_subsystem.h
                       oonf_libdata.h
                       os_core.h
                       )

# add os_specific source(include files
# TODO: add BSD and WIN32
IF(LINUX)
    SET(OONF_CORE_SRCS ${OONF_CORE_SRCS}
                       os_generic/os_core_generic_syslog.c
                       os_linux/os_core_linux.c
                       )
    SET(OONF_CORE_INCLUDES ${OONF_CORE_INCLUDES}
                       os_generic/os_core_generic_syslog.h
                       os_linux/os_core_linux.h
                       )
ENDIF(LINUX)

SET(linkto_internal oonf_libcommon oonf_libconfig)

oonf_create_library("libcore" "${OONF_CORE_SRCS}" "${OONF_CORE_INCLUDES}" "${linkto_internal}" "${CMAKE_DL_LIBS}")

# remove git commit cache entry
UNSET (OONF_LIB_GIT CACHE)
