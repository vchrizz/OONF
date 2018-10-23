# build framework
add_subdirectory(libcommon)
add_subdirectory(libconfig)
add_subdirectory(libcore)
add_subdirectory(librfc5444)
#add_subdirectory(crypto)
add_subdirectory(generic)
add_subdirectory(nhdp)
add_subdirectory(olsrv2)
add_subdirectory(base)

if (NOT OONF_NO_TESTING)
    add_subdirectory(tests)
endif (NOT OONF_NO_TESTING)

