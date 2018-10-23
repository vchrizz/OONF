# generic oonf library creation

function (oonf_create_library libname source include link_internal linkto_external)
    # create static and dynamic library
    add_library(oonf_${libname} SHARED ${source})
    add_library(oonf_static_${libname} OBJECT ${source})
    
    # add libraries to global static/dynamic target
    add_dependencies(dynamic oonf_${libname})
    add_dependencies(static oonf_static_${libname})

    # and link their dependencies
    if(WIN32)
        target_link_libraries(oonf_${libname} ws2_32 iphlpapi)
    endif(WIN32)

    set_target_properties(oonf_${libname} PROPERTIES SOVERSION "${OONF_VERSION}")

    if (linkto_internal)
        target_link_libraries(oonf_${libname} ${linkto_internal})
    endif (linkto_internal)
    if (linkto_external)
        target_link_libraries(oonf_${libname} ${linkto_external})
    endif (linkto_external)
    
    install(TARGETS oonf_${libname} LIBRARY
                                    DESTINATION ${INSTALL_LIB_DIR}
                                    COMPONENT component_oonf_${libname})
    
    ADD_CUSTOM_TARGET(install_oonf_${libname}
                      COMMAND ${CMAKE_COMMAND} 
                      -DBUILD_TYPE=${CMAKE_BUILD_TYPE}
                      -DCOMPONENT=component_oonf_${libname}
                      -P ${CMAKE_BINARY_DIR}/cmake_install.cmake)
    ADD_DEPENDENCIES(install_oonf_${libname}   oonf_${libname})
    
    if (linkto_internal)
        FOREACH(lib ${linkto_internal})
            ADD_DEPENDENCIES(install_oonf_${libname} ${lib})
            ADD_DEPENDENCIES(install_oonf_${libname} install_${lib})
        ENDFOREACH(lib)
    endif (linkto_internal)
endfunction (oonf_create_library)

function (oonf_create_plugin libname source include linkto_external)
    SET (linkto_internal oonf_libcore oonf_libconfig oonf_libcommon)
    
    oonf_create_library("${libname}" "${source}" "${include}" "${linkto_internal}" "${linkto_external}")
endfunction (oonf_create_plugin)
