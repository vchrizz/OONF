# calculate default cmake file install target
if (WIN32 AND NOT CYGWIN)
  set(DEF_INSTALL_CMAKE_DIR CMake)
else ()
  set(DEF_INSTALL_CMAKE_DIR lib/oonf)
endif ()

###########################
#### API configuration ####
###########################

# set CMAKE build type for api and plugins
# (Debug, Release, MinSizeRel)
set (CMAKE_BUILD_TYPE Debug CACHE STRING
     "Choose the type of build (Debug Release RelWithDebInfo MinSizeRel)")

# maximum logging level
set (OONF_LOGGING_LEVEL debug CACHE STRING 
     "Maximum logging level compiled into OONF API (warn, info, debug)")
SET_PROPERTY(CACHE OONF_LOGGING_LEVEL PROPERTY STRINGS debug info warn)
 
# remove help texts from application, core-api and plugins
set (OONF_REMOVE_HELPTEXT false CACHE BOOL
     "Set if you want to remove the help texts from application to reduce size")

set (OONF_SANITIZE false CACHE BOOL
     "Activate the address sanitizer")

######################################
#### Install target configuration ####
######################################

set (INSTALL_LIB_DIR        lib/oonf)
set (INSTALL_PKGCONFIG_DIR  lib/pkgconfig)
set (INSTALL_INCLUDE_DIR    include)
set (INSTALL_CMAKE_DIR      ${DEF_INSTALL_CMAKE_DIR})

####################################
#### RFC 5444 API configuration ####
####################################

# disallow the consumer to drop a tlv context
set (RFC5444_DISALLOW_CONSUMER_CONTEXT_DROP false)

# activate assets() to check state of the pbb writer
# and prevent calling functions at the wrong time
set (RFC5444_WRITER_STATE_MACHINE true)

# activate several unnecessary cleanup operations
# that make debugging the API easier
set (RFC5444_DEBUG_CLEANUP true)

# activate rfc5444 address-block compression
set (RFC5444_DO_ADDR_COMPRESSION true)

# set to true to clear all bits in an address which are not included
# in the subnet mask
# set this to false to make interop tests!
set (RFC5444_CLEAR_ADDRESS_POSTFIX false)
