# check for polarssl header
INCLUDE (CheckIncludeFiles)
INCLUDE (CheckLibraryExists)

CHECK_INCLUDE_FILES(polarssl/sha1.h HAVE_SHA1_H)
CHECK_INCLUDE_FILES(polarssl/sha256.h HAVE_SHA256_H)
CHECK_INCLUDE_FILES(polarssl/sha512.h HAVE_SHA512_H)

CHECK_LIBRARY_EXISTS(polarssl md_init_ctx "" HAVE_LIBPOLARSSL)
CHECK_LIBRARY_EXISTS(mbedtls md_init_ctx "" HAVE_LIBMBEDTLS)

IF ((HAVE_SHA1_H OR HAVE_SHA256_H OR HAVE_SHA512_H) AND (HAVE_LIBPOLARSSL OR HAVE_LIBMBEDTLS))
    message ("PolarSSL found")
    # set library parameters
    SET (name hash_polarssl)

    # use generic plugin maker
    IF (HAVE_LIBPOLARSSL)
        oonf_create_plugin("${name}" "${name}.c" "${name}.h" "polarssl")
    ELSE()
        oonf_create_plugin("${name}" "${name}.c" "${name}.h" "mbedtls")
    ENDIF()
ELSE()
    message ("PolarSSL not found")
ENDIF()
