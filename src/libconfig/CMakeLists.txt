SET(OONF_CONFIG_SRCS cfg_cmd.c
                      cfg_db.c
                      cfg_help.c
                      cfg_io.c
                      cfg_schema.c
                      cfg_tobin.c
                      cfg_validate.c
                      cfg.c)

SET(OONF_CONFIG_INCLUDES cfg_cmd.h
                         cfg_db.h
                         cfg_help.h
                         cfg_io.h
                         cfg_schema.h
                         cfg_tobin.h
                         cfg_validate.h
                         cfg.h)

oonf_create_library("libconfig" "${OONF_CONFIG_SRCS}" "${OONF_CONFIG_INCLUDES}" "oonf_libcommon" "")
