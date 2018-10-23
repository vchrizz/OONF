# set library parameters
SET (source  olsrv2_lan.c)
SET (include olsrv2_lan.h)

# use generic plugin maker
oonf_create_plugin("olsrv2_lan" "${source}" "${include}" "")
