# set library parameters
SET (source  old_lan.c)
SET (include old_lan.h)

# use generic plugin maker
oonf_create_plugin("olsrv2_old_lan" "${source}" "${include}" "")
