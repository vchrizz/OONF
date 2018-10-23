# set library parameters
SET (source  olsrv2.c
             olsrv2_lan.c
             olsrv2_originator.c
             olsrv2_reader.c
             olsrv2_routing.c
             olsrv2_tc.c
             olsrv2_writer.c)
SET (include olsrv2.h
             olsrv2_lan.h
             olsrv2_originator.h
             olsrv2_reader.h
             olsrv2_routing.h
             olsrv2_tc.h
             olsrv2_writer.h)

# use generic plugin maker
oonf_create_plugin("olsrv2" "${source}" "${include}" "")
