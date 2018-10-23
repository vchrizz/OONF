# set library parameters
SET (source  nhdp.c
             nhdp_db.c
             nhdp_domain.c
             nhdp_hysteresis.c
             nhdp_interfaces.c
             nhdp_reader.c
             nhdp_writer.c)
SET (include nhdp.h
             nhdp_db.h
             nhdp_domain.h
             nhdp_hysteresis.h
             nhdp_interfaces.h
             nhdp_reader.h
             nhdp_writer.h)


# use generic plugin maker
oonf_create_plugin("nhdp" "${source}" "${include}" "")
