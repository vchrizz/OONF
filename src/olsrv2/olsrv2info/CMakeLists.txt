# set library parameters
SET (name olsrv2info)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
