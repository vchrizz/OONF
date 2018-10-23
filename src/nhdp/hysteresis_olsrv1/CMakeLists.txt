# set library parameters
SET (name hysteresis_olsrv1)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
