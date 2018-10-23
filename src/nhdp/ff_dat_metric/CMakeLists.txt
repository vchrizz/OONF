# set library parameters
SET (name ff_dat_metric)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
