# set library parameters
SET (name constant_metric)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
