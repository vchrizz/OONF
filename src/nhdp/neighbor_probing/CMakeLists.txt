# set library parameters
SET (name neighbor_probing)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
