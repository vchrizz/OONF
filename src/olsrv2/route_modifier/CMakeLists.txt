# set library parameters
SET (name route_modifier)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
