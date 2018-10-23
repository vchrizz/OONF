# set library parameters
SET (name cfg_compact)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
