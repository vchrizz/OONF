# set library parameters
SET (name layer2_import)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
