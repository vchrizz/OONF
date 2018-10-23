# set library parameters
SET (name layer2info)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
