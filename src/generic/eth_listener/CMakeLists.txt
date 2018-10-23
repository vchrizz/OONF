# set library parameters
SET (name eth_listener)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
