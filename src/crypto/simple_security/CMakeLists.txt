# set library parameters
SET (name simple_security)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
