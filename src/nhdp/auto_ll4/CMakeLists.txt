# set library parameters
SET (name auto_ll4)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
