# set library parameters
SET (name nhdpcheck)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
