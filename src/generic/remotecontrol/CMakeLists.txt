# set library parameters
SET (name remotecontrol)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
