# set library parameters
SET (name sharedkey_sig)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
