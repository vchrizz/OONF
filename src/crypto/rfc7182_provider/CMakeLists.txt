# set library parameters
SET (name rfc7182_provider)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
