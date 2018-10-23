# set library parameters
SET (name rfc5444_signature)

# use generic plugin maker
oonf_create_plugin("${name}" "${name}.c" "${name}.h" "")
