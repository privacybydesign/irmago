escaped_json=$(cat "verifier_scheme_data.json" | jq -c | jq -R)

# create cfg file for the certificate signing request
echo "
[ req ]
default_md         = sha256
distinguished_name = req_distinguished_name
prompt             = no
req_extensions     = v3_req
x509_extensions    = v3_ext

[ req_distinguished_name ]
C   = NL
ST  = Utrecht
L   = Utrecht
O   = Yivi
CN  = localhost

[ v3_req ]
subjectAltName   = @alt_names
extendedKeyUsage = clientAuth
keyUsage         = digitalSignature, keyEncipherment
basicConstraints = critical, CA:FALSE
2.1.123.1        = ASN1:UTF8String:$escaped_json

[ alt_names ]
DNS.0 = localhost
URI.0 = http://localhost

[ v3_ext ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
" > "end-entity.cfg"

