#!/bin/bash

URI="irma.app"
ISSUER_KEY="../issuer_ec_priv.pem"

set -euo pipefail
mkdir -p certs && cd certs

echo "
[ req ]
default_md = sha256
distinguished_name = req_distinguished_name
prompt = no
req_extensions = v3_req
x509_extensions = v3_ext

[ req_distinguished_name ]
C 	= NL
ST 	= Utrecht
L 	= Utrecht
O 	= Yivi
CN 	= $URI

[ v3_req ]
subjectAltName = @alt_names
basicConstraints = critical,CA:false
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
#TODO: 2.1.123.1 = ASN1:UTF8String:{\"registration\":\"https://portal.dev/organizations/yivi/\",\"organization\":{\"logo\":{\"mimeType\":\"image/png\",\"data\":\"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\"},\"legalName\":{\"en\":\"Yivi B.V.\",\"nl\":\"Yivi B.V.\"}},\"rp\":{\"authorized\":[{\"credential\":\"test.test.email\",\"attributes\":[\"email\"]}],\"purpose\":{\"en\":\"Test purpose\",\"nl\":\"Test purpose\"}}}

[ alt_names ]
URI.1 = https://$URI
URI.2 = http://$URI   # Allow HTTP-only for testing on AllowNonHttpsIssuerUrl exception
DNS.1 = $URI

[ v3_ext ]
subjectKeyIdentifier 	= hash
authorityKeyIdentifier 	= keyid:always,issuer
" > "end-entity.ext"

echo "basicConstraints=CA:true,pathlen:0" > "ca.ext"


echo "Generating Root CA key and self-signed certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out root.key
openssl req -x509 -new -key root.key -sha256 -days 3650 -out root.crt \
  -subj "/C=US/O=My Org Root CA/CN=My Root CA"

echo "Generating Intermediate CA key and CSR..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out intermediate.key
openssl req -new -key intermediate.key -out intermediate.csr \
  -subj "/C=US/O=My Org Intermediate CA/CN=My Intermediate CA"

echo "Signing Intermediate CA with Root CA..."
openssl x509 -req -in intermediate.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -out intermediate.crt -days 1825 -sha256 \
  -extfile ca.ext

openssl req -config end-entity.ext -new -key $ISSUER_KEY -out leaf.csr

echo "Signing Leaf with Intermediate CA..."
openssl x509 -req -in leaf.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial \
  -out leaf.crt -days 825 -sha256 \
  -extfile end-entity.ext \
  -extensions v3_req

echo "Creating chain.pem (leaf → intermediate → root)..."
cat leaf.crt intermediate.crt root.crt > chain.pem

echo "Done. Generated files:"
ls -1 leaf.crt intermediate.crt root.crt chain.pem
