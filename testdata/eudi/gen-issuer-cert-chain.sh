#!/bin/bash

URI="irma.app"
ISSUER_KEY="../issuer_ec_priv.pem"

set -euo pipefail
mkdir -p certs_issuer && cd certs_issuer

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
2.1.123.1 = ASN1:UTF8String:{\\\"registration\\\":\\\"https://portal.dev/organizations/yivi/\\\",\\\"organization\\\":{\\\"legalName\\\":{\\\"en\\\":\\\"Yivi B.V.\\\",\\\"nl\\\":\\\"Yivi B.V.\\\"}},\\\"ap\\\":{\\\"authorized\\\":[{\\\"credential\\\":\\\"test.test.email\\\",\\\"attributes\\\":[\\\"email\\\", \\\"domain\\\"]}]}}

[ alt_names ]
URI.1 = https://$URI
DNS.1 = $URI

[ v3_ext ]
subjectKeyIdentifier 	= hash
authorityKeyIdentifier 	= keyid:always,issuer
" > "end-entity.ext"

echo "basicConstraints=CA:true,pathlen:0" > "ca.ext"


echo "Generating Root CA key and self-signed certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out root.key
openssl req -x509 -new -key root.key -sha256 -days 3650 -out root.crt \
  -subj "/C=US/O=My Org Root CA/CN=My Issuer Root CA"

echo "Generating Intermediate CA key and CSR..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out intermediate.key
openssl req -new -key intermediate.key -out intermediate.csr \
  -subj "/C=US/O=My Org Intermediate CA/CN=My Issuer Intermediate CA"

echo "Signing Intermediate CA with Root CA..."
openssl x509 -req -in intermediate.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -out intermediate.crt -days 1825 -sha256 \
  -extfile ca.ext

openssl req -extensions v3_req -config end-entity.ext -new -key $ISSUER_KEY -out leaf.csr

echo "Signing Leaf with Intermediate CA..."
openssl x509 -req -in leaf.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial \
  -out leaf.crt -days 825 -sha256 \
  -extfile end-entity.ext \
  -extensions v3_req

echo "Creating chain.pem (leaf → intermediate → root)..."
cat leaf.crt intermediate.crt root.crt > chain.pem

echo "Done. Generated files:"
ls -1 leaf.crt intermediate.crt root.crt chain.pem
