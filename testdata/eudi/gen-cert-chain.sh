#!/bin/bash

URI="irma.app"
ISSUER_KEY="../issuer_ec_priv.pem"

set -euo pipefail
mkdir -p certs && cd certs

echo "
basicConstraints = critical,CA:false
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = 1.3.130.2.0.0.1.7
subjectAltName = @alt_names

[alt_names]
URI.1 = https://$URI
DNS.1 = $URI
" > "end-entity.ext"

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
  -extfile <(echo "basicConstraints=CA:true,pathlen:0") \

openssl req -new -key $ISSUER_KEY -out leaf.csr \
  -subj "/C=US/O=My Org/CN=leaf.example.com"

echo "Signing Leaf with Intermediate CA..."
openssl x509 -req -in leaf.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial \
  -out leaf.crt -days 825 -sha256 \
  -extfile end-entity.ext \

echo "Creating chain.pem (leaf → intermediate → root)..."
cat leaf.crt intermediate.crt root.crt > chain.pem

echo "Done. Generated files:"
ls -1 leaf.crt intermediate.crt root.crt chain.pem
