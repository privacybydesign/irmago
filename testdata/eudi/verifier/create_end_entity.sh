#!/usr/bin/env bash
# Generates end-entity.cfg, whose 2.1.123.1 extension carries the relying
# party's scheme data (its authorized attribute sets) into the verifier
# certificate. Run this after editing verifier_scheme_data.json, then run
# gen-cert-chain.sh to sign the certificate.
set -euo pipefail
cd "$(dirname "$0")"

# Compact the scheme data onto one line and escape it as a quoted string, which
# is the form openssl's ASN1:UTF8String value takes.
#
# This was `jq -c | jq -R`, but jq is not present on every machine that needs to
# regenerate this certificate -- a stock Git Bash on Windows has no jq, where the
# script failed on its first line -- and the transformation is small enough to do
# with sed: strip each line's leading indentation, join the lines, then escape
# backslashes and quotes.
#
# Only *leading* whitespace goes: the spaces a pretty-printed JSON file leaves
# after ':' and ',' are legal JSON and harmless inside the config value, while
# stripping whitespace indiscriminately would corrupt string contents and turn
# "Yivi B.V." into "YiviB.V.".
compact_json=$(sed -e 's/^[[:space:]]*//' "verifier_scheme_data.json" | tr -d '\n\r')
escaped_json="\"$(printf '%s' "$compact_json" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')\""

# create cfg file for the certificate signing request
cat > "end-entity.cfg" <<EOF
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
EOF

echo "wrote end-entity.cfg; run ./gen-cert-chain.sh to sign the certificate"

