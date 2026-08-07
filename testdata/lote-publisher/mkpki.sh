#!/bin/sh
# Regenerates the LoTE publisher's signing material.
#
# A self-signed root plus a signing leaf under it. The wallet anchors the root
# and requires the leaf to carry digitalSignature (eudi_jwt.VerifyCertificate
# asserts it explicitly), so both are pinned here rather than left to defaults.
#
# Both certificates get 3650 days. The leaf deliberately does NOT get the 825
# days a TLS end-entity certificate would: this is committed test material, and a
# two-year fuse means the suite fails on a Tuesday for reasons nobody remembers.
#
# The chain is two deep on purpose. eudi_jwt.VerifyCertificate builds paths from
# the anchors the wallet has installed and does not use intermediates from the
# `x5c` header, so a deeper chain would need its intermediates installed too.
set -e
cd "$(dirname "$0")"
mkdir -p certs && cd certs

openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -x509 -new -key root.key -sha256 -days 3650 -out root.crt \
  -subj "/C=NL/O=Yivi Test/CN=Yivi Test LoTE Root"

openssl ecparam -name prime256v1 -genkey -noout -out signer.key
openssl req -new -key signer.key -out signer.csr \
  -subj "/C=NL/O=Yivi Test/CN=Yivi Test LoTE Signer"

printf 'keyUsage = digitalSignature\nbasicConstraints = critical, CA:FALSE\nsubjectKeyIdentifier = hash\n' > ext.cfg
openssl x509 -req -in signer.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -out signer.crt -days 3650 -sha256 -extfile ext.cfg

# The publisher embeds the DER in the JWS `x5c` header.
openssl x509 -in signer.crt -outform DER -out signer.der

rm signer.csr ext.cfg root.srl
echo "regenerated:"
openssl x509 -in signer.crt -noout -subject -issuer -dates
