#!/bin/sh
# Regenerates the test wallet provider's attestation PKI: a root CA and the
# signing key walletprovider/fake signs wallet instance and key attestations
# with in the EUDI Python issuer tests (internal/sessiontest). The Python AS
# trusts signer.pem (see ../trusted-attesters): it checks a WIA's signature
# against the keys of the certificates it trusts, not against a chain.
# Test material only.
set -e
cd "$(dirname "$0")"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/O=Yivi/CN=Test wallet provider root" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
openssl ecparam -name prime256v1 -genkey -noout -out signer.key
openssl req -new -key signer.key -subj "/O=Yivi/CN=Test wallet provider attestations" -out signer.csr
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n" > signer.ext
openssl x509 -req -in signer.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days 3650 -extfile signer.ext -out signer.pem
rm -f signer.csr signer.ext ca.srl
mkdir -p ../trusted-attesters
cp signer.pem ../trusted-attesters/signer.pem
