#!/usr/bin/env bash
# Generates the test PKI material used by the EUDI Python PID issuer
# and the EUDI Kotlin verifier integration tests.
#
# Outputs:
#   ca.pem           - test root CA cert (PEM, self-signed)
#   ca.key           - test root CA private key
#   issuer.pem       - PID issuer leaf cert (PEM, signed by ca)
#   issuer.der       - same cert in DER (Python issuer wants both)
#   issuer.key       - PID issuer private key (PKCS#8 PEM)
#   verifier.pem     - Kotlin verifier access cert (PEM, signed by ca)
#   verifier.key     - Kotlin verifier access private key
#
# The CA cert is the trust anchor passed to the irmago client at test time.
# Re-run this script only when the certs need to be regenerated; the outputs
# are checked into the repo.

set -euo pipefail

cd "$(dirname "$0")"

DAYS=3650
SAN_ISSUER="DNS:eudi-pid-issuer-py.localhost,DNS:localhost,DNS:tls-proxy.localhost"
SAN_VERIFIER="DNS:eudi-kotlin-verifier.localhost,DNS:localhost,DNS:tls-proxy.localhost"

# Root CA
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
  -subj "/CN=Yivi Test EUDI Root CA" \
  -out ca.pem

# PID issuer leaf
openssl ecparam -name prime256v1 -genkey -noout -out issuer.key
openssl req -new -key issuer.key \
  -subj "/CN=Yivi Test PID Issuer/C=NL" \
  -out issuer.csr
openssl x509 -req -in issuer.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out issuer.pem -days "$DAYS" -sha256 \
  -extfile <(printf "subjectAltName=%s\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n" "$SAN_ISSUER")
openssl x509 -in issuer.pem -outform der -out issuer.der
rm -f issuer.csr ca.srl

# Verifier access cert
openssl ecparam -name prime256v1 -genkey -noout -out verifier.key
openssl req -new -key verifier.key \
  -subj "/CN=Yivi Test EUDI Verifier/C=NL" \
  -out verifier.csr
openssl x509 -req -in verifier.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out verifier.pem -days "$DAYS" -sha256 \
  -extfile <(printf "subjectAltName=%s\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n" "$SAN_VERIFIER")
rm -f verifier.csr ca.srl

# Internal TLS cert/key for the AS's bundled webserver (server_cert/server_key
# in idpy-oidc). Not externally exposed — requests reach the AS via the nginx
# tls_proxy upstream over plain HTTP, but the AS startup code requires the
# files to be present.
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" \
  -keyout as_internal.key -out as_internal.pem \
  -subj "/CN=eudi-as-internal" \
  -addext "subjectAltName=DNS:localhost"

# RSA private key for the issuer's nonce-signing endpoint (config: keys.nonce_path).
openssl genrsa -out nonce_rsa2048.pem 2048

# EC P-256 private key for credential-request encryption (config: keys.credential_request_path).
# The issuer derives a JWK from this key and embeds it in metadata.
openssl ecparam -name prime256v1 -genkey -noout -out credential_request.pem

# Metadata signing key + cert for the Python issuer frontend
# (frontend.frontends_config[*].metadata_signing_key_path/_certificate_path).
openssl ecparam -name prime256v1 -genkey -noout -out metadata_signing.key
openssl req -new -key metadata_signing.key \
  -subj "/CN=Yivi Test Metadata Signing/C=NL" \
  -out metadata_signing.csr
openssl x509 -req -in metadata_signing.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out metadata_signing.pem -days "$DAYS" -sha256
rm -f metadata_signing.csr ca.srl

# Combined chain file the irmago test harness expects as `issuerChain`
cat issuer.pem ca.pem > issuer-chain.pem

echo "Generated:"
ls -1 *.pem *.der *.key
