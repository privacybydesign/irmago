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

# Clean up intermediate files even on error so a partial failure does not
# leave stray *.csr / ca.srl artefacts in the testdata directory.
trap 'rm -f -- *.csr ca.srl' EXIT

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
# 1.0.18013.5.1.2 is ISO 18013-5 Annex B.1.2's mdoc document-signer usage. It has
# to be here because this same certificate signs the issuer's mso_mdoc MSOs, and
# irmago rejects a document signer that enumerates its extended key usages
# without naming this one. clientAuth stays for the SD-JWT/x5c path.
openssl x509 -req -in issuer.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out issuer.pem -days "$DAYS" -sha256 \
  -extfile <(printf "subjectAltName=%s\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth,1.0.18013.5.1.2\n" "$SAN_ISSUER")
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

# Note: no internal TLS cert/key for the AS — upstream server.py (idpy-oidc
# 0.9.4) has the ssl_context wiring commented out, so the AS always serves
# plain HTTP on :5000 regardless of webserver.server_cert/server_key. Setting
# those config keys to null makes create_context return None and skip the
# file load entirely. nginx reaches the AS over http:// upstream.

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
