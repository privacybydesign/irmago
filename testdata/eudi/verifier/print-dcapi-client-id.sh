#!/usr/bin/env bash
# Prints the VERIFIER_ORIGINALCLIENTID that docker-compose.yml must pin for the
# eudi_openid4vp_dcapi service, computed from the current verifier.crt.
#
# That service uses the x509_hash client identifier prefix, so its client id is
# the base64url (unpadded) SHA-256 of the DER-encoded access certificate. The
# verifier refuses to start when the pinned value does not match the keystore's
# certificate, exiting with
#
#   java.lang.IllegalArgumentException: Original Client Id '...' doesn't match the expected value
#
# Run this after gen-cert-chain.sh re-signs verifier.crt, and paste the output
# into docker-compose.yml. Nothing verifies the coupling automatically, and the
# container's failure is a startup crash rather than a test assertion, so a stale
# pin surfaces only as every DC API test failing to reach 127.0.0.1:8091.
set -euo pipefail
cd "$(dirname "$0")"

hash=$(openssl x509 -in verifier.crt -outform der |
	openssl dgst -sha256 -binary |
	base64 |
	tr -d '\n' |
	tr '+/' '-_' |
	tr -d '=')

echo "docker-compose.yml, service eudi_openid4vp_dcapi:"
echo "      - VERIFIER_ORIGINALCLIENTID=${hash}"
