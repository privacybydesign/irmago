#!/bin/sh
# Regenerates the golden anchor list that eudi/trust/lote/golden_anchors_test.go
# reads: a signed anchor list this package did not marshal itself, and so the one
# thing that catches a rename of the members only an anchor list carries.
#
# Unlike mkgolden.sh it goes through the publisher CLI end to end — keygen, build,
# sign — because the CLI is what an anchor list is built with, and its gates are
# part of what the golden document proves survivable. The chain is throwaway and
# its own: re-running mkgolden.sh must not invalidate this signature or the other
# way round.
#
# The list is dated from generation time (issue = now, next_update = +180 days),
# so it contains a moment after the signing certificate's notBefore — where the
# test pins its clock. Only that certificate's notAfter bounds the document.
set -e
cd "$(dirname "$0")"
repo="$(cd ../.. && pwd)"
yivi="${YIVI:-go run "$repo/yivi"}"

rm -rf golden-anchors
mkdir -p golden-anchors/certs

$yivi eudi lote keygen --out-dir golden-anchors/certs --country NL --organization "Yivi Example" --days 3650
$yivi eudi lote build "$repo/testdata/lote-source-anchors" --sequence-number 1 \
  --issued-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --offline -o golden-anchors/list.json
$yivi eudi lote sign golden-anchors/list.json --key golden-anchors/certs/signer.key \
  --cert golden-anchors/certs/signer.crt --anchor golden-anchors/certs/ca.crt -o golden-anchors/list.jws

ski="$(openssl x509 -in golden-anchors/certs/signer.crt -noout -ext subjectKeyIdentifier | tail -1 | tr -d ' ')"
$yivi eudi lote verify golden-anchors/list.jws --anchor golden-anchors/certs/ca.crt --signer-ski "$ski"
