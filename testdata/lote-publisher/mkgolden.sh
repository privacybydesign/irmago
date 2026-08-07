#!/bin/sh
# Regenerates the golden LoTE: a committed, signed document that
# eudi/trust/lote/golden_test.go verifies and reads.
#
# Why a committed document exists at all: every other test builds its list out of
# the Go structs in model.go, so a change to those structs' JSON tags — renaming
# `next_update`, dropping `other_ids` — passes the whole suite while breaking
# every real list. Only a document the tests did not marshal can catch that. It
# doubles as documentation: golden/list.json is the same list in readable form,
# and the test proves the two agree, so the readable copy cannot drift into a lie.
#
# The golden material is deliberately its OWN pki, not ../certs: re-running
# mkpki.sh must not invalidate a committed signature.
#
# The list's window is dated from generation time (issue = now, next_update =
# +30 days) so that it contains a moment after the signing certificate's
# notBefore. The golden test pins its clock to that certificate's notBefore plus a
# day — inside both windows by construction — so the document never expires out
# from under the suite; only the certificate's own notAfter (10 years) bounds it.
set -e
cd "$(dirname "$0")"
mkdir -p golden/certs
cd golden/certs

# --- the golden signing chain -------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -x509 -new -key root.key -sha256 -days 3650 -out root.crt \
  -subj "/C=NL/O=Yivi Test/CN=Yivi Golden LoTE Root"

openssl ecparam -name prime256v1 -genkey -noout -out signer.key
openssl req -new -key signer.key -out signer.csr \
  -subj "/C=NL/O=Yivi Test/CN=Yivi Golden LoTE Signer"
printf 'keyUsage = digitalSignature\nbasicConstraints = critical, CA:FALSE\nsubjectKeyIdentifier = hash\n' > ext.cfg
openssl x509 -req -in signer.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -out signer.crt -days 3650 -sha256 -extfile ext.cfg
openssl x509 -in signer.crt -outform DER -out signer.der

# --- a listed party's certificate, so the entries can key on a real one --------
openssl ecparam -name prime256v1 -genkey -noout -out party.key
openssl req -new -key party.key -out party.csr \
  -subj "/C=NL/O=Gemeente Voorbeeld/CN=verifier.voorbeeld.example/organizationIdentifier=VATNL-000000001"
openssl x509 -req -in party.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -out party.crt -days 3650 -sha256 -extfile ext.cfg
openssl x509 -in party.crt -outform DER -out party.der

rm signer.csr party.csr ext.cfg root.srl
cd ..

# --- build and sign, reusing the publisher's own signing code ------------------
python3 - <<'PY'
import base64, json, os, sys, time

sys.path.insert(0, "..")
import publish  # noqa: E402  — the real signer, not a reimplementation

# Point it at the golden material rather than the live publisher's.
publish.CERTS = os.path.abspath("certs")
publish.LIST_ID = "urn:yivi:trustlist:golden"

with open("certs/party.der", "rb") as f:
    party_der = f.read()
party_ski = base64.b64encode(
    bytes.fromhex(
        os.popen(
            "openssl x509 -in certs/party.crt -noout -ext subjectKeyIdentifier "
            "| tail -1 | tr -d ' :\\n'"
        ).read().strip()
    )
).decode()

# Every shape the wallet understands, in one document: both certificate key
# forms, a DID, a marking, a withdrawal, service-level overrides, an unknown
# marking that must be carried and ignored, and multilingual names.
list_document = {
    "scheme_information": {
        "list_identifier": "urn:yivi:trustlist:golden",
        "sequence_number": 42,
        # Relative to generation time: the window has to contain a moment after
        # the signing certificate's notBefore for the test's pinned clock to
        # satisfy both.
        "list_issue_date_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "next_update": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 30 * 86400)
        ),
    },
    "entities": [
        {
            "organization_identifier": "VATNL-000000001",
            "name": {"en": "Gemeente Voorbeeld", "nl": "Gemeente Voorbeeld"},
            "logo_uri": "https://trustlist.example/logos/voorbeeld.png",
            "services": [
                {
                    "type": "verifier",
                    "status": "granted",
                    "digital_identity": {
                        "x509_certificate": base64.b64encode(party_der).decode()
                    },
                    "markings": ["onboarded-by-yivi"],
                }
            ],
        },
        {
            "name": {"en": "Voorbeeld Issuing BV"},
            "services": [
                {
                    "type": "issuer",
                    "status": "granted",
                    "digital_identity": {"x509_ski": party_ski},
                    "name": {"en": "Voorbeeld Diplomas"},
                    "logo_uri": "https://trustlist.example/logos/diplomas.png",
                    "markings": ["some-future-qualifier"],
                }
            ],
        },
        {
            "name": {"en": "DID Verifier BV"},
            "services": [
                {
                    "type": "verifier",
                    "status": "granted",
                    "digital_identity": {
                        "other_ids": [
                            {"type": "did", "value": "did:web:verifier.example.com"}
                        ]
                    },
                }
            ],
        },
        {
            "name": {"en": "Withdrawn BV"},
            "services": [
                {
                    "type": "issuer",
                    "status": "withdrawn",
                    "digital_identity": {
                        "other_ids": [
                            {"type": "did", "value": "did:web:withdrawn.example.com"}
                        ]
                    },
                }
            ],
        },
    ],
}

payload = json.dumps(list_document, separators=(",", ":")).encode()
with open("list.jws", "wb") as f:
    f.write(publish.sign(payload))
# The readable copy. golden_test.go proves it parses to the same List as the
# signed payload, so it can never quietly disagree with what is signed.
with open("list.json", "w") as f:
    json.dump(list_document, f, indent=2, sort_keys=True)
    f.write("\n")
print("wrote golden/list.jws and golden/list.json")
PY
