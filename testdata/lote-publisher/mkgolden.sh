#!/bin/sh
# Regenerates the golden LoTE that eudi/trust/lote/golden_test.go reads: the one
# document the tests did not marshal themselves, and so the only thing that
# catches a JSON tag rename.
#
# The golden material is its OWN pki, not ../certs: re-running mkpki.sh must not
# invalidate a committed signature.
#
# The list is dated from generation time (issue = now, next_update = +30 days), so
# it contains a moment after the signing certificate's notBefore — where the test
# pins its clock. Only that certificate's notAfter bounds the document.
set -e
cd "$(dirname "$0")"
mkdir -p golden/certs
cd golden/certs

# --- the golden signing chain -------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -x509 -new -key root.key -sha256 -days 3650 -out root.crt \
  -subj "/C=NL/O=Yivi Golden/CN=Yivi Golden LoTE Root"

openssl ecparam -name prime256v1 -genkey -noout -out signer.key
openssl req -new -key signer.key -out signer.csr \
  -subj "/C=NL/O=Yivi Golden/CN=Yivi Golden LoTE Signer"
printf 'keyUsage = digitalSignature\nbasicConstraints = critical, CA:FALSE\nsubjectKeyIdentifier = hash\n' > ext.cfg
openssl x509 -req -in signer.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -out signer.crt -days 3650 -sha256 -extfile ext.cfg
openssl x509 -in signer.crt -outform DER -out signer.der

# --- a listed party's certificate, so the entries can key on a real one --------
openssl ecparam -name prime256v1 -genkey -noout -out party.key
openssl req -new -key party.key -out party.csr \
  -subj "/C=NL/O=Example Municipality/CN=verifier.example.com/organizationIdentifier=VATNL-000000001"
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
# Clause 6.3.6 prescribes `CC:name` for the English SchemeName, where CC is the
# SchemeTerritory ("NL" here). Nothing in the wallet enforces the format — it
# compares the identity verbatim against what its source configures — so the golden
# document is where a conformant one is written down.
publish.LIST_ID = "NL:Yivi Golden Trust List"

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

# Every shape the wallet understands in one document: both certificate key forms,
# a DID, service-level overrides, carried-but-ignored markings, multilingual names.
# Three services carry no status — meaning granted, clause 6.6.0 NOTE 1 — and the
# fourth an explicit withdrawal, so both branches are exercised.
#
# Built through publish.py's own helpers, so the golden document and the E2E
# publisher cannot disagree about Annex A.
list_document = {
    "LoTE": {
        # So the window contains a moment after the certificate's notBefore.
        "ListAndSchemeInformation": publish.scheme_information(
            sequence_number=42,
            next_update_seconds=30 * 86400,
            operator="Yivi Golden",
        ),
        "TrustedEntitiesList": [
            publish.entity(
                name={"en": "Example Municipality", "nl": "Example Municipality"},
                organization_identifier="VATNL-000000001",
                logo_uri="https://trustlist.example/logos/municipality.png",
                services=[
                    publish.service(
                        role="Verifier",
                        identity={
                            "X509Certificates": [
                                {"val": base64.b64encode(party_der).decode()}
                            ]
                        },
                        name={"en": "Example Municipality", "nl": "Example Municipality"},
                        markings=["onboarded-by-yivi"],
                    )
                ],
            ),
            publish.entity(
                name={"en": "Example Issuing Ltd"},
                services=[
                    publish.service(
                        role="Issuer",
                        identity={"X509SKIs": [party_ski]},
                        name={"en": "Example Diplomas"},
                        logo_uri="https://trustlist.example/logos/diplomas.png",
                        markings=["some-future-qualifier"],
                    )
                ],
            ),
            publish.entity(
                name={"en": "DID Verifier Ltd"},
                services=[
                    publish.service(
                        role="Verifier",
                        identity={"OtherIds": ["did:web:verifier.example.com"]},
                        name={"en": "DID Verifier Ltd"},
                    )
                ],
            ),
            publish.entity(
                name={"en": "Withdrawn Ltd"},
                services=[
                    publish.service(
                        role="Issuer",
                        identity={"OtherIds": ["did:web:withdrawn.example.com"]},
                        name={"en": "Withdrawn Ltd"},
                        status="Withdrawn",
                    )
                ],
            ),
        ],
    }
}

payload = json.dumps(list_document, separators=(",", ":")).encode()
with open("list.jws", "wb") as f:
    f.write(publish.sign(payload))
# The readable copy; golden_test.go proves it parses to the same List.
with open("list.json", "w") as f:
    json.dump(list_document, f, indent=2, sort_keys=True)
    f.write("\n")
print("wrote golden/list.jws and golden/list.json")
PY
