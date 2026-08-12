#!/usr/bin/env python3
"""A LoTE publisher for the integration tests.

Publishes an ETSI TS 119 602 scheme-explicit List of Trusted Entities in the
**Annex A JSON binding**, signed as a compact JAdES-B-B document, and lets a test
replace what it publishes between requests.

**It signs with the openssl CLI and stdlib base64 on purpose, never with a JWS
library.** The wallet verifies with lestrrat-go/jwx; a publisher using the same
library would test that library against itself and leave untested the thing that
actually breaks when a real backend publishes its first list — how a foreign
toolchain emits the `x5c` chain, orders the protected header, or encodes an
ECDSA signature. Everything about the JWS here is assembled by hand for that
reason. See docs/plans/lote-e2e-tests.md.

The *document* is likewise built by hand here rather than by the Go serialiser,
so a change to model.go's JSON tags shows up as an integration failure instead of
agreeing with itself. Note this is the last such independent check: the
production publisher (`yivi eudi lote`) shares the wallet's structs, so CI
validates its output against the ETSI JSON Schema and DSS instead. See
docs/plans/lote-annex-a-publisher.md.

Routes:

  GET  /                  the current signed list
  GET  /logo.png          a curated logo, for the display scenario
  POST /admin/publish     {entities, sequence_number, next_update_seconds}
  POST /admin/dark        answer 503 until the next publish

The `entities` are the compact form `expand_entity` takes, not Annex A — see its
docstring for why.

There is deliberately no fetch-count route: the suite's observability is
wallet-side only, so a count could only be a debugging aid, and one that invites
assertions the tests do not make. There is deliberately no tamper route either —
an invalid document is invalid whoever signed it, so tamper coverage stays with
the in-process list server.

`next_update_seconds` may be negative. That is not a curiosity: the wallet treats
a list as current while `now - ClockSkew < next_update`, so backdating to just
inside that window is how a test gets a *held* list to expire in seconds instead
of waiting out the three-minute skew.
"""

import base64
import json
import os
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CERTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
LIST_ID = os.environ.get("LOTE_LIST_ID", "urn:yivi:trustlist:sessiontest")
PORT = int(os.environ.get("LOTE_PORT", sys.argv[1] if len(sys.argv) > 1 else 9800))

# A 1x1 red PNG. Small on purpose: the display scenario asserts that the bytes
# the wallet cached are the bytes served, not that they render nicely.
LOGO_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8AAAwAB/AF/pV1cAAAAAElFTkSuQmCC"
)


def b64url(raw):
    """base64url without padding, as JWS requires."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def der_sig_to_raw(der):
    """ECDSA DER SEQUENCE{INTEGER r, INTEGER s} -> raw r||s, 32 bytes each.

    openssl emits DER; JWS ES256 wants the raw concatenation. Doing this by hand
    is the point of this publisher, not an accident of it: it is one of the two
    places a foreign signer diverges from a JWS library (the other being `x5c`
    below, which is standard base64 rather than base64url).
    """
    if der[0] != 0x30:
        raise ValueError("signature is not a DER sequence")
    i = 2 if der[1] < 0x80 else 3  # short-form length suffices for P-256
    out = b""
    for _ in range(2):
        if der[i] != 0x02:
            raise ValueError("expected a DER INTEGER")
        length = der[i + 1]
        # DER strips leading zeros and may add one to keep the integer positive;
        # JWS wants a fixed 32-byte field either way.
        value = der[i + 2 : i + 2 + length].lstrip(b"\x00")
        out += value.rjust(32, b"\x00")
        i += 2 + length
    return out


def sign(payload):
    with open(os.path.join(CERTS, "signer.der"), "rb") as f:
        leaf_der = f.read()

    header = {
        "typ": "tl+jwt",  # lote.LoteTyp: what says this JWS is a trusted list
        "alg": "ES256",
        "x5c": [base64.b64encode(leaf_der).decode()],  # RFC 7515: standard base64
    }
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + b64url(payload)
    ).encode()

    der = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", os.path.join(CERTS, "signer.key")],
        input=signing_input,
        capture_output=True,
        check=True,
    ).stdout
    return signing_input + b"." + b64url(der_sig_to_raw(der)).encode()


def stamp(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def scheme_information(sequence_number, next_update_seconds, operator="Yivi Test"):
    """The scheme-explicit mandatory fields (TS 119 602 Table 1).

    All twelve are required once the scheme information is explicit, and Annex A
    binds only the explicit form — there is no standard JSON binding for a
    scheme-implicit LoTE to fall back on. LIST_ID becomes the English SchemeName,
    which is the identity the wallet pins.
    """
    now = time.time()
    return {
        "LoTEVersionIdentifier": 1,
        "LoTESequenceNumber": sequence_number,
        "LoTEType": "https://yivi.app/19602/LoTEType/YiviRecognizedPartiesList",
        "SchemeOperatorName": [{"lang": "en", "value": operator}],
        "SchemeOperatorAddress": {
            "SchemeOperatorPostalAddress": [
                {
                    "lang": "en",
                    "StreetAddress": "Testlaan 1",
                    "Locality": "Utrecht",
                    "PostalCode": "3512 AA",
                    "Country": "NL",
                }
            ],
            "SchemeOperatorElectronicAddress": [
                {"lang": "en", "uriValue": "mailto:trustlist@yivi.test"}
            ],
        },
        "SchemeName": [{"lang": "en", "value": LIST_ID}],
        "SchemeInformationURI": [
            {"lang": "en", "uriValue": "https://yivi.test/trustlist"}
        ],
        "StatusDeterminationApproach": (
            "https://yivi.app/19602/YiviRecognizedPartiesList/StatusDetn/Yivi"
        ),
        "SchemeTypeCommunityRules": [
            {
                "lang": "en",
                "uriValue": "https://yivi.app/19602/YiviRecognizedParties/schemerules/Yivi",
            }
        ],
        "SchemeTerritory": "NL",
        "PolicyOrLegalNotice": [
            {
                "LoTEPolicy": {
                    "lang": "en",
                    "uriValue": "https://yivi.test/trustlist/policy",
                }
            }
        ],
        "ListIssueDateTime": stamp(now),
        "NextUpdate": stamp(now + next_update_seconds),
    }


def build(entities, sequence_number, next_update_seconds):
    """An Annex A document: the list wrapped in a single `LoTE` member."""
    return json.dumps(
        {
            "LoTE": {
                "ListAndSchemeInformation": scheme_information(
                    sequence_number, next_update_seconds
                ),
                "TrustedEntitiesList": entities,
            }
        },
        separators=(",", ":"),
    ).encode()


def entity(name, services, organization_identifier=None, logo_uri=None):
    """One TrustedEntity, with the mandatory TEAddress and TEInformationURI.

    Clause 6.5.0 makes both mandatory, and TEAddress mandatory in both halves —
    a postal *and* an electronic address. The wallet reads neither; they are the
    price of the binding, and the reason listing a party is more expensive to
    curate than it was.

    Yivi's organization identifier and logo have no Annex A field and go into
    TEInformationExtensions.
    """
    extensions = []
    if organization_identifier:
        extensions.append({"YiviOrganizationIdentifier": organization_identifier})
    if logo_uri:
        extensions.append({"YiviLogoURI": logo_uri})

    information = {
        "TEName": [{"lang": lang, "value": value} for lang, value in sorted(name.items())],
        "TEAddress": {
            "TEPostalAddress": [
                {
                    "lang": "en",
                    "StreetAddress": "Voorbeeldweg 1",
                    "Locality": "Utrecht",
                    "PostalCode": "3512 AA",
                    "Country": "NL",
                }
            ],
            "TEElectronicAddress": [
                {"lang": "en", "uriValue": "mailto:info@voorbeeld.test"}
            ],
        },
        "TEInformationURI": [
            {"lang": "en", "uriValue": "https://voorbeeld.test/about"}
        ],
    }
    if extensions:
        information["TEInformationExtensions"] = extensions

    return {"TrustedEntityInformation": information, "TrustedEntityServices": services}


def service(role, identity, name, status="Granted", logo_uri=None, markings=()):
    """One TrustedEntityService.

    ServiceName is mandatory (clause 6.6.0), so a service not presented under its
    own brand repeats the entity's name rather than being left unnamed.

    ServiceTypeIdentifier and ServiceStatus are *optional* in the schema but
    always emitted: clause 6.6.0's notes give their absence the meaning "all
    services share one type / one status", which is wrong for a list carrying
    both roles and visible withdrawals.
    """
    extensions = []
    if logo_uri:
        extensions.append({"YiviLogoURI": logo_uri})
    extensions.extend({"YiviMarking": marking} for marking in markings)

    information = {
        "ServiceName": [
            {"lang": lang, "value": value} for lang, value in sorted(name.items())
        ],
        "ServiceDigitalIdentity": identity,
        "ServiceTypeIdentifier": f"https://yivi.app/19602/Svctype/{role}",
        "ServiceStatus": f"https://yivi.app/19602/Svcstatus/{status}",
    }
    if extensions:
        information["ServiceInformationExtensions"] = extensions

    return {"ServiceInformation": information}


def expand_entity(spec):
    """Expand the admin API's compact entity form into an Annex A TrustedEntity.

    The admin API deliberately does *not* take Annex A directly. It is a
    test-only interface, so its shape is ours to choose, and keeping it compact
    means the Annex A structure lives in exactly one place — here — rather than
    being spelled out again in Go test fixtures that would then have to be kept
    in step with it.

    A service that names itself keeps its own name; one that does not inherits
    the entity's, because ServiceName is mandatory and something has to fill it.
    """
    services = []
    for svc in spec.get("services", []):
        identity = {}
        if svc.get("did"):
            identity["OtherIds"] = [svc["did"]]
        if svc.get("ski"):
            identity["X509SKIs"] = [svc["ski"]]
        if svc.get("certificate"):
            identity["X509Certificates"] = [{"val": svc["certificate"]}]

        services.append(
            service(
                role=svc.get("role", "Issuer"),
                identity=identity,
                name={"en": svc.get("name") or spec["name"]},
                status=svc.get("status", "Granted"),
                logo_uri=svc.get("logo_uri"),
                markings=svc.get("markings") or (),
            )
        )

    return entity(
        name={"en": spec["name"]},
        services=services,
        organization_identifier=spec.get("organization_identifier"),
        logo_uri=spec.get("logo_uri"),
    )


class State:
    def __init__(self):
        # An empty list until a test publishes one, so a wallet that refreshes
        # before any test has spoken gets a valid document granting nobody.
        self.document = sign(build([], 1, 86400))
        self.dark = False


STATE = State()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # the test output is noisy enough

    def _send(self, code, body=b"", ctype="application/jose"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/logo.png"):
            return self._send(200, LOGO_PNG, "image/png")
        if STATE.dark:
            return self._send(503, b"dark", "text/plain")
        return self._send(200, STATE.document)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError as err:
            return self._send(400, str(err).encode(), "text/plain")

        if self.path.startswith("/admin/dark"):
            STATE.dark = True
            return self._send(200, b"dark", "text/plain")

        if self.path.startswith("/admin/publish"):
            try:
                STATE.document = sign(
                    build(
                        [expand_entity(spec) for spec in body.get("entities", [])],
                        body.get("sequence_number", 1),
                        body.get("next_update_seconds", 86400),
                    )
                )
            except (subprocess.CalledProcessError, ValueError) as err:
                return self._send(500, str(err).encode(), "text/plain")
            STATE.dark = False
            return self._send(200, b"published", "text/plain")

        return self._send(404, b"no such admin route", "text/plain")


if __name__ == "__main__":
    print(f"lote publisher on :{PORT}, list {LIST_ID}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
