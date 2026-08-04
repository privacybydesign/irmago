#!/usr/bin/env python3
"""A LoTE publisher for the integration tests.

Publishes an ETSI TS 119 602 List of Trusted Entities as a compact JAdES-B-B
document, and lets a test replace what it publishes between requests.

**It signs with the openssl CLI and stdlib base64 on purpose, never with a JWS
library.** The wallet verifies with lestrrat-go/jwx; a publisher using the same
library would test that library against itself and leave untested the thing that
actually breaks when a real backend publishes its first list — how a foreign
toolchain emits the `x5c` chain, orders the protected header, or encodes an
ECDSA signature. Everything about the JWS here is assembled by hand for that
reason. See docs/plans/lote-e2e-tests.md.

Routes:

  GET  /                  the current signed list
  GET  /logo.png          a curated logo, for the display scenario
  POST /admin/publish     {entities, sequence_number, next_update_seconds}
  POST /admin/dark        answer 503 until the next publish

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


def build(entities, sequence_number, next_update_seconds):
    now = time.time()

    def stamp(t):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))

    return json.dumps(
        {
            "scheme_information": {
                "list_identifier": LIST_ID,
                "sequence_number": sequence_number,
                "list_issue_date_time": stamp(now),
                "next_update": stamp(now + next_update_seconds),
            },
            "entities": entities,
        },
        separators=(",", ":"),
    ).encode()


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
                        body.get("entities", []),
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
