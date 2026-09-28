# OpenID4VP verifier test certificate

The relying party certificate the `eudi_openid4vp` / `eudi_openid4vp_jwt` /
`eudi_openid4vp_dcapi` containers present to the wallet during the OpenID4VP
integration tests, plus the CA that signs it. `verifier.crt` carries the relying
party's scheme data — its authorized attribute sets — in the X.509 extension at OID
`2.1.123.1`, which is what `eudi/scheme`'s query validator checks a DCQL query
against.

| File | Used by |
|---|---|
| `keystore.p12` | mounted by all three verifier containers (`docker-compose.yml`), alias `verifier_cert`, password `changeit` |
| `verifier.crt`, `ca.crt`, `chain.pem` | the certificate chain the containers serve in the request object's `x5c` header |
| `verifier_scheme_data.json` | the source of the `2.1.123.1` extension, and embedded as `testdata.VerifierCertSchemeData` for the unit tests |
| `ca.crt` | embedded as `testdata.VerifierCACertBytes`, which the test client trusts as a verifier trust anchor |
| `end-entity.cfg` | generated; do not edit by hand |

## Changing what the verifier is authorized to request

Edit `verifier_scheme_data.json`, then regenerate and restart:

```bash
./create_end_entity.sh   # rewrites end-entity.cfg from verifier_scheme_data.json
./gen-cert-chain.sh      # re-signs verifier.crt, chain.pem and keystore.p12
./print-dcapi-client-id.sh   # prints the new VERIFIER_ORIGINALCLIENTID for docker-compose.yml
docker restart eudi_openid4vp eudi_openid4vp_jwt eudi_openid4vp_dcapi
```

The containers read `keystore.p12` at startup, so without the restart the tests keep
seeing the previous authorized set.

A credential identifier in `rp.authorized` is matched either as an exact string (when
it parses as a URL with a scheme, e.g. `urn:eudi:pid:1`) or by dot-separated parts with
`*` wildcard support. Part matching indexes the authorized identifier by the requested
one's position, so an authorized identifier with *fewer* parts than the request never
matches: a five-part mdoc docType such as `eu.europa.ec.av.1` needs either that exact
identifier or a wildcard, and a three-part Yivi-style entry cannot cover it.

## Re-signing invalidates the DC API verifier's pinned client id

`eudi_openid4vp_dcapi` uses the `x509_hash` client identifier prefix, so its client id
*is* the base64url (unpadded) SHA-256 of the DER-encoded access certificate. It is
pinned in `docker-compose.yml` as `VERIFIER_ORIGINALCLIENTID`, and the verifier
**refuses to start** when the pin does not match the certificate in the keystore:

```
java.lang.IllegalArgumentException: Original Client Id '<pinned>' doesn't match the expected value
```

The container then sits at `Exited (1)`, `depends_on: condition: service_started` does
not catch it, and every DC API test fails against `127.0.0.1:8091` — which is how this
was missed once already, in a merge where one side added the service and the other
re-signed the certificate, with no textual conflict between them.

So after `gen-cert-chain.sh`, recompute the value and paste it into
`docker-compose.yml`:

```bash
./print-dcapi-client-id.sh
```

or, equivalently, by hand:

```bash
openssl x509 -in verifier.crt -outform der |
  openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='
```

To check a running container agrees, create a session and read the `client_id` back —
it must carry the same hash:

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"nonce":"nonce","origin":"https://verifier.example.com","intended_use_id":"1",
       "dcql_query":{"credentials":[{"id":"email_credential","format":"dc+sd-jwt",
       "meta":{"vct_values":["test.test.email"]},"claims":[{"path":["email"]}]}]}}' \
  http://127.0.0.1:8091/ui/presentations
```

All three scripts run on a stock Git Bash, Linux or macOS shell — no `jq` required, and
`gen-cert-chain.sh` disables MSYS path conversion so openssl's `-subj "/C=NL/..."`
survives on Windows.

The private keys here are throwaway test keys, committed on purpose.
