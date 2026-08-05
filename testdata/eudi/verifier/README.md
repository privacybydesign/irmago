# OpenID4VP verifier test certificate

The relying party certificate the `eudi_openid4vp` / `eudi_openid4vp_jwt` containers
present to the wallet during the OpenID4VP integration tests, plus the CA that signs
it. `verifier.crt` carries the relying party's scheme data — its authorized attribute
sets — in the X.509 extension at OID `2.1.123.1`, which is what
`eudi/scheme`'s query validator checks a DCQL query against.

| File | Used by |
|---|---|
| `keystore.p12` | mounted by both verifier containers (`docker-compose.yml`), alias `verifier_cert`, password `changeit` |
| `verifier.crt`, `ca.crt`, `chain.pem` | the certificate chain the containers serve in the request object's `x5c` header |
| `verifier_scheme_data.json` | the source of the `2.1.123.1` extension, and embedded as `testdata.VerifierCertSchemeData` for the unit tests |
| `ca.crt` | embedded as `testdata.VerifierCACertBytes`, which the test client trusts as a verifier trust anchor |
| `end-entity.cfg` | generated; do not edit by hand |

## Changing what the verifier is authorized to request

Edit `verifier_scheme_data.json`, then regenerate and restart:

```bash
./create_end_entity.sh   # rewrites end-entity.cfg from verifier_scheme_data.json
./gen-cert-chain.sh      # re-signs verifier.crt, chain.pem and keystore.p12
docker restart eudi_openid4vp eudi_openid4vp_jwt
```

The containers read `keystore.p12` at startup, so without the restart the tests keep
seeing the previous authorized set.

A credential identifier in `rp.authorized` is matched either as an exact string (when
it parses as a URL with a scheme, e.g. `urn:eudi:pid:1`) or by dot-separated parts with
`*` wildcard support. Part matching indexes the authorized identifier by the requested
one's position, so an authorized identifier with *fewer* parts than the request never
matches: a five-part mdoc docType such as `eu.europa.ec.av.1` needs either that exact
identifier or a wildcard, and a three-part Yivi-style entry cannot cover it.

Both scripts run on a stock Git Bash, Linux or macOS shell — no `jq` required, and
`gen-cert-chain.sh` disables MSYS path conversion so openssl's `-subj "/C=NL/..."`
survives on Windows.

The private keys here are throwaway test keys, committed on purpose.
