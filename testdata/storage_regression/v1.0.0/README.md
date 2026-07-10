# Storage regression snapshot — v1.0.0

Client storage generated at the `v1.0.0` tag, loaded and verified by
`TestClientStorageRegression`. Regenerate with
`TestGenerateClientStorageForRegressionTests` (`GENERATE_STORAGE=1`).

## Files

| File | Description |
|------|-------------|
| `bbolt_client_db` | IRMA client bbolt database (idemix credentials, IRMA-issued SD-JWTs, logs). Copied to `db2` on load. |
| `eudi_client_db` | EUDI SQLCipher database (`yivi-eudi.db`): OpenID4VCI credentials. |
| `ecdsa_sk.pem` | Client signer key. |
| `keyshare_users.json` | Keyshare users preloaded into the test keyshare server. |
| `metadata.json` | Human-readable dump of the stored credentials and logs. |

## Sessions performed

- **IRMA issuance:** `irma-demo.MijnOverheid.fullName` (idemix), `test.test.email`
  (idemix + 10 SD-JWTs), `irma-demo.MijnOverheid.singleton`, `irma-demo.RU.studentCard`.
- **OpenID4VCI issuance:** 3× `TestCredentialSdJwt` (vct `https://localhost:8443/vct/test`)
  and 1× `OrganizationCredentialSdJwt` (vct `https://localhost:8443/vct/organization`, deeply nested).
- **IRMA disclosures:** `test.test.email`; `irma-demo.MijnOverheid.fullName` (×2); and one spanning
  `irma-demo.MijnOverheid.fullName` + `irma-demo.MijnOverheid.singleton` + `irma-demo.RU.studentCard`.
- **IRMA signature.**
- **OpenID4VP disclosures:** `test.test.email` (×2, served from bbolt) plus
  `https://localhost:8443/vct/test` and `https://localhost:8443/vct/organization`
  (served from the EUDI DB, via the veramo verifier).
- **Removals** (final actions): `irma-demo.RU.studentCard` + 2 spare `https://localhost:8443/vct/test`.

## Expected database state

- **bbolt** (`bbolt_client_db`): `irma-demo.MijnOverheid.fullName`,
  `irma-demo.MijnOverheid.singleton` and `test.test.email`; the `test.test.email` SD-JWT
  retains 8 of 10 instances (2 consumed by OpenID4VP disclosure); `irma-demo.RU.studentCard` removed.
- **EUDI SQLCipher** (`eudi_client_db`): one `https://localhost:8443/vct/test` and one
  `https://localhost:8443/vct/organization` batch remaining.
- **Activity logs** (merged from both stores): all four types — issuance, disclosure,
  signature, removal — returned newest-first, ending with the three removals.
