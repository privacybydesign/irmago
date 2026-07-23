# Storage regression snapshot — v1.0.0

Client storage generated at the `v1.0.0` tag, loaded and verified by
`TestClientStorageRegressionV1_0_0`.

> **Do not regenerate or encrypt this snapshot.** v1.0.0/v1.1.0 shipped a bug that
> opened the EUDI database without its AES key, so `eudi_client_db` here is genuinely
> **plaintext** — exactly what those releases wrote to disk. It is the input for the
> plaintext→encrypted migration regression test (fixed in v1.1.1): loading it must
> trigger `sqlcipher.EncryptInPlace` and still read every credential back. The
> born-encrypted steady state is covered separately by the `v1.1.1` snapshot.

## Files

| File | Description |
|------|-------------|
| `bbolt_client_db` | IRMA client bbolt database (idemix credentials, IRMA-issued SD-JWTs, logs). Copied to `db2` on load. |
| `eudi_client_db` | EUDI SQLCipher database (`yivi-eudi.db`): OpenID4VCI credentials. **Intentionally plaintext** (see note above); do not encrypt or regenerate. |
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
- **OpenID4VP disclosures:** `test.test.email` (×2, served from bbolt) plus, via the
  veramo verifier and served from the EUDI DB, `https://localhost:8443/vct/test` (the
  `email` claim) and `https://localhost:8443/vct/organization` (only the
  `university.name` and `university.founded` claims — a subset of the nested tree).
- **Removals** (final actions): `irma-demo.RU.studentCard` + 2 spare `https://localhost:8443/vct/test`.

## Expected database state

- **bbolt** (`bbolt_client_db`): `irma-demo.MijnOverheid.fullName`,
  `irma-demo.MijnOverheid.singleton` and `test.test.email`; the `test.test.email` SD-JWT
  retains 8 of 10 instances (2 consumed by OpenID4VP disclosure); `irma-demo.RU.studentCard` removed.
- **EUDI SQLCipher** (`eudi_client_db`): one `https://localhost:8443/vct/test` and one
  `https://localhost:8443/vct/organization` batch remaining.
- **Activity logs** (merged from both stores): all four types — issuance, disclosure,
  signature, removal — returned newest-first, ending with the three removals.

## Verified by the regression test

`TestClientStorageRegressionV1_0_0` asserts, entirely through `client.Client`'s public
interface (`GetCredentials` / `LoadNewestLogs`):

- each credential's attribute names and values (including every nested attribute of the
  organization credential), and valid PNG logos on the IRMA credential + issuer images;
- EUDI credential metadata (issuer, SD-JWT format, issuance date, not revoked);
- the `test.test.email` SD-JWT instance count (8 of 10);
- log count, types, newest-first ordering, and content — the disclosed attributes and
  values, the signed message, the removed credential ids, and valid images on log
  credentials;
- that the loaded client can still run fresh sessions: IRMA issuance, IRMA disclosure
  (incl. keyshare) and signature, OpenID4VCI issuance, and OpenID4VP disclosure
  (direct-post and veramo).
