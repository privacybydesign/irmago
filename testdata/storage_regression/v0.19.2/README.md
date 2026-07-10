# Storage regression snapshot — v0.19.2

Client storage generated at the `v0.19.2` tag, loaded and verified by
`TestClientStorageRegression`. This snapshot predates the EUDI SQLCipher
storage, so it contains only the IRMA client (bbolt) database.

## Files

| File | Description |
|------|-------------|
| `bbolt_client_db` | IRMA client bbolt database (idemix credentials, IRMA-issued SD-JWTs, logs). Copied to `db2` on load. |
| `ecdsa_sk.pem` | Client signer key. |
| `keyshare_users.json` | Keyshare users preloaded into the test keyshare server. |
| `metadata.json` | Human-readable dump of the stored credentials and logs. |

There is no `eudi_client_db`: OpenID4VCI / EUDI credentials did not exist yet at
this version.

## Sessions performed

- **IRMA issuance:** `irma-demo.MijnOverheid.fullName` (idemix), `test.test.email`
  (idemix + 10 SD-JWTs), `irma-demo.MijnOverheid.singleton` (plus `test.test.mijnirma`
  from keyshare enrollment).
- **IRMA disclosure:** `test.test.email`.
- **IRMA signature.**
- **OpenID4VP disclosures:** `test.test.email` (×2), served from bbolt.

No credentials are removed, so there are no removal logs.

## Expected database state

- **bbolt** (`bbolt_client_db`): `irma-demo.MijnOverheid.fullName`,
  `irma-demo.MijnOverheid.singleton` and `test.test.email` (idemix + SD-JWT), plus the
  internal `test.test.mijnirma` keyshare-enrollment credential (stored, but not surfaced
  by `GetCredentials`). The `test.test.email` SD-JWT credential retains 8 of 10 instances
  (2 consumed by OpenID4VP disclosure).
- **Activity logs** (8 entries): 4 issuance, 1 IRMA disclosure, 1 signature and
  2 OpenID4VP disclosures — returned newest-first.
