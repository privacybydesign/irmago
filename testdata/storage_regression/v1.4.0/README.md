# Storage regression snapshot — v1.4.0

Client storage generated at `v1.4.0`, the release that wired mdoc (ISO 18013-5,
`mso_mdoc`) credentials into real issuance and presentation. Loaded and verified by
`TestClientStorageRegressionV1_4_0`. Regenerate with
`TestGenerateClientStorageForRegressionTests` (`GENERATE_STORAGE=1`) while `version.go`
reads `1.4.0`.

This is the first snapshot that holds an mdoc. Storage-visible changes compared to
the `v1.3.0` snapshot:

- **mdoc data exists at rest for the first time**, in its own tables
  (`mdoc_batches`, `mdoc_batch_instances`, `mdoc_device_keys`): one age-verification
  batch of 30 instances, one of them spent by a disclosure, plus mdoc issuance and
  disclosure log entries.
- **The veramo test issuer is stored under its credential issuer URL**
  (`https://localhost:8443/test-issuer`), where older snapshots stored a `did:web`
  identifier.

Like the `v1.1.1` and `v1.3.0` snapshots, its `eudi_client_db` is **born encrypted**.

## Files

| File | Description |
|------|-------------|
| `bbolt_client_db` | IRMA client bbolt database (idemix credentials, IRMA-issued SD-JWTs, logs). Copied to `db2` on load. |
| `eudi_client_db` | EUDI SQLCipher database (`yivi-eudi.db`): OpenID4VCI SD-JWT and mdoc credentials, logs, and status-list state. **Encrypted at rest.** |
| `ecdsa_sk.pem` | Client signer key. |
| `keyshare_users.json` | Keyshare users preloaded into the test keyshare server. |
| `metadata.json` | Human-readable dump of the stored credentials and logs. |

As with the older snapshots, `metadata.json` shows logo bytes that the databases do not
hold: the EUDI database stores only a logo URI. EUDI credentials and log entries,
including the mdoc ones, therefore load without an image.

## Sessions performed

The same session script as the `v1.3.0` snapshot, plus two mdoc steps:

- **IRMA issuance:** `irma-demo.MijnOverheid.fullName` (idemix), `test.test.email`
  (idemix + 10 SD-JWTs), `irma-demo.MijnOverheid.singleton`, `irma-demo.RU.studentCard`.
- **OpenID4VCI issuance (SD-JWT):** 3× `TestCredentialSdJwt`, 1× `OrganizationCredentialSdJwt`.
- **Status list:** 1× `StatusListCredentialSdJwt`, revoked at the issuer and then refreshed.
- **OpenID4VCI issuance (mdoc):** 1× `eu.europa.ec.eudi.age_verification_mdoc` from the
  Python PID issuer (docType `eu.europa.ec.av.1`, element `age_over_18 = true`), a batch
  of 30.
- **IRMA disclosures** (4), **IRMA signature**, and **OpenID4VP SD-JWT disclosures** (4),
  as in `v1.3.0`.
- **OpenID4VP mdoc disclosure:** `age_over_18` to the EUDI reference verifier
  (`direct_post.jwt`), which checked the issuer and device signatures.
- **Removals** (final actions): `irma-demo.RU.studentCard` + 2 spare `https://localhost:8443/vct/test`.

## Expected database state

- **bbolt**: `irma-demo.MijnOverheid.fullName`, `irma-demo.MijnOverheid.singleton` and
  `test.test.email` (8 of 10 SD-JWT instances left).
- **EUDI SQLCipher**: one `https://localhost:8443/vct/test`, one
  `https://localhost:8443/vct/organization`, one revoked
  `https://localhost:8443/vct/statuslist`, and one `eu.europa.ec.av.1` mdoc batch with
  29 of 30 instances left.
- **Activity logs**: 24 entries, newest-first: the three removals, then the mdoc disclosure.

## Verified by the regression test

`TestClientStorageRegressionV1_4_0` checks, through `client.Client`'s public interface:

- a subset of the SD-JWT, IRMA and status-list checks from the `v1.3.0` test;
- the mdoc credential: docType, name, issuer id and name, issuer verified, MSO validity
  dates, not revoked and not revocation-supporting, the `age_over_18` attribute, and
  29 remaining instances (a spent instance stays spent after a reload);
- the mdoc issuance and disclosure log entries: credential, format, names, attribute,
  dates;
- log count, types and order;
- that the loaded client can still run fresh sessions of every kind, including a fresh
  mdoc issuance and disclosure.

The stored mdoc is **not** disclosed again. Its MSO is valid for 90 days from generation
(until 2026-12-22), so a disclosure of it would start failing on its own. The test removes
it, and the stored status-list credential, before the fresh-session check.
