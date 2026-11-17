# Storage regression snapshot — v1.5.0

Client storage generated at `v1.5.0`, the release that added SD-JWT-secured W3C VCDM 2.0
credentials (`vc+sd-jwt`), revocation of mdocs through the Token Status List, and CWT-encoded
Status List Tokens. Loaded and verified by `TestClientStorageRegressionV1_5_0`.
Regenerate with `TestGenerateClientStorageForRegressionTests` (`GENERATE_STORAGE=1`) while
`version.go` reads `1.5.0`.

This is the first snapshot that holds a VCDM credential or a revocable mdoc. Storage-visible changes compared to
the `v1.4.0` snapshot:

- **VCDM data exists at rest for the first time**, in its own tables (`vcdm_batches`,
  `vcdm_batch_instances`). Their holder binding keys live in `holder_binding_keys`, which
  VCDM shares with SD-JWT VC. That table gained a `vcdm_batch_instance_id` column. Its
  SD-JWT VC link keeps the column name `issued_credential_instance_id`.
- **A VCDM credential is stored as revoked through a W3C Bitstring Status List**: its
  instance carries `bitstring_status_entries` and a revoked `last_known_status`.
- **Claim images are stored** next to the logos, in `eudi_logos/credentials/`. They come
  from an Open Badges credential. The server that served them, and the JSON-LD context its
  type was expanded from, are not running when the test loads the snapshot.
- **mdoc status is stored for the first time.** `mdoc_batch_instances` gained
  `status_list_uri`, `status_list_idx`, `last_known_status` and `last_status_check_at`. The PID
  mdoc's 30 instances each name their own entry and are stored as revoked. The age-verification
  mdoc names no status list, so its columns are empty.
- **A CWT Status List Token is cached for the first time**, for the PID mdoc. The cache field
  became `RawToken`, still stored in the `raw_jwt` column. The encoding is not stored: the
  wallet tells a CWT from a JWT by its bytes.
- The database was written before 1.6.0 pinned the SQLCipher parameters.

Like the `v1.1.1` to `v1.4.0` snapshots, its `eudi_client_db` is **born encrypted**.

## Files

| File | Description |
|------|-------------|
| `bbolt_client_db` | IRMA client bbolt database (idemix credentials, IRMA-issued SD-JWTs, logs). Copied to `db2` on load. |
| `eudi_client_db` | EUDI SQLCipher database (`yivi-eudi.db`): OpenID4VCI SD-JWT VC, VCDM and mdoc credentials, logs, and status-list state (JWT and CWT tokens). **Encrypted at rest.** |
| `eudi_logos/` | EUDI logo and claim image files, one folder per container (`credentials`, `issuers`, `verifiers`). Encrypted, with HMAC file names. Copied to `eudi/<container>/logos/` on load. |
| `ecdsa_sk.pem` | Client signer key. |
| `keyshare_users.json` | Keyshare users preloaded into the test keyshare server. |

## Sessions performed

The same session script as the `v1.4.0` snapshot, plus these VCDM steps, all against veramo:

- **OpenID4VCI issuance (VCDM):** `TestCredentialVcdm` for Vera (`vera@example.com`); a
  `StatusListCredentialVcdm`, then revoked at the issuer and refreshed; an Open Badges
  credential (`TestOpenBadgeCredential`) with a `data:` image, two downloaded images and one
  image URL that does not resolve; and a spare `TestCredentialVcdm` (`spare-vcdm@example.com`).
- **OpenID4VCI issuance (mdoc with status):** 1× `eu.europa.ec.eudi.pid_mdoc` from the Python
  PID issuer (docType `eu.europa.ec.eudi.pid.1`), a batch of 30. An in-test server (the
  `startMdocStatusListServer` helper) handed the issuer one Token Status List entry per
  instance and served the list as a CWT, signed with the issuer's document signer key. All
  entries were then set to revoked, and the wallet refreshed.
- **OpenID4VP VCDM disclosures** to the veramo verifier, each a `vp+jwt` presentation: Vera's
  credential, then the Open Badge.
- **Removals** (final actions): `irma-demo.RU.studentCard`, 2 spare
  `https://localhost:8443/vct/test` and the spare VCDM credential.

Each VCDM credential is a single instance, not a batch. Veramo gives every copy in a batch
its own `credentialSubject.id`, and v1.5.0 refuses such a batch. So no VCDM instance is
marked `used`.

## Expected database state

- **bbolt**: `irma-demo.MijnOverheid.fullName`, `irma-demo.MijnOverheid.singleton` and
  `test.test.email` (8 of 10 SD-JWT instances left).
- **EUDI SQLCipher**: one `https://localhost:8443/vct/test`, one
  `https://localhost:8443/vct/organization`, one revoked
  `https://localhost:8443/vct/statuslist`, one `eu.europa.ec.av.1` mdoc batch with 29 of 30
  instances left, one revoked `eu.europa.ec.eudi.pid.1` mdoc batch of 30 instances with a cached
  CWT Status List Token, and three VCDM batches: Vera's, the revoked status-list one, and the Open
  Badge.
- **Activity logs**: 32 entries, newest-first: the four removals, then the Open Badge, VCDM
  and mdoc disclosures.

## Verified by the regression test

`TestClientStorageRegressionV1_5_0` checks, through `client.Client`'s public interface:

- the SD-JWT VC, IRMA and status-list checks shared with older snapshots, and that each of
  the 30 stored age-verification mdoc instances still signs with its stored device key (29 left);
- the PID mdoc: it reads back as revocation-supporting and revoked, without the status list
  server. In a copy of the database, every instance keeps its own status list URI and index,
  a revoked last-known status and a check time, and the token cached for that URI is a CWT.
  Each instance still signs with its stored device key. The token itself is not decoded: it
  has expired, and the wallet would fetch it again rather than read a stale cache entry;
- both `TestVcdmCredential` credentials: name, issuer and verified flag, attributes under
  `credentialSubject` (including the holder's `credentialSubject.id`), no expiry date, and
  revocation: none for Vera's, revoked for the status-list one, read without network access;
- the Open Badge's claim images, loaded from the image store;
- log count and order, the OpenID4VCI issuances, the removals, and the VCDM and Open Badge
  disclosure log entries with their images;
- that a DCQL `type_values` query still finds the Open Badge, from the types stored at
  issuance, since its context cannot be fetched now;
- that Vera's stored credential can still be disclosed: the verifier checks a presentation
  signed with the stored holder binding key;
- that the loaded client can still run fresh sessions of every kind, including a fresh VCDM
  issuance and disclosure.

The Open Badge disclosure log's issuer image is only checked to load. A log entry stores its
issuer image under the issuer id, which Vera's credential shares, so the later VCDM removal
log replaced it with the issuer metadata's logo.
