# Storage regression snapshot — v1.5.0

Client storage generated at `v1.5.0`, the release that added SD-JWT-secured W3C VCDM 2.0
credentials (`vc+sd-jwt`). Loaded and verified by `TestClientStorageRegressionV1_5_0`.
Regenerate with `TestGenerateClientStorageForRegressionTests` (`GENERATE_STORAGE=1`) while
`version.go` reads `1.5.0`.

This is the first snapshot that holds a VCDM credential. Storage-visible changes compared to
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
- `mdoc_batch_instances` gained status columns. They are empty here: the mdoc names no status
  list.
- The status list cache field became `RawToken`, still stored in the `raw_jwt` column.
- The database was written before 1.6.0 pinned the SQLCipher parameters.

Like the `v1.1.1` to `v1.4.0` snapshots, its `eudi_client_db` is **born encrypted**.

## Files

| File | Description |
|------|-------------|
| `bbolt_client_db` | IRMA client bbolt database (idemix credentials, IRMA-issued SD-JWTs, logs). Copied to `db2` on load. |
| `eudi_client_db` | EUDI SQLCipher database (`yivi-eudi.db`): OpenID4VCI SD-JWT VC, VCDM and mdoc credentials, logs, and status-list state. **Encrypted at rest.** |
| `eudi_logos/` | EUDI logo and claim image files, one folder per container (`credentials`, `issuers`, `verifiers`). Encrypted, with HMAC file names. Copied to `eudi/<container>/logos/` on load. |
| `ecdsa_sk.pem` | Client signer key. |
| `keyshare_users.json` | Keyshare users preloaded into the test keyshare server. |

## Sessions performed

The same session script as the `v1.4.0` snapshot, plus these VCDM steps, all against veramo:

- **OpenID4VCI issuance (VCDM):** `TestCredentialVcdm` for Vera (`vera@example.com`); a
  `StatusListCredentialVcdm`, then revoked at the issuer and refreshed; an Open Badges
  credential (`TestOpenBadgeCredential`) with a `data:` image, two downloaded images and one
  image URL that does not resolve; and a spare `TestCredentialVcdm` (`spare-vcdm@example.com`).
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
  instances left, and three VCDM batches: Vera's, the revoked status-list one, and the Open
  Badge.
- **Activity logs**: 31 entries, newest-first: the four removals, then the Open Badge, VCDM
  and mdoc disclosures.

## Verified by the regression test

`TestClientStorageRegressionV1_5_0` checks, through `client.Client`'s public interface:

- the SD-JWT VC, IRMA and status-list checks shared with older snapshots, and that each of
  the 30 stored mdoc instances still signs with its stored device key (29 left);
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
