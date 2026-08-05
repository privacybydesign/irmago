# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Locale-aware client: `client.New` takes an initial UI locale and `Client.SetLocale` changes it at runtime. All app-facing text resolves inside irmago through a fixed fallback chain (exact locale → base language → English → any); text of one object never mixes languages, while fields that are not displayed text — logos and issue URLs — fall back across languages independently, so they survive a locale that does not translate them.
- Background logo backfill on startup and locale change: fetches logos missing for the current locale and signals `ClientHandler.CredentialsChanged()` when a sweep actually caches something. A single worker runs the sweeps, so they never overlap and a burst of language changes collapses into one sweep for the language the user landed on; `Client.Close` cancels a running sweep, aborting any download in flight, and waits for it to unwind. Listing calls never block on the network.
- mDoc (ISO 18013-5, `mso_mdoc`) credentials are wired into the real issuance and presentation paths, replacing the standalone prototype wire format added in 1.1.1. Issuance runs through the generic OpenID4VCI client via a new format-parser seam (`services.CredentialFormatParser`, registered per format in `client.New`), so credential offer, token request, nonce endpoint and proof of possession are shared with SD-JWT VC rather than duplicated; presentation runs through a `mdoc_dcql` DCQL handler alongside the existing SD-JWT handlers. `mso_mdoc` is accepted by the credential-configuration validators, and the verifier's `response_uri` is threaded through `PrepareDisclosure` because mdoc's `deviceAuth` signs over the OpenID4VP session transcript (`[clientId, nonce, responseUri]`); SD-JWT's key-binding JWT ignores it.
- An OpenID4VCI credential offer without a `grants` member is now accepted: the grant type is taken from the authorization server's `grant_types_supported` metadata, as OID4VCI v1.0 § 4.1.1 requires for an absent or empty `grants`. An omitted `grant_types_supported` counts as `["authorization_code", "implicit"]` per RFC 8414 § 2. Only the authorization code grant can be derived this way, because the pre-authorized code flow needs a `pre-authorized_code` and only the offer can supply one, so such an offer still fails when the authorization server does not support `authorization_code`. An offer that does name grant types, but only ones the wallet does not implement, keeps failing as before.
- `client.ClientHandler`: the wallet's own app-facing callback interface, which `client.New` now takes in place of `irmaclient.ClientHandler`. It carries only what the app acts on — `CredentialsChanged`, `ReportError`, and the enrollment and change-pin results — replacing `UpdateAttributes` and `Revoked(cred)` with the single `CredentialsChanged` and dropping `UpdateConfiguration` (irma_configuration internals the app cannot use). `client.Client` adapts it to the callback surface `IrmaClient` expects internally.
- `ClientHandler.CredentialsChanged()`: one signal for "the credentials you are showing are out of date". It now also fires when a credential's revocation status changes, for both credential technologies — an idemix credential whose issuer revoked it, discovered while the client updates its non-revocation witness, and an SD-JWT VC whose Token Status List entry moved, discovered by the background sweep or a UI-initiated `Client.RefreshStatuses`. Previously an SD-JWT VC revocation never reached the app at all — the sweep wrote the new status to storage and stopped there, so it went unnoticed until the user happened to reopen the credential list — while an idemix one did arrive, through the `Revoked(cred)` this replaces, but on every rediscovery rather than once. Only a *change* fires it: the sweep is silent when it re-confirms a status the wallet already recorded, and an idemix revocation is reported once per credential rather than on every rediscovery — a revoked credential's non-revocation witness never advances, so `IrmaClient`'s witness-update job keeps finding the same revocation every few tens of seconds. Either way the app is not nagged into re-reading its credential list on a timer. Suspension and un-suspension count alongside revocation. `Client.RefreshStatuses(ctx) error` keeps its signature.

### Changed
- Issuance now says so when a credential will render without display text, instead of degrading silently. The wallet falls back to showing the raw `vct`/`docType` in place of a name, which is deliberate — it keeps a verified credential storable — but nothing recorded *why*, and the three issuer-side causes are indistinguishable from the app: the issuer advertises no credential configuration under the offered `credential_configuration_id`; the configuration carries no `credential_metadata` (what an issuer emitting an older OpenID4VCI draft looks like from here, since those put `display` and `claims` on the configuration itself, which is not read); or the metadata is present but carries no display entries, or no claims and therefore no attribute labels. Each is now named in a warning naming the issuer and the credential type.
- Don't wait for at least one Redis replica anymore when using Redis Sentinel mode
- **Breaking:** `client.New` takes a `client.ClientHandler` instead of an `irmaclient.ClientHandler`. The gomobile app must implement the new, smaller interface: replace `UpdateAttributes` with `CredentialsChanged`, and drop `UpdateConfiguration` and `Revoked(cred)` — whatever the app did on `Revoked` now belongs in `CredentialsChanged`.
- **Breaking:** `clientmodels` DTOs ship resolved strings instead of translation maps (17 `TranslatedString` fields). The gomobile app must update in lockstep: pass the locale to `client.New`, call `SetLocale` on language changes, and drop client-side language picking.
- **Breaking:** `clientmodels.CredentialFormat` has a third member, `Format_MsoMdoc` (`"mso_mdoc"`), alongside `"dc+sd-jwt"` and `"idemix"`. **irmamobile must ship this in lockstep**, because its mirrored Dart enum is closed and has no fallback member: an unrecognised value throws while the enum is being decoded, which fails the *entire* payload rather than the one mdoc entry. The value reaches the app in four places — `Credential.credential_instance_ids` and `Credential.batch_instance_counts_remaining` (where it is a map *key*, so the entry cannot be skipped), `LogCredential.formats`, and `DisclosureCandidate.format` — so an app without the new member breaks the credential list, the activity log, and the disclosure permission screen the moment the wallet holds one mdoc. Adding an unknown-value fallback to the Dart enum is worth doing in the same change, so the next format added here degrades to one unrenderable row instead of a dead screen.
- Issuance downloads only the logo that resolves for the current locale, skipping cached ones, instead of the first available display's logo.
- EUDI activity logs persist text resolved at creation time; on read, entries re-resolve against the stored credential's metadata for the active locale, falling back to the snapshot for deleted credentials and verifier names. Entries written by earlier versions (translation-map format) are decoded transparently.
- Support for the IETF OAuth Token Status List (draft-ietf-oauth-status-list-15) on SD-JWT VC credentials: the wallet fetches, verifies, and caches Status List Tokens (`application/statuslist+jwt`), checks credential status at issuance, at disclosure, and on a background sweep, and exposes `Client.RefreshStatuses(ctx)` for UI-initiated refreshes.

### Fixed
- **Security:** a verifier can no longer escape the authorization carried in its certificate by naming itself in the request. The certificate's authorized attribute sets were checked in an `else if` after the branch that reads `client_metadata.client_name`, so the two shared one chain: any request supplying a `client_name` took the first branch and the certificate's authorization was never read, accepting every query. Since the verifier signs the request it supplies that field itself, this let any verifier holding a trusted Yivi certificate widen its own authorization at will. What a verifier may ask for and how it chooses to display itself are now decided independently, and the check runs before the display logic. A certificate carrying no scheme data still skips the check, since it registers no attribute sets to check against — third-party certificates remain authorized for all attributes, as before.
- mDoc attribute display names now resolve when the issuer publishes a claim path without its namespace. An mdoc claim path is `[namespace, elementIdentifier]`, and `claimDisplayName` compared stored metadata paths against the requested namespace and element, so a one-component `["age_over_18"]` matched nothing and the attribute rendered with no label at all — while the credential's own name still resolved, no error was raised and nothing was logged, which reads in the app as a wallet display bug rather than as issuer metadata missing a namespace. `convertCredentialMetadata` stores whatever the issuer published verbatim, and the EU Age Verification profile specifies no display metadata at all, so nothing obliges an issuer to use the two-component form. A bare `[elementIdentifier]` path is now accepted, but only after an exact match has been ruled out across every claim, so a fully qualified path always wins; the fallback logs a warning naming the path the issuer should have published, since the fix belongs in the issuer's metadata. Being a read-time fallback, this also repairs credentials already stored in a wallet.
- **Security:** an mDoc's `docType` is now bound to the signed one. `MDoc.docType` sits in the document map beside `issuerSigned` and is covered by no digest and no signature; `MobileSecurityObject.docType` is inside the MSO the Document Signer certificate signs. The two were never compared, and the value the verifier reported was taken from the unsigned envelope, so re-labelling that one field left all three verification entry points returning valid while reporting the attacker's `docType`. That value is not inert: the mdoc format parser stores it as the credential's `VerifiableCredentialType`, which is what DCQL `doctype_value` matching and the scheme's relying-party authorization then key off — so an age-verification credential could be filed and presented as a PID. A mismatch is now rejected, `VerificationResult.DocType` carries the signed value, and it is left empty on every failure path rather than echoing an unauthenticated string. `VerifyWithDeviceAuth` also rejects a caller-supplied `docType` that differs from the signed one, which previously surfaced only as an opaque `deviceAuth signature invalid`.
- **Security:** a verifier can no longer crash the wallet with a crafted DCQL query. `mdoc_dcql`'s claim-value comparison used Go's `==` on two `any` values decoded from untrusted input — the claim value from the credential's cached claims, the expected value from the authorization request. `==` panics when both hold the same uncomparable dynamic type, so an array-valued claim tested against an array in a `values` constraint died with `comparing uncomparable type []interface {}`. It was reached while rendering the permission screen, before the user was asked anything. The comparison is now structural and never panics. It also matches numbers across decoders (JSON yields `float64` for every number, CBOR yields `uint64`/`int64`), which a bare `==` never did, so a `values` constraint on an integer claim silently never matched.
- **Interop:** mDoc CBOR now matches the ISO 18013-5 wire format at four positions where a Go type was substituting its own encoding. `issuerAuth` and `deviceSignature` are the bare `COSE_Sign1` array the standard specifies, rather than a byte string wrapping it (a `[]byte` field) or the tag-18 `COSE_Sign1_Tagged` form (go-cose's `Sign1Message`); each `IssuerSignedItemBytes` is the `#6.24(bstr)` value itself, rather than the map `{"EncodedItem": <bstr>}` that fxamacker/cbor produced for the one-field `Tag24Item` struct — a Go field name on the wire, with the tag-24 value buried a byte string deeper; and `deviceSigned.nameSpaces` is likewise a bare tag-24 value. Each of these round-tripped against this codebase and nothing else, which is why the existing tests passed: both sides simply agreed on the wrong shape. Digests and signatures are computed over the same bytes as before, so no credential or signature changes — only the envelope. Reading stays deliberately more permissive than writing: `decodeCoseSign1` accepts both COSE serializations, since the tag is outside `Sig_structure` and implementations disagree about it. New tests decode a real `DeviceResponse` generically, into `any` rather than this package's own structs, and assert the shape at each position.
- mDoc issuance no longer fails when holder binding resolves to a DID. A stored holder binding key carries a thumbprint *or* a DID URL and never both, and it gets the DID whenever the credential configuration's binding method is `did:key` or `did:jwk`. The mdoc parser can only compute a thumbprint from the COSE key in the MSO, so against any DID-binding issuer the match found nothing and issuance aborted with `no matching holder binding key found` — after the credential had already been issued. `ParsedCredential` now carries the holder binding public key, and the matcher derives every identifier form the wallet could have stored from it, the same way `JwtProofBuilder` does; a test pins that the derived DID URLs are byte-identical to the ones the proof builder writes, so the two cannot drift apart silently. This replaces `ParsedCredential.HolderBindingKeyDidUrl`, which no code ever populated.
- A stored mDoc batch's `Format` is taken from the credential that was parsed and verified, not from the issuer metadata's credential configuration. The configuration was read with an unchecked map index, so an absent `credential_configuration_id` yielded a zero-valued configuration and the batch was stored with an empty format — which every later format-keyed read misses, including `GetBatchesByDocType` and the DCQL handlers' dispatch on format.
- Presenting an mDoc no longer burns a single-use instance on a disclosure that then fails. `mdoc_dcql` marked the instance used before decoding the batch's cached claims for the log entry, which is fallible, so a failure there consumed a use on a presentation that returned an error and never reached the verifier. Everything fallible for a selection now happens before the instance is marked, as in `eudi_sdjwt_dcql`.
- **Security:** an mDoc's Document Signer certificate is now checked for the extended key usage that authorizes it to sign mdocs (`1.0.18013.5.1.2`, ISO 18013-5 Annex B.1.2). Previously the chain walk passed `x509.ExtKeyUsageAny` and nothing else looked, so *any* certificate chaining to a trusted IACA root was accepted as a document signer — including one legitimately issued for an unrelated role beneath the same root. That is not hypothetical for Yivi's own trust model, which has a relying-party branch alongside the attestation-provider branch. A certificate that enumerates its permitted usages and omits this one is rejected; a certificate with no extended key usage extension is still accepted, since RFC 5280 § 4.2.1.12 defines that as "not restricted as to purpose". `x509.VerifyOptions.KeyUsages` cannot express the OID — `crypto/x509`'s `ExtKeyUsage` enum has no member for it — so the chain walk keeps `ExtKeyUsageAny` purely to stop Go defaulting to `ExtKeyUsageServerAuth`, and the usage is checked separately. `mdoc.Issuer` now stamps the usage on the DS certificates it generates, which it should have been doing anyway.
- An `mso_mdoc` credential configuration is no longer rejected for advertising its signing algorithm the way OpenID4VCI requires. `credential_signing_alg_values_supported` is REQUIRED and non-empty, but its element type is format-specific: COSE algorithm identifiers as integers (`-7` for ES256) for `mso_mdoc`, JWS algorithm names as strings (`"ES256"`) for `dc+sd-jwt`. Every value was read as a string, so an mdoc configuration looked as though it advertised no algorithm at all and `ValidateSupportedFeatures` refused the issuance before the first network call — including for the EUDI reference issuer, whose every mdoc configuration advertises exactly `[-7]`. COSE identifiers are now validated for `mso_mdoc` against the one algorithm `eudi/credentials/mdoc` signs and verifies with, so an issuer offering only e.g. `-8` (EdDSA) is still rejected, but now with a message naming what was advertised — and rejected up front rather than after a full token and credential request, at an opaque `MSO signature invalid`. The message distinguishes the two ways an offer can miss: advertising an algorithm ISO 18013-5 permits for the MSO (`-7` ES256, `-8` EdDSA, `-35` ES384, `-36` ES512) that this wallet has yet to implement, or advertising nothing 18013-5 permits at all, such as `-257` (RS256) or a JWS name in place of an identifier. An absent or empty array remains accepted for both formats. The EU Age Verification Blueprint does not specify this metadata — its Annex A marks AP metadata "TBD" — while its crypto suite mandates P-256 with ES256 and SHA-256, so ES256 is the only identifier the AV profile needs.
- Presenting an mDoc over OpenID4VP no longer fails relying-party authorization. The scheme-level query check read the requested credential type only from `vct_values` and treated every string component of a claim path as an attribute name; `mso_mdoc` names its type with `doctype_value` and its claim paths are `[namespace, elementIdentifier]`, so every mdoc query was rejected — first as "missing vct_values", and had that been supplied, for requesting the namespace as an unregistered attribute. `scheme.CredentialQueryInfo` now carries `DocTypeValue` alongside `VctValues` and exposes both through `CredentialTypes()`, and the attribute names come from a new format-aware `dcql.CredentialQuery.AuthorizationAttributeNames()` that contributes only the `elementIdentifier` for mdoc while leaving every other format's behaviour unchanged. A query naming no credential type at all is still refused. This only ever affected verifiers presenting a Yivi-issued certificate without `client_metadata.client_name` — the DID client-id path deliberately skips this check and a non-Yivi certificate never reaches it — which is the production trust model, so the failure would not have shown up against a development verifier. That `client_name` exemption was itself an authorization bypass, closed separately in this release (see the first entry under Fixed), so authorization now runs for every Yivi-issued certificate regardless of how the verifier names itself.
- A relying party whose authorized credential identifier has fewer dot-separated parts than the identifier a verifier requests no longer panics the wallet while matching them (the authorized identifier was indexed by the requested one's position, and read past its end). Such a pairing was already a non-match, so this is a rejection rather than a policy change; a dotted mdoc docType like `eu.europa.ec.av.1`, five parts against a scheme's usual three, makes it ordinary rather than exotic.
- mDoc permission screens and disclosure logs now show the issuer name, credential logo and attribute display names. `mdoc_dcql` reads batches through `GetBatchesByDocType` and `GetBatchByHash`, neither of which eager-loaded the issuer display entries or the credential metadata's claims, so the display metadata came back empty while the SD-JWT handler — which reads through the fully-preloaded `GetCredentialBatchList` — looked correct. All four batch lookups now share one preload set, since a missing preload does not fail but silently renders blank.
- An OpenID4VCI credential offer that omits the optional `grants` member (or sets it to `null`) no longer takes down the host process. `grants` is OPTIONAL per OID4VCI v1.0 § 4.1.1, but the pointer was dereferenced without a nil check while selecting the grant type, and that happened on a goroutine owned by irmago, so the resulting nil pointer panic was not covered by any `recover` and aborted the app rather than ending the session. As a backstop, a panic anywhere on the OpenID4VCI session goroutine is now reported as a session failure ([#643](https://github.com/privacybydesign/irmago/issues/643)).
- An OpenID4VCI credential offer whose pre-authorized code grant omits the `pre-authorized_code`, which is REQUIRED per OID4VCI v1.0 § 4.1.1, is now rejected while the offer is parsed. Previously the wallet accepted it and sent an empty `pre-authorized_code` to the token endpoint.
- EUDI storage writes are now atomic: `writeFile` writes to a temp file and renames it into place, so a crash or a concurrent write can no longer leave a partially written file behind. Previously a truncated ciphertext read back as a decryption error rather than as a missing file — the worse of the two failure modes, since it looks like corruption rather than absence.
- `common.SaveFile` wrote its temporary file into the process working directory instead of the destination's directory on Windows, then renamed it into place. It located the directory with `path.Dir`, which only understands `/`, while the path it is given has already been converted to OS separators — so on Windows it found no separator and returned `"."`. The rename then crossed volumes whenever the destination was on another drive, which Windows refuses, failing the write and orphaning the temp file in the working directory. Affects scheme signing (`pk.pem`, `index`) and the scheme file copies made during download.
- The data tab resolved credential and issuer logos from the first display entry only, so a logo attached to another language's display did not show.
- OpenID4VCI issuance logs recorded the issuer metadata's `vct` (possibly a placeholder like `"unknown"`) as the credential id; the issued JWT's `vct` claim now takes precedence.
- SD-JWT VC credential displays now merge per field instead of per whole locale entry: when the VCT type-metadata document defines a `display` entry for a locale, `openid4vci.Merge` keeps VCT's value for every field it specifies but inherits any field VCT leaves empty (`logo`, `description`, `background_color`, `text_color`, `background_image`) from the OpenID4VCI `credential_metadata` entry for the same locale. Previously the whole VCI entry was dropped for that locale, so issuers that put the credential logo on the VCI side while the VCT `display` omitted it ended up with a blank credential logo in the wallet ([#635](https://github.com/privacybydesign/irmago/issues/635)).
- Credential, issuer and verifier logos now keep their MIME type: the EUDI `LogoManager` stores the Content-Type reported on download (or by the verifier's scheme data) alongside the image bytes, and `LoadLogoImage` returns it in `clientmodels.Image.MimeType`. Previously the MIME type was discarded, so wallets could not tell SVG logos apart from bitmaps and SD-JWT VC credential logos in SVG format rendered blank ([irmamobile#674](https://github.com/privacybydesign/irmamobile/issues/674)). **Breaking (internal API):** `filesystem.LogoManager.Save` takes an extra `mimeType` parameter and `Get` returns it.
- Dismissing an OpenID4VP session left it running, so its permission screen reappeared on every IRMA session completed afterwards. `Dismiss` now delivers a denial through the same channel the user's own refusal travels, unwinding the session, and the permission refresh only fires while a session is genuinely awaiting an answer.
- With two OpenID4VP sessions in flight, dismissing one could cancel the other: the client kept a single current-session pointer and handed itself out as every session's dismisser, so a dismissal always reached the most recently started session. The untouched session was reported as dismissed, while the dismissed one stayed parked awaiting permission forever, leaked its goroutine, and could not be reached by any further dismissal. The dismisser `NewSession` returns is now bound to its own session, and the permission refresh for issuance-during-disclosure reaches every awaiting session instead of only the newest. A dismissal arriving while the authorization request is still being fetched and verified, previously a silent no-op, now cancels the session the moment it would first ask for permission ([#650](https://github.com/privacybydesign/irmago/issues/650)).
- `session.finish` drops a repeat of the terminal state it already dispatched, so `HandleUserInteraction`'s dismissal backstop and a protocol's own `Cancelled` no longer both emit a `Dismissed` event. Best-effort rather than guaranteed: the state it compares is written from both the UI and protocol goroutines without synchronisation, like `session.State` itself. A *different* later terminal state is still dispatched — the backstop is a guess about what the protocol will do, and OpenID4VCI's `Dismiss` only logs, so its issuance runs on past the guess and stores a credential; the wallet now reports that `Success` rather than leaving the user on the dismissal.

### Internal
- **Breaking (internal API):** `scheme.CredentialQueryInfo.ClaimPaths` is renamed to `AttributeNames`. The field holds the attribute identifiers a DCQL query requests, matched against `AuthorizedAttributeSet.Attributes` — never claim paths, since projecting paths into attribute names is format-specific and now happens in `dcql.CredentialQuery.AuthorizationAttributeNames`. The old name invited exactly the mistake that broke mdoc authorization.
- Removed `dcql.CredentialQuery.ClaimPaths`, an alias for `AllClaimPaths` with no callers. It and `VctValues` were documented as implementing a `scheme.ValidatableCredentialQuery` interface that no longer exists; `VctValues` is still used and keeps a doc comment describing what it actually returns.
- **Breaking (internal API):** `services.RevocationService.RefreshStatuses` returns `(changed int, err error)` — the number of credential batches whose status moved, which the client uses to decide whether to wake the app. `db.CredentialStatusInstance` carries `LastKnownStatus` so the sweep can tell a change from a re-confirmation.
- Integration tests in `internal/sessiontest` for the revocation half of `CredentialsChanged`, one per credential technology: an idemix credential revoked at a revocation-enabled server (needs the docker-compose postgres, like the other revocation tests), and an SD-JWT VC revoked at the real status-list agent (in the opt-in status-list group, alongside its neighbours).
- Dutch-locale and locale-switch integration tests for every protocol and integration layer.
- The storage regression tests now assert EUDI activity-log content, pinning the legacy translation-map decoding. Regenerate the regression fixture at the next release: this version changes the stored log text format and the issuance-log credential id.
- Refactor the SD-JWT implementation to correctly split the SD-JWT and SD-JWT VC specification details into separate packages.

## [1.2.0] - 2026-07-22
### Added
- `eudi/holderkeys`: a CGO-free package providing the holder-key seam (`HolderSigner`, `SoftwareHolderSigner`, the KB-JWT `NewSignerKeyBinder` bridge) so a WSCA adapter or a server-side (Postgres) holder can implement external holder-key signing without pulling in a sqlcipher (cgo) dependency.
- Pluggable holder-key binding seams for external secure devices (WSCA/HSM): `openid4vci.NewClient` takes a required `HolderKeyBinder` and `eudi_sdjwt_dcql.NewSdJwtVcDcqlHandler` a required `sdjwtvc.KeyBinder`, and `proofs.BuildWithES256Signer` signs the OpenID4VCI proof of possession via an external signer. Callers pass the software, storage-backed binder for the existing behaviour, or a WSCA/HSM-backed implementation.
- `storage.NewStorageWithDialector(dialector, fs)`: open the EUDI holder database on any GORM dialector (e.g. `gorm.io/driver/postgres`) rather than only sqlcipher, for server-side / multi-tenant deployments. `NewStorage` is unchanged (it builds the sqlcipher dialector and delegates). The caller owns the at-rest encryption posture of a non-sqlcipher driver.

### Fixed
- Disclosure requests that pin a fixed attribute value now still offer an issuance suggestion for the requested credential type, when that type is non-singleton and publishes an `IssueURL`. Previously, if the user already held a matching credential, no option to obtain a fresh credential of that type was offered.
- EUDI holder key-metadata models (`ECDSAKeyMetadata`, `RSAKeyMetadata`) tagged `HolderBindingKeyID` as a unique index rather than the primary key the doc comment intends, so the models had no primary key. When GORM upserts the key-metadata association while storing a holder binding key it builds the `ON CONFLICT` target from the primary key; with none defined it emitted `ON CONFLICT DO UPDATE` with no target, which Postgres rejects (SQLSTATE 42601) — breaking every OpenID4VCI credential redemption on a Postgres-backed holder storage. `HolderBindingKeyID` is now `primaryKey`. Backwards-compatible: `AutoMigrate` is additive and keeps the existing unique index, which still satisfies the new `ON CONFLICT (holder_binding_key_id)` on both SQLite and Postgres.
- `AutoMigrate` of the EUDI holder models is now ordered parents-before-children, so it also runs on foreign-key-enforcing drivers (e.g. Postgres) and not only SQLite.
- `eudi/storage` no longer transitively pulls in the cgo `sqlcipher` package. The sqlcipher-only constructor moved from `storage.NewStorage` to a new `eudi/storage/sqlcipherstorage` package as `sqlcipherstorage.New`, so a pure-Go dialector consumer (e.g. `gorm.io/driver/postgres`) can import `eudi/storage` and build without compiling sqlcipher — including under `CGO_ENABLED=1` / `go test -race`, which the old layout still forced. **Breaking:** callers of `storage.NewStorage(...)` now call `sqlcipherstorage.New(...)` (identical signature); `storage.NewStorageWithDialector` is unchanged.

### Internal
- Centralize ad-hoc `http.Client` instantiations into a single shared `common.HTTPClient`, giving one source of truth for outbound client configuration.

## [1.1.1] - 2026-07-14
### Security
- The EUDI SQLCipher database was opened without its AES encryption key since v1.0.0, leaving `yivi-eudi.db` (holder binding keys, private keys, SD-JWT VC credentials and logs) unencrypted at rest despite the documented encryption-at-rest. The key is now passed to the connection so the database is encrypted.

### Internal
- Add storage regression tests for versions 1.0.0 (intentionally plaintext EUDI database, exercises the plaintext→encrypted migration) and 1.1.1 (born-encrypted EUDI database)
- Add prototype mDoc (ISO 18013-5) implementation for the EU Age Verification Blueprint (`eu.europa.ec.av.1`) under `eudi/credentials/mdoc`, covering issuer/holder/verifier flows, two-level IACA→DS certificate chain verification, `deviceKeyInfo`/`deviceAuth` device binding, selective disclosure, and an OpenID4VP-only presentation wire format (DCQL request, vp_token, direct_post form body with state). Not yet wired into any production issuance/verification path.

### Fixed
- On first launch after upgrading, an existing plaintext `yivi-eudi.db` written by v1.0.0/v1.1.0 is transparently and atomically re-encrypted in place with no data loss; already-encrypted databases are left untouched.
- Fix `200 serverResponse: context deadline exceeded (Client.Timeout or context cancellation while reading body)` on slow connections or large/slow response bodies: the outbound `http.Client` in `irma/transport.go` had a 5s `Timeout` that covered the whole request (including reading the response body) and silently overrode the intended 20s per-request context deadline. The 5s timeout is removed so the 20s deadline is the single source of truth.

## [1.1.0] - 2026-07-08
### Added
- Added support for `x509_hash` client identifier prefix in OpenID4VP flow
- Added support for Verifier Metadata in OpenID4VP flow

### Security
- Update Go toolchain 1.26.3 → 1.26.4 to fix vulnerabilities in `net/textproto` (GO-2026-5039) and `crypto/x509` (GO-2026-5037)
- Update dependencies with security relevance:
  - `github.com/go-chi/chi/v5` 5.2.5 → 5.3.0 (host header handling)
  - `github.com/golang-jwt/jwt/v5` 5.2.2 → 5.3.1
  - `github.com/hashicorp/go-retryablehttp` 0.7.7 → 0.7.8 (avoids leaking credentials embedded in request URLs)
- Sanitize user-controlled strings before writing them to log entries to prevent log injection
- Filter sensitive HTTP headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-Auth-Token`) from request logs
- Fix email header injection by using the parsed recipient address in the SMTP `To:` header
- Normalize file paths via `filepath.Clean` before filesystem operations

### Changed
- Replace `github.com/go-errors/errors` `WrapPrefix` calls with stdlib `fmt.Errorf` wrapping so `errors.Is`/`errors.As` traverse wrapped errors
- Raise the minimum Go version to 1.26
- Apply `go fix` modernizations across the codebase and enforce `go fix` as a CI status check
- Update CI GitHub Action versions to Node 24 supported once
- Update other dependencies to their latest releases: `github.com/lestrrat-go/jwx/v3`, `github.com/go-co-op/gocron` (v1 and v2), `github.com/spf13/{cast,cobra,pflag,viper}`, `go.etcd.io/bbolt`, `gorm.io/driver/{mysql,postgres,sqlserver}`, `github.com/alicebob/miniredis/v2`, `github.com/go-chi/cors` and `github.com/go-errors/errors`
- Added DID First Candidate Recommendation backwards-compatibility for verification methods containing `publicKeyBase58` verification material.

### Fixed
- Treat email addresses with a non-resolvable (NXDOMAIN) domain as permanently invalid instead of a transient network error, so the keyshare email task no longer retries them indefinitely and crowds out delivery of valid emails
- Fix `panic: send on closed channel` in the in-memory session store that could crash the server when an expired session was deleted while a status update for it was still being delivered to subscribers. Session-update notifications are now delivered synchronously under the read lock (mutually exclusive with channel closing) instead of from an unsynchronized goroutine, and subscription channels are cleaned up when their subscriber goes away. This also fixes two related data races on the session store detected under `-race`.
- Fix disclosure returning the wrong credential instance after another instance of the same credential type was deleted, caused by the positional credential cache not being invalidated for the instances shifted by the deletion
- Fixed a DidDocument deserialisation bug, where the `controller` attribute can be either a single string or a set of strings.

## [1.0.0] - 2026-06-19
### Added
- Support for issuing SD-JWT VC credentials over the OpenID4VCI protocol to the new `client` package
  - Supports the Pre-Authorized Code flow, including an optional `tx_code` (with retry on incorrect entry)
  - Supports the Authorization Code flow, including Pushed Authorization Requests (PAR), in-app browser based authorization, and PKCE
  - Supports DID-based holder binding: keys are bound to the credential at issuance, stored securely on the client, and removed together with the credential
  - Supports `authorization_details` in Authorization and Token requests
  - Supports encrypted credential request bodies
  - Issuers are verified via `did:web`, `did:key` and `did:jwk`; the `did:web` resolver can be configured to accept insecure HTTP for development
- Support for disclosing SD-JWT VC credentials with nested selectively-disclosable claims and array claims over the OpenID4VP 1.0 protocol
  - DCQL support extended with `claim_sets`, the `multiple` flag, predefined claim values (also for non-string values), and `require_cryptographic_holder_binding`
  - Adds the `decentralized_identifier` client identifier prefix in addition to the existing `x509_san_dns`
  - Stricter validation of presentation nonces and verifier metadata
- New top-level Go package `client`, offering a unified `Client` that wraps the existing `irmaclient` (renamed to `IrmaClient`) together with an `OpenID4VCIClient` and an `OpenID4VPClient`
  - New schemaless session implementation that no longer relies on `IrmaConfiguration` for OpenID4VCI/VP credential types
  - New `common/clientmodels` package containing the serializable types shared between client integrations (sessions, logs, interactions)
  - API to delete individual credentials, and the ability to mark batches of size 1 as infinitely reusable
- Encrypted-at-rest EUDI storage using SQLCipher for sensitive data such as holder binding keys, key metadata, and SD-JWT VC credentials
  - File names of stored images and logos (credential, issuer, requestor) are hashed and salted with an AES-derived key
- New EUDI session log system covering both OpenID4VCI issuance and OpenID4VP disclosure sessions
  - Logs include credential metadata, issuer/credential/requestor logos, revocation status and dates
  - Logs are indexed by creation date and merged with `irmaclient` logs in chronological order using a two-pointer merge
  - `DeleteAll` now also clears the EUDI storage and database contents
- `yivi` top-level command line tool that wraps the existing `irma` command (container image published as `ghcr.io/privacybydesign/yivi`); the existing `irma` command remains available as `yivi irma ...`
- Disclosure UI improvements: support for attribute group headers, credential images shown during disclosure, and a more reliable selection of the requestor's display name

### Changed
- Raise the minimum Go version to 1.26
- Apply `go fix` modernizations across the codebase and enforce `go fix` as a CI status check
- Requests using `irma.HTTPTransport` have a doubled response timeout (20 seconds) to accommodate for slow and/or foreign connections
- `Attribute` no longer carries an `Id`; it now carries a `ClaimPath` (`[]any`) to address nested claims. The `Array` and `Object` value variants are removed from `AttributeValue`, and `TranslatedString` is no longer an `AttributeValue` variant
- Public structs across the client packages now use snake_case JSON tags
- `SessionState.Error` is now a serializable error type; `PinBlockedTimeSeconds` and `RemainingPinAttempts` are now optional; sessions can be dismissed from any state
- Revocation attributes are filtered out of the user-facing attribute list; the wrongly-issued credential view only contains the relevant attribute and only the most recent wrongly-issued credential is shown
- The repository layout has been reorganised: CLI sources moved under `yivi/cli/...`, the `irma/cmd` package now lives at `yivi/cli/irmacli`, and EUDI components live under the new `eudi/...` tree

### Security
- Update dependencies to resolve Dependabot security advisories:
  - `golang.org/x/crypto` 0.40.0 → 0.53.0 (GHSA-f6x5-jh6r-wrfv, GHSA-j5w8-q4qc-rx2x)
  - `github.com/sirupsen/logrus` 1.9.0 → 1.9.4 (GHSA-4f99-4q7p-p3gh)
  - `github.com/jackc/pgx/v5` 5.5.5 → 5.10.0 (GHSA-9jj7-4m8r-rfcm, GHSA-j88v-2chj-qfwx)
  - `filippo.io/edwards25519` 1.1.0 → 1.2.0 (GHSA-fw7p-63qq-7hpr)

### Fix
- Bug that keyshare registration failed when users email domain had no MX records.
- Bug where an empty `con` in a `condiscon` request caused all attribute disclosures to be swallowed, even when other `con`s were satisfied (irmamobile #360)

### Deprecated
- `irma server` flags `--email` / `-e` and `--no-email`, and the `email` config key, are no longer used. They are still accepted for backwards compatibility but will emit a deprecation warning when set.

### Removed
- Outbound POST of admin email and version to `privacybydesign.foundation/serverinfo/` on `irma server` startup (endpoint no longer exists)
- Production-mode requirement that `irma server` operators specify `--email` or `--no-email`; the admin email value is no longer used for anything

### Internal
- New `eudi/...` tree with packages for OpenID4VCI, OpenID4VP, DCQL, SD-JWT VC presentation/verification, DID resolution (`did:web`, `did:jwk`), JWT key providers, OAuth2/PKCE, and storage (SQLCipher + filesystem)
- Test infrastructure for OpenID4VCI: local issuance server, mock authorization server, and a Veramo-compatible OpenID4VP verifier; integration tests for both the Pre-Authorized and Authorization Code flows
- Significant expansion of the integration test suite (chained sessions, signature sessions, pairing code, optional credentials, multiple-credential issuance, schemaless disclosure, complex SD-JWT VC scenarios)
- Docker Compose now runs integration tests with TLS; CGO is enabled via env var to support SQLCipher
- SQLCipher build instructions for macOS, Debian/Ubuntu, Fedora/RHEL and Windows added to the README; CI installs the SQLCipher library. Pre-compiled release binaries are still built with `CGO_ENABLED=0` and do not include SQLCipher

## [0.19.2] - 2026-02-26
### Fix
- Bug that caused HTTP request body to not be sent upon retransmission

### Changed
- Add wildcard support for authorized credentials and attributes in relying party and attestation provider certificates

## [0.19.1] - 2025-10-13
### Fix
- Bug in `irmaclient` that caused attributes to be stored in the wrong order in credential removal logs

## [0.19.0] - 2025-09-30
### Changed
- Remove legacy storage from irmaclient
- Add support for issuing SD-JWT VC together with Idemix over the IRMA protocol to `irmaclient` and `irmaserver`
  - Irma servers can opt-in to SD-JWT VC issuance by configuring issuer certificates and private keys for SD-JWT VC
  - SD-JWT VCs are issued in batches of which the size is specified in the issuance request
  - SD-JWT VCs contain key binding public keys for which the private key is stored securely on the client
    - These holder/key binding public keys are provided to the issuer's irma server by the client during the commitments POST request
  - SD-JWT VC issuers are verified via certificates on the new Yivi trust lists, permissions are checked on the client via a custom json field in the certificates
  - Old `Client` was renamed to `IrmaClient` and was wrapped in new `Client` struct together with new `OpenID4VPClient`
- Add support for disclosing SD-JWT VC credentials over the OpenID4VP 1.0 protocol to `irmaclient`
  - Supports both `direct_post` and `direct_post.jwt` response modes
  - Supports DCQL queries for credentials that can be found in the schemes, specified by `vct_values`
  - Supports `x509_san_dns` client identifier prefix
  - Verifiers are trusted via x509 certificates on the new Yivi trust lists, attribute permissions are checked on the client via a custom json field in these certificates

### Fix
- Solve issue that made log logo paths invalid on iOS after each update/recompilation

### Security
 - Fix for [CVE GHSA-pv8v-c99h-c5q4](https://github.com/privacybydesign/irmago/security/advisories/GHSA-pv8v-c99h-c5q4) (Next session functionality can be used to do sessions on irma server without proper permissions)

## [0.18.1] - 2025-04-10
### Fix
- Bug in `irmaclient` that caused the pin challenge to always be called (at least) twice

## [0.18.0] - 2025-04-09
### Changed
- Download schemes from `https://schemes.yivi.app/` instead of `https://privacybydesign.foundation/schememanager/`

  Note: if the scheme auto-update mechanism is enabled in your `irma server` (enabled by default), please make sure outgoing
  network traffic is allowed from your `irma server` to schemes.yivi.app (51.158.130.42) and privacybydesign.foundation (37.97.206.70)

## [0.17.1] - 2025-04-01
### Changed
- Make keyshare pin challenge more resilient by retrying when `pin_challengeresponse` fails due to a server conflict

### Security
- Update github.com/golang-jwt/jwt/v4 from 4.5.1 to 4.5.2

## [0.17.0] - 2025-03-14
### Added
- Option to generate and use scheme private keys encrypted with a passphrase

### Changed
- Use golang version 1.23
- Make keyshare protocol more resilient by retrying when `getResponse` fails due to a server conflict

### Fixed
- Key ID not being set correctly in keyshare JWTs
- Infinite loop in SSE go-routine in sessions with pairing mode enabled

### Security
- Update go toolchain to 1.23.5
- Update golang.org/x/crypto to 0.32.0

### Internal
- Fix docker-compose not being available for test jobs in default GH Actions runner image
- Dev: make sure keyshare and myirmaserver don't crash when using example configuration
- Add arm64 docker build to delivery workflow

## [0.16.0] - 2024-07-17
### Added
- Option to configure client mtls redis cert and key for `irma server`, `irma keyshare server` and `irma keyshare myirmaserver`

### Security
- Update go toolchain to 1.22.5
- Update github.com/hashicorp/go-retryablehttp dependency from 0.7.1 to 0.7.7

### Internal
- Phase out deprecated GitHub Actions packages

## [0.15.2] - 2024-03-19
### Security
- Update go toolchain to 1.22.1
- Update github.com/jackc/pgx/v5 dependency from 5.4.3 to 5.5.4

### Internal
- Fix sqlserver tests in GitHub Actions workflow

## [0.15.1] - 2023-12-18
### Fixed
- `RemoveScheme` function in `irmaclient` already stripping storage before checking whether the scheme is in assets

### Security
- Update go toolchain to 1.21.5

## [0.15.0] - 2023-12-11
### Added
- Support for Redis in Sentinel mode
- Redis support for `irma keyshare server` and `irma keyshare myirmaserver`
- `/health` endpoint for `irma server`, `irma keyshare server` and `irma keyshare myirmaserver`
- `RemoveRequestorScheme` function in `irmaclient` to remove a requestor scheme from the `irma_configuration` directory

### Changed
- Using optimistic locking in the `irma server` instead of pessimistic locking
- `storage-fallback-key-file` option of `irma keyshare server` being replaced by `storage-fallback-keys-dir` option

### Fixed
- HTTP cookies not stored in `irmaclient` when received from a `Set-Cookie` header
- Invalid hostname specified in MX record bypasses e-mail address revalidation
- Background revocation tasks not stopped when closing an `irmaclient`
- `RemoveScheme` function in `irmaclient` not deleting issuer schemes without a keyshare server ([#260](https://github.com/privacybydesign/irmago/issues/260))

### Internal
- Fixed issue with expired `irma-demo.MijnOverheid` key in testdata
- Always use testdata of current branch for integration-test jobs in GitHub Actions workflow

## [0.14.2] - 2023-10-25
### Fixed
- IRMA session gets stuck in communicating status when user is requested to confirm PIN in `irmaclient`

## [0.14.1] - 2023-10-18
### Fixed
- Improve stability of database drivers by bumping their versions

### Security
- Use Go toolchain version 1.21.3 for building `irma` CLI tool

### Internal
- Fixed failing tests due to expired test.test2 idemix key

## [0.14.0] - 2023-10-02
Note for users of the `irmaclient` package (e.g. maintainers of the [Yivi app](https://github.com/privacybydesign/irmamobile)): the `KeyshareVerifyPin` function requires the renewal endpoint for the keyshare attribute to be present. Therefore, this version should first be deployed on keyshare servers before the client side can be upgraded.
### Added
- Option `skipExpiryCheck` in disclosure requests to allow disclosure of expired credentials (e.g. `"skipExpiryCheck": ["irma-demo.sidn-pbdf.email"]`)
- Option `host` in session request to overrule host name in IRMA QR if permission has been granted (see below)
  ```
  {
    "@context": "https://irma.app/ld/request/disclosure/v2",
    "host": "irma.example.com",
    "disclose": ...
  }
  ```
  This leads to the following session package:
  ```
  {
    "token":"KzxuWKwL5KGLKr4uerws",
    "sessionPtr": {"u":"https://irma.example.com/irma/session/ysDohpoySavbHAUDjmpz","irmaqr":"disclosing"},
    "frontendRequest": {
      "authorization":"qGrMmL8UZwZ88Sq8gobV",
      "minProtocolVersion": "1.0",
      "maxProtocolVersion": "1.1"
    }
  }
  ```
- Permission option `host_perms` in the requestor configuration to specify which values a requestor may use for the `host` option in session requests
  ```
  {
    "requestors": {
        "myapp": {
            "disclose_perms": [ "irma-demo.MijnOverheid.ageLower.over18" ],
            "sign_perms": [ "irma-demo.MijnOverheid.ageLower.*" ],
            "issue_perms": [ "irma-demo.MijnOverheid.ageLower" ],
            "host_perms": ["*.example.com"]
            "auth_method": "token",
            "key": "eGE2PSomOT84amVVdTU"
        }
    }
  }
  ```
- Renewal endpoint for keyshare attribute in the keyshare server (`/users/renewKeyshareAttribute`)
- Keyshare server /api/v2/prove/... endpoints for the new keyshare protocol

### Changed
- `KeyshareVerifyPin` function in irmaclient ensures the keyshare attribute is valid
- Sending the account expiry email is done when user has only valid e-mail addresses
- Strip unnecessary details from database errors

### Fixed
- User account expiry continues when one or more e-mail addresses are marked for revalidation

## [0.13.3] - 2023-09-06
### Fixed
- Auto-update mechanism of IRMA configuration not working in ghcr.io/privacybydesign/irma Docker container
- Panics occur when the timestamp file does not exist in a scheme directory

## [0.13.2] - 2023-08-22
### Changed
- Remove mail header 'Content-Transfer-Encoding: binary'
  The header gets converted to 'Content-Transfer-Encoding: quoted-printable' causing 'arc=fail (body hash mismatch)' with gmail

## [0.13.1] - 2023-08-16
### Fixed
- Invalid amount of arguments in query scan when e-mail revalidation is disabled

## [0.13.0] - 2023-08-10
### Added
- E-mail address revalidation, addressing issues where user's e-mail addresses can be (temporary) invalid
- Publish the Docker image of the `irma` CLI tool on ghcr.io/privacybydesign/irma
- Support for revocation db type `sqlserver` (Microsoft SQL Server)

### Changed
- Use separate application user in Dockerfile for entrypoint
- Rename RevocationStorage's UpdateLatest function to LatestUpdates. This name better fits its behaviour. The functionality stays the same.
- Validate revocation witness before revocation update is applied
- RevocationStorage's EnableRevocation function does not return an error anymore if it has been enabled already
- Use a Docker image created from scratch as base for the Dockerfile
- Custom WrapErrorPrefix function that respects the error's type
- Log info message of irma.SessionError errors

As part of e-mail address revalidation:
- `VerifyMXRecord` incorporates a check to see if there is an active network connection
- MyIrma server: `/user` returns an additional field `revalidate_in_progress` in the JSON response body, indicating whether the e-mail address is being revalidated or not
- MyIrma server: `/user/delete` and `/email/remove` return a 500 status code and `REVALIDATE_EMAIL` error type if one or more e-mail addresses of the user are invalid

**Note:** Enabling e-mail address revalidation requires a change in the database schema. In order to do this please add the `revalidate_on` column of type `bigint` to the `irma.emails` table. See the [schema](https://github.com/privacybydesign/irmago/tree/master/server/keyshare/schema.sql#L50) file. Otherwise e-mail address revalidation is disabled and there will not be a breaking change.

### Fixed
- Race conditions in database logic of revocation storage
- `irma scheme verify` not detecting missing files in index
- Scheme verification/signing does not reject credentials with invalid revocation settings
- Write transactions within memory implementation of revocation storage may lead to unintended changes

### Removed
- Superfluous openssl package in Dockerfile

### Security
- Let IRMA servers by default reject IRMA/Yivi apps that don't support pairing codes (IRMA protocol version <= 2.7)

**Note:** This is an important security update for issuers to make sure that pairing codes cannot be circumvented.
IRMA apps that don't support pairing codes should not be in circulation anymore, so this change won't affect users.
Yivi apps have always supported pairing codes.

### Internal
- Linter switch from golint to staticcheck
- Use Postgres 15 for unit and component tests

## [0.12.6] - 2023-05-31
### Fixed
- Legacy endpoints of keyshare server return 403 status codes when database is down

## [0.12.5] - 2023-05-25

### Changed
- Print warning in logs if log verbosity is set to trace

### Fixed
- LogoPath is incorrect after a requestor scheme update
- Parallel sessions may fail when one of the sessions requires pairing

## [0.12.4] - 2023-05-16

### Fixed
- Revocation related log messages occur twice or have wrong severity in irmaclient

## [0.12.3] - 2023-05-12

### Changed
- Move checks for missing schemes from scheme parsing to storage parsing
- Ignore directories in irma_configuration directory that don't contain a scheme

### Fixed
- Stability issues in transport logic
- Server and client timeouts are out-of-sync
- Keyshare server returns 403 status codes when database is down
- Handling invalid email or login tokens gives different status codes in different contexts
- CopyDirectory function may fail when relative paths are used

### Security
- Improve randomness of session tokens and pairing codes

### Internal
- Change contact e-mail address in README to Yivi
- Phase out deprecated io/ioutil library

## [0.12.2] - 2023-03-22

### Fixed
- Keyshare token cached by irmaclient becomes invalid when PIN is changed

## [0.12.1] - 2023-02-28

### Fixed
- Disable CGO bindings for release artifacts to natively support Alpine

## [0.12.0] - 2023-02-28

### Added
- Separate timeout constraints for the amount of time a client has to complete a session (`MaxSessionLifetime`) and a requestor has to retrieve the session result from the server (`SessionResultLifetime`)
- In `keyshareserver`, `EmailTokenValidity` allows configuring how long an e-mail address validation token is valid

### Changed
 - The maximum time a client has to complete a session is increased in `MaxSessionLifetime` to 15 minutes by default
 - `myirmaserver` returns a more appropriate `403 Invalid token` error response during e-mail address verification at `/verify` when the provided token is expired and therefore not found in the database.

### Security
 - Update dependency `golang.org/x/net` to v0.7.0, addressing [CVE-2022-27664](https://nvd.nist.gov/vuln/detail/CVE-2022-27664)
 - Update dependency `golang.org/x/text/language` to v0.7.0, addressing [CVE-2022-32149](https://nvd.nist.gov/vuln/detail/CVE-2022-32149)

## [0.11.2] - 2023-02-13

### Fixed
 - ParseFolder cannot handle legacy oldscheme and tempscheme directories

## [0.11.1] - 2023-01-19

### Added
 - Missing support for keyshare server endpoint versioning

### Removed
 - Superfluous endpoint versioning in HTTP response headers of keyshare server

### Fixed
 - Race condition in revocation gocron instance due to jobs that start too soon
 - Deal with leftover temp dirs in scheme folder if updating is aborted
 - Scheme index updates within UpdateSchemes should be written to disk atomically
 - InstallScheme does not undo its changes when an error occurs
 - Test: race condition in StartBadHttpServer handler

## [0.11.0] - 2022-11-10

### Added
- Storage encryption functionality in `irmaclient`
- Challenge response user authentication using ECDSA key pair between `irma keyshare server` and `irmaclient`
- Support for multiple keyshare servers in `irmaclient` to improve testability
- Extra configuration options for postgres database connections in `irma keyshare server` and `irma keyshare myirmaserver`
- Rate limiting on sending emails to the same email address in a short time period by `irma keyshare server` and `irma keyshare myirmaserver`
- Middleware to catch panics in HTTP handlers and return a 500 error instead
- Performance test scripts for `irma keyshare server`
- MyIRMA webclient service in docker-compose.yml to improve development setup
- CI status check for i386 architecture
- CodeQL static code analysis
- Contact details for support, discussion and responsible disclosure
- VSCode launch configuration

### Changed
- BREAKING: `irmaclient` requires minimum `irma keyshare server` version 0.11.0 (due to challenge response user authentication).
  `irma keyshare server` does support older `irmaclient` versions.
- Updated dependencies
- Phased out unmaintained jasonlvhit/gocron library and migrated to go-co-op/gocron
- Made gocron usage more consistent
- Phased out legacy `irmaclient` log entry formats
- Consistently specify charset in HTTP responses when the content type is `application/json`
- Applied the code convention changes of golang 1.19
- Always use the latest version of golang in GitHub status checks
- Improved input validation of email addresses
- Improved testability of revoked credentials
- Use new URL of timestamp server (atumd) in unit tests

### Fixed
- Broken retrieval of user from postgres database by `irma keyshare server`
- Also remove legacy file storage when calling `RemoveStorage` in `irmaclient`
- `irma keyshare myirmaserver` requests login and email attribute options as conjunction instead of as disjunction
- Chained sessions did not work due to bug in `irma keyshare server`
- Attributes from multiple issuer schemes could not be mixed in chained sessions
- Panics occurred during error handling in `irmaclient`
- Avoid gocron panics in revocation code during `irmaclient` startup
- Do not abort `irma keyshare tasks` run while looping over expired accounts and finding an invalid email address (quick fix)
- Use subject value instead of file path value as email subject in account removed email of `irma keyshare myirmaserver`
- Requestor JWT authentication did not work at revocation endpoint of `irma server`
- Concurrency issues in `irmaclient.Client.credential()` and `irma.Configuration.parseKeysFolder()`

### Security
- Prevent that a user can detect whether a certain email address is registered at `irma keyshare server` and `irma keyshare myirmaserver` (vulnerable versions have never been live in production)


## [0.10.0] - 2022-03-09

### Added
- `irma session` now supports [static sessions](https://irma.app/docs/irma-server/#static-irma-qrs) and can start sessions from a [session package](https://irma.app/docs/api-irma-server/#post-session)
- (Requestor) schemes and their contents can now [specify their languages](https://github.com/privacybydesign/irmago/pull/194/), which `irma scheme verify` takes into account
- Add Apple Silicon builds in releases

### Fixed
- Mutex deadlock that could freeze the server when using chained sessions
- Bug that would prevent warnings on 4xx and 5xx responses from showing when not in verbose/debug mode


## [0.9.0] - 2021-12-17

### Added

* Support for [stateless IRMA server using Redis](https://irma.app/docs/stateless)
* Added Dockerfile and docker-compose files for running `irma`, the unit tests, and/or the services required by the unit tests

### Changes

* Improve error messages of IRMA server in case of invalid session requests

### Fixed

* Fix panic when an issuance request contains a credential ID consisting of less than three parts
* Ensure session handler callback function, when specified, is also called when session expires
* Several small bugs in MyIRMA backend server


## [0.8.0] - 2021-07-27
This release contains several large new features. In particular, the shoulder surf prevention feature brings a number of breaking changes in the API, mainly within the `irmaserver` package.

### Added

* Support for [chained IRMA sessions](https://irma.app/docs/next/chained-sessions)
* A Go rewrite of the [keyshare server](https://irma.app/docs/overview/#irma-pin-codes-using-the-keyshare-server) (see the new `irma keyshare` commands), succeeding the [now deprecated `irma_keyshare_server`](https://github.com/credentials/irma_keyshare_server)
* Added a function `SessionStatus` in the `irmaserver` package returning a channel with status updates of an IRMA session
* Added `--api-prefix` parameter to the IRMA server for prefixing its API endpoints with a string
* Added `--max-session-lifetime` parameter to the IRMA server for setting the session expiry (default 5 minutes)
* Shoulder surfing prevention: support for device pairing to prevent shoulder surfing (i.e. make it impossible for someone in close physical proximity to a user to scan the QR code that was meant for the user)
  * Introduced new endpoints used by the [frontend](https://github.com/privacybydesign/irma-frontend-packages) to manage device pairing
  * The API of the `irmaserver` package has two new functions `SetFrontendOptions` and `PairingCompleted`
  * A new server status `"PAIRING"` is introduced

### Changes

* During scheme parsing, folders found in the scheme folder not present in the assets (when configured) are removed
* Shoulder surfing prevention:
  * The `server.SessionPackage` struct now contains a new struct `FrontendRequest` of type `*irma.FrontendSessionRequest`, containing the following:
    * A boolean `PairingRecommended` (named `pairingHint` when being marshalled to JSON) that is set to true when pairing is recommended for that session, as indication to the frontend
    * An `Authorization` token used by the frontend to set pairing options
    * Fields called `MinProtocolVersion` and `MaxProtocolVersion` indicating the frontend protocol version range supported by the IRMA server.
  * The return values of the `StartSession` function from the API of the `irmaserver` package have changed as follows:
    * The type of the second return parameter, the requestor token, has changed from `string` to `irma.RequestorToken`
    * A new return parameter (type `*irma.FrontendSessionRequest`) has been added containing the frontend pairing settings (corresponding to the `FrontendRequest` field in the `server.SessionPackage` mentioned above)
  * The `token` parameter, as used by most functions in the API of the `irmaserver` package, now has the type `irma.RequestorToken`
  * The `server.Status` type has been moved to `irma.ServerStatus`; the related constants are also moved, e.g. from `server.StatusInitialized` to `irma.ServerStatusInitialized`

### Fixed
* Bug causing IRMA server startup to fail when revocation is enabled
* Bug causing sessions to fail when revocation is enabled and the issuer has multiple revocation-enabled keys
* Incorrectly cased SQL column name used in revocation data lookup
* Bug causing issuance time in revocation records being floored to credential validity epoch boundaries
* Fixed bug when loading private key of issuer if another issuer with a similar name exists

## [0.7.0] - 2021-03-17
### Fixed
* Bug causing scheme updating to fail if OS temp dir is on other file system than the schemes
* Prevent session result JWTs from being expired immediately if no expiry is specified is set in the session request; instead in that case they expire after two minutes
* When POSTing session result to the `callbackUrl` specified in session request, set `Content-Type` to `application/json` for JSON messages
* Fixed panic during scheme downloading on Windows
* Correctly decode randomblind attributes when verifying disclosures/signatures

### Added
* Add request URL to log entry when IRMA server encounters an error (404 or otherwise) during HTTP request handling
* Add flag `--allow-unsigned-callbacks` to IRMA server to allow `callbackUrl` in session requests when no JWT private key is installed
* Add flag `--augment-client-return-url` to IRMA server to enable augmenting client return URL with server session token as query parameter (needs to be additionally enabled in session requests)
* Add new `irma issuer keyprove` and `irma issuer keyverify` commands to generate and verify zero-knowledge proofs of correct generation of issuer private/public keypairs

### Changed
* Clarify warning and suppress stacktrace in IRMA server log entry in case `/statusevents` is hit while SSE is disabled
* Force Unix (LF) line endings in schemes during scheme signing for consistency
* Moved revocation commands from `irma issuer revocation` to just `irma issuer`

## [0.6.1] - 2020-12-15
### Changed
* Change endpoint to which [IRMA server admin email address](https://irma.app/docs/email/) is sent and include IRMA server version number

### Fixed
* Bug that could cause schemes on disk to enter an inconsistent state, causing IRMA server to refuse to startup
* Nil deref during IRMA server startup in case local IP address failed to be determined
* Bug causing requestor scheme updating to fail

## [0.6.0] - 2020-10-20
### Added
* Support for "randomblind" attributes (if enabled in the scheme), for e.g. election use cases: attributes containing large random numbers issued in such a way that 1) the issuer does not learn their value while still providing a valid signature over the credential containing the attributes, and 2) the attribute value will be unequal to all previously issued randomblind attributes with overwhelming probability. Once issued, these attributes can be disclosed normally (i.e., only the issuance protocol is different for these attributes).
* Initial support (currently limited to issuing sessions) in `irmaclient` for "pretty verifier names": human-readable and translatable requestor names to show in the IRMA app during a session to identify the requestor, instead of just a hostname, defined in a new scheme type called "requestor schemes" (e.g. https://github.com/privacybydesign/pbdf-requestors)

### Changed
* Renamed and refactored several (mostly internal) functions dealing with installing, parsing and updating schemes, to support both scheme types (normal schemes as well as requestor schemes)
* `irmaclient` now includes suggestions for non-singletons in the disclosure candidates during sessions, like it does for singletons not in the user's wallet

### Fixed
* Bug that would cause the IRMA server to log required values of attributes to be disclosed, when logging the session request
* Bug in `irmaclient` leading to the wrong error message in case of bad internet connection

## [0.5.1] - 2020-09-17
### Changed
* Switched to forks of `cobra`, `viper`, and `pflag` so that depending packages don't require `replace` directives in their go.mod

## [0.5.0] - 2020-09-03
### Fixed
* Bug in scheme update mechanism leading to `UNKNOWN_PUBLIC_KEY` errors when new public keys have been added to the scheme
* Several bugfixes in `irmaclient`

## [0.5.0-rc.5] - 2020-08-11
### Added
* Support disabling scheme auto-updating in `irma session`
* Support revocation in `irma session` and `irma request`

### Fixed
* Fixed bug in server configuration defaults when enabling production mode through config file
* Fixed bug that would kill server-sent events (SSE) connections after several seconds
* Fixed invalidation of local copy of index if local scheme is newer than the remote one
* Ignore absence of FAQ fields and category in credentialtypes during `irma scheme verify`

### Security
* Abort issuance or disclosure in server and client in case of expired public keys

## [0.5.0-rc.4] - 2020-06-18
### Added
* Support for parallel sessions (e.g. issuance of missing credentials during a disclosure session) to `irmaclient`

### Fixed
* Several minor bugs in `irmaclient`

### Security
* The IRMA server now keeps issuer private keys in memory as short as possible


## [0.5.0-rc.3] - 2020-05-14
### Added
* Various additions to `irmaclient` for the [new IRMA app](https://github.com/privacybydesign/irmamobile), among others:
  * Several new fields in `irma.CredentialType` for specifying e.g. help messages and card colors
  * Added developer mode enabling non-HTTPS connections to IRMA servers for local testing (see below)

### Fixed
* Problems with `--privkeys` option to IRMA server

### Security
* `irma` command, IRMA server and `irmaclient` will now enforce HTTPS for outgoing connections whenever possible
* Update supported TLS ciphers and curves for IRMA server
* Fixed potential bug allowing MitM attacker to arbitrarily change installed schemes
* Fixed potential DoS attack in IRMA server endpoints (sending it large amounts of data or keeping connections open indefinitely)


## [0.5.0-rc.2] - 2020-04-21

### Added
* Revocation of previously issued credentials (see [documentation](https://irma.app/docs/revocation/))
* Support HTTP/2 in IRMA server and app
* Option `--skip-permission-keys-check` to IRMA server disabling checking that all required private keys are present in the server configuration

### Changed
* Use go modules instead of `dep` for tracking and locking dependencies

### Fixed
* `irmaserver` HTTP handler returns 404 an 405 as JSON error messages as expected
* Consistently use a docopt/git/aptitude like format for usage sections in help of `irma` subcommands
* Incorrect default value of `--url` flag to `irma session` subcommand
* IRMA server no longer allows nonsensical wildcard usage in [requestor permissions](https://irma.app/docs/irma-server/#permissions)

### Security
* `irma issuer keygen` now has default keylength 2048
* Added various sanity checks to files and file paths
* Fixed potential scheme downgrade attack when installing/updating schemes in MitM scenarios


## [0.5.0-rc.1] - 2020-03-03
### Added
- Include `clientReturnURL` in session request

### Changed
- All (translated) names of issuers and credential types of demo schemes (i.e. `irma-demo`) must now start with `Demo `
- `irmaclient` now uses bbolt for storage
- When the `irmaclient` receives a credential identical to another older one, the older one is overwritten
- Scheme signing and verification now supports symlinks

### Fixed
- Unclear error message when the request's `Content-Type` HTTP header is not properly set
- Unclear error message when non-optional attributes are missing in issuance request
- Scheme verification now ignores deprecated issuers and keys and ignores missing IssueURL tags in credential types
- `irma server` no longer crashes at startup if no network interfaces are available
- Various bugs in `irma server` configuration


## [0.4.1] - 2019-10-15
### Changed
- Renamed `irma session` flag `--authmethod` to `--auth-method` for consistency with server `Configuration` struct

### Fixed
- Fix bug that would prevent downloading of demo private keys of demo schemes on server startup and scheme updating
- `irma server` now respects the `disable_schemes_update` option like the `irmaserver` library (#63)
- Other small fixes


## [0.4.0] - 2019-10-09
### Added
- New irma server feature: static (e.g. printable) QRs that start preconfigured sessions, see [documentation](https://irma.app/docs/irma-server/#static-irma-qrs)
- irma server now returns attribute issuance time to the requestor after the session has finished

### Fixed
- Hopefully fix “unknown or expired session” errors that would sometimes occur in the IRMA app in bad network conditions
- Combined issuance-disclosure requests with two schemes one of which has a keyshare server now work as expected
- Various other bugfixes

[1.2.0]: https://github.com/privacybydesign/irmago/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/privacybydesign/irmago/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/privacybydesign/irmago/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/privacybydesign/irmago/compare/v0.19.2...v1.0.0
[0.19.2]: https://github.com/privacybydesign/irmago/compare/v0.19.1...v0.19.2
[0.19.1]: https://github.com/privacybydesign/irmago/compare/v0.19.0...v0.19.1
[0.19.0]: https://github.com/privacybydesign/irmago/compare/v0.18.1...v0.19.0
[0.18.1]: https://github.com/privacybydesign/irmago/compare/v0.18.0...v0.18.1
[0.18.0]: https://github.com/privacybydesign/irmago/compare/v0.17.1...v0.18.0
[0.17.1]: https://github.com/privacybydesign/irmago/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/privacybydesign/irmago/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/privacybydesign/irmago/compare/v0.15.2...v0.16.0
[0.15.2]: https://github.com/privacybydesign/irmago/compare/v0.15.1...v0.15.2
[0.15.1]: https://github.com/privacybydesign/irmago/compare/v0.15.0...v0.15.1
[0.15.0]: https://github.com/privacybydesign/irmago/compare/v0.14.2...v0.15.0
[0.14.2]: https://github.com/privacybydesign/irmago/compare/v0.14.1...v0.14.2
[0.14.1]: https://github.com/privacybydesign/irmago/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/privacybydesign/irmago/compare/v0.13.3...v0.14.0
[0.13.3]: https://github.com/privacybydesign/irmago/compare/v0.13.2...v0.13.3
[0.13.2]: https://github.com/privacybydesign/irmago/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/privacybydesign/irmago/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/privacybydesign/irmago/compare/v0.12.6...v0.13.0
[0.12.6]: https://github.com/privacybydesign/irmago/compare/v0.12.5...v0.12.6
[0.12.5]: https://github.com/privacybydesign/irmago/compare/v0.12.4...v0.12.5
[0.12.4]: https://github.com/privacybydesign/irmago/compare/v0.12.3...v0.12.4
[0.12.3]: https://github.com/privacybydesign/irmago/compare/v0.12.2...v0.12.3
[0.12.2]: https://github.com/privacybydesign/irmago/compare/v0.12.1...v0.12.2
[0.12.1]: https://github.com/privacybydesign/irmago/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/privacybydesign/irmago/compare/v0.11.2...v0.12.0
[0.11.2]: https://github.com/privacybydesign/irmago/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/privacybydesign/irmago/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/privacybydesign/irmago/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/privacybydesign/irmago/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/privacybydesign/irmago/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/privacybydesign/irmago/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/privacybydesign/irmago/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/privacybydesign/irmago/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/privacybydesign/irmago/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/privacybydesign/irmago/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.5...v0.5.0
[0.5.0-rc.5]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.4...v0.5.0-rc.5
[0.5.0-rc.4]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.3...v0.5.0-rc.4
[0.5.0-rc.3]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.2...v0.5.0-rc.3
[0.5.0-rc.2]: https://github.com/privacybydesign/irmago/compare/v0.5.0-rc.1...v0.5.0-rc.2
[0.5.0-rc.1]: https://github.com/privacybydesign/irmago/compare/v0.4.1...v0.5.0-rc.1
[0.4.1]: https://github.com/privacybydesign/irmago/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/privacybydesign/irmago/tree/v0.4.0
