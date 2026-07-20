# ISO/IEC 18013-5 mdoc support in irmago

Implementation plan for landing the `mso_mdoc` credential format in irmago, covering
**issuance to the wallet via OpenID4VCI** and **disclosure via OpenID4VP (DCQL)**.

Reference implementation used throughout this plan: [multipaz](https://github.com/openwallet-foundation-labs/identity-credential)
(local checkout: `~/code/multipaz`). Relevant specs:

- ISO/IEC 18013-5:2021 — mdoc data model, MSO, DeviceResponse, selective disclosure
- ISO/IEC TS 18013-7 — mdoc over OpenID4VP (SessionTranscript / OID4VP handover)
- OpenID4VCI — `mso_mdoc` credential configuration format
- OpenID4VP — DCQL queries with format `mso_mdoc`, vp_token encoding
- RFC 9052/9053 (COSE), RFC 8949 (CBOR)

---

## 1. Current state of irmago

The `openid4vci` branch already contains most of the *format-agnostic* plumbing. mdoc is
recognized but not implemented anywhere:

| Area | Status | Location |
|---|---|---|
| Format identifier `mso_mdoc` | exists | `eudi/metadata/metadata.go:142` |
| Client credential format enum | only `dc+sd-jwt`, `idemix` | `common/clientmodels/enums.go:26` |
| OpenID4VCI metadata validation | `MdocFormatVerifier` is a **stub** (accepts anything); `ValidateSupportedFeatures()` **rejects** anything that is not SD-JWT VC | `eudi/openid4vci/metadata_validators.go:161,176` |
| OpenID4VP vp_formats | `MdocClientMedataVpFormat` (COSE alg list) parsed but unused | `eudi/openid4vp/openid4vp.go:47` |
| DCQL dispatch | pluggable `DcqlCredentialQueryHandler` interface; only SD-JWT handlers registered | `eudi/openid4vp/dcql/credential_query_handler.go:36`, `eudi/openid4vp/client.go:57` |
| Credential storage | GORM models with explicit TODO for polymorphic multi-format support | `eudi/storage/db/models/credentials.go:11` |
| Holder/device keys | ECDSA P-256 key storage keyed by JWK thumbprint, reusable as-is | `eudi/storage/db/holderbindingkey_store.go`, `irma/irmaclient/keybinding_storage.go` |
| CBOR | `fxamacker/cbor v1.5.1` (legacy, used for revocation) | `go.mod` |
| COSE | none | — |
| Integration tests | dockerized issuers/verifiers (`docker-compose.yml`: veramo OID4VCI issuer, python EUDI PID issuer, OID4VP verifier) driven from `internal/sessiontest/` | `internal/sessiontest/openid4vci_issuance_test.go`, `openid4vp_*_test.go` |

The SD-JWT VC integration (`eudi/credentials/sdjwtvc/`, `eudi/openid4vp/eudi_sdjwt_dcql/`)
is the architectural precedent: a self-contained credential-format package plus a
DCQL handler, wired into the client through existing interfaces.

## 2. Scope and non-goals

**In scope (wallet/holder side):**

- Receiving `mso_mdoc` credentials via OpenID4VCI (pre-authorized + authorization code
  flows, batch issuance) and verifying them against trust anchors before storage.
- Storing mdoc credentials and their device keys alongside SD-JWT VCs.
- Answering DCQL `mso_mdoc` queries and producing a `DeviceResponse` in a vp_token
  (response modes `direct_post` and `direct_post.jwt`), with selective disclosure and
  `deviceSignature` device auth.
- Enough *issuer/verifier-side* mdoc code to build test fixtures and run hermetic
  end-to-end tests in-process (this code is production-quality and may later back a
  Yivi mdoc issuer, but exposing a public issuer API is not a goal of this plan).

**Out of scope (for now):**

- `deviceMac` device auth (requires ECDH with an ephemeral reader key; OpenID4VP flows
  in practice use `deviceSignature`). The data model will represent both variants.
- Proximity flows (BLE/NFC device engagement, session encryption from 18013-5 §9.1.1).
- Digital Credentials API (`dc_api` response modes / `OpenID4VPDCAPIHandover`) — the
  handover construction is designed so this can be added later.
- Zero-knowledge variants (`mso_mdoc_zk`).
- mdoc revocation/status lists (follow-up; MSO `status` field is parsed and preserved).

## 3. Key design decisions

1. **Dependencies.** Add `github.com/fxamacker/cbor/v2` (different import path than the
   existing v1, so both coexist; v2 is required for proper tag-24 and deterministic
   encoding support) and `github.com/veraison/go-cose` for `COSE_Sign1`. `COSE_Key` and
   (later) `COSE_Mac0` are small enough to implement in-repo on top of cbor/v2.

2. **New package `eudi/credentials/mdoc/`**, sibling of `sdjwtvc/`, containing the full
   data model, encoding, building (issuer side), and verification (holder + verifier
   side). No dependency on OpenID4VCI/VP packages — those depend on it.

3. **Reuse the holder-binding key machinery** for mdoc device keys: same ECDSA P-256
   generation, same encrypted storage, same one-key-per-batch-instance model. The MSO's
   `deviceKeyInfo.deviceKey` is the COSE_Key form of the JWK that already goes into the
   OpenID4VCI proof JWT `cnf` claim — no new proof type needed.

4. **DCQL handler interface change.** `PrepareDisclosure(selections, nonce, clientId)`
   is insufficient for mdoc: the OID4VP `SessionTranscript` handover additionally needs
   `response_uri` and (for encrypted responses) the verifier's encryption JWK
   thumbprint. Extend the interface to pass a `DisclosureContext` struct instead of
   bare `nonce`/`clientId`. This is the only cross-format interface change required.

5. **Storage** follows the existing TODO in `eudi/storage/db/models/credentials.go`:
   add a `Format` discriminator to `CredentialBatch` / `IssuedCredentialInstance`, store
   the raw `IssuerSigned` CBOR in `RawCredential`, and store a processed claims
   projection (namespace → element → JSON value) for display/candidate matching, in the
   same spot where the processed SD-JWT payload lives today.

6. **SessionTranscript handover**: implement the structure used by current OpenID4VP
   drafts (multipaz "DRAFT_29" variant, `mdoc/response/MdocDocument.kt` +
   `openid/OpenID4VP.kt#openID4VPMsoMdoc`):

   ```
   HandoverInfo   = [ client_id, nonce, jwk_thumbprint | null, response_uri | null ]
   SessionTranscript = [ null, null, [ "OpenID4VPHandover", SHA-256(cbor(HandoverInfo)) ] ]
   ```

   Verify against the draft version irmago's verifiers actually implement during M6
   interop testing; the construction is isolated in one function so a draft-24 variant
   is a small addition if needed.

---

## 4. Milestones

Each milestone is independently mergeable, fully covered by automated tests, and does
not regress existing SD-JWT VC / idemix flows (CI gate: existing test suite stays green).

### M1 — CBOR/COSE foundation

**Deliverable:** low-level primitives every later milestone builds on.

- Add `fxamacker/cbor/v2` and `veraison/go-cose` to `go.mod`.
- `eudi/credentials/mdoc/cbor.go`: encode/decode helpers with the fixed cbor/v2
  `EncOptions`/`DecOptions` for 18013-5 (core deterministic-ish encoding, tag 24
  `EncodedCBOR` wrapper type `#6.24(bstr .cbor X)`, full-date tag 1004, tdate tag 0
  with RFC 3339 no-fractional-seconds UTC).
- `eudi/credentials/mdoc/cose.go`: `COSE_Key` (EC2/P-256 ⇄ `*ecdsa.PublicKey` ⇄ JWK),
  thin wrappers around go-cose `Sign1` for sign/verify with protected `alg` and
  unprotected `x5chain` (label 33) headers.

**Automated tests:**

- Round-trip tests for every helper; deterministic-encoding byte-equality tests.
- COSE_Sign1 sign/verify against fixed keys; cross-check one signature against a
  COSE example from RFC 9052 / an ISO 18013-5 Annex D test vector (multipaz keeps
  these in `multipaz/src/commonTest/.../mdoc/TestVectors.kt` — port the hex blobs).
- COSE_Key ⇄ JWK ⇄ ecdsa.PublicKey conversion fuzz/round-trip tests.

### M2 — mdoc data model: parsing and verification

**Deliverable:** `eudi/credentials/mdoc/` can parse and cryptographically verify an
mdoc produced by any conformant issuer. This is the holder's "check before storing"
capability and the core of any later verifier.

Types (mirroring multipaz `mdoc/mso/MobileSecurityObject.kt`,
`mdoc/issuersigned/IssuerSignedItem.kt`, `mdoc/response/DeviceResponse.kt`):

- `IssuerSignedItem` (digestID, random ≥16 bytes, elementIdentifier, elementValue) —
  **must preserve original encoded bytes** for digest recomputation.
- `IssuerNameSpaces`, `IssuerSigned` (`nameSpaces` + `issuerAuth` COSE_Sign1).
- `MobileSecurityObject` (version, digestAlgorithm, docType, valueDigests,
  deviceKeyInfo incl. keyAuthorizations, validityInfo, optional status).
- `Document`, `DeviceSigned`, `DeviceAuth` (signature | mac), `DeviceResponse`.

Verification (`Verifier` type, mirroring multipaz `DeviceResponse.verify`):

1. issuerAuth COSE_Sign1 signature with leaf cert from x5chain;
2. x5chain validation to a configured IACA trust anchor set — reuse/extend the existing
   `eudi/trustmodel.go` / `trustanchors.go` X.509 infrastructure;
3. recomputed digests of all present IssuerSignedItems == MSO valueDigests entries;
4. docType consistency, validityInfo window, digest algorithm allow-list;
5. (DeviceResponse only) DeviceAuth `deviceSignature` over `DeviceAuthentication =
   ["DeviceAuthentication", SessionTranscript, docType, #6.24(DeviceNameSpaces)]`
   against the MSO device key.

**Automated tests:**

- Parse + verify the ISO 18013-5 Annex D mDL test vector (issuer-signed structure and
  full DeviceResponse, including the known SessionTranscript) — ported from multipaz.
- Negative tests: tampered element value (digest mismatch), wrong cert chain, expired
  validityInfo, unknown digest algorithm, duplicate digestIDs, salt < 16 bytes.

### M3 — mdoc building: issuer and device sides

**Deliverable:** the ability to *create* valid mdocs and DeviceResponses in-process.
Required for hermetic tests of M4–M6; doubles as the seed of a future Yivi mdoc issuer.

- `Builder` for `IssuerNameSpaces`: shuffled random digestIDs, crypto/rand 16-byte
  salts (multipaz `IssuerNamespaces.Builder`).
- MSO construction from a built namespace set + device public key + validity window;
  issuerAuth signing with a DS certificate (x5chain in unprotected header).
- Test PKI helpers: generate IACA root + DS certificate with the 18013-5 profile
  (multipaz `MdocUtil.generateIacaCertificate` / `generateDsCertificate`) under
  `eudi/credentials/mdoc/testutil/` or `internal/`.
- `DeviceResponse` builder: selective disclosure by filtering IssuerSignedItems on
  requested `[namespace, element]` pairs; `DeviceAuthentication` assembly;
  `deviceSignature` with a device private key; SessionTranscript taken as an opaque
  input (handover construction comes in M6).

**Automated tests:**

- Full in-process round trip: build → sign → encode → decode → verify (M2 verifier),
  for single- and multi-namespace documents, with and without selective disclosure.
- Property test: any subset of disclosed elements verifies; any modified element fails.
- Byte-level golden-file test for one fixed-rand fixture to catch encoding drift.

### M4 — wallet storage and client surface

**Deliverable:** mdoc credentials are first-class citizens in wallet storage, credential
listing, and logs — installable via an internal API (no OpenID4VCI yet).

- `common/clientmodels/enums.go`: add `Format_MsoMdoc CredentialFormat = "mso_mdoc"`.
- `eudi/storage/db/models/credentials.go`: add the format discriminator and mdoc
  claims projection (the existing polymorphic-association TODO); GORM auto-migration
  covers schema evolution — add an explicit migration test from an SD-JWT-only DB.
- Device key storage: store/retrieve mdoc device keys through the existing
  `HolderBindingKey` model and `irmaclient` key-binding storage (keys are indexed by
  JWK thumbprint; the COSE_Key⇄JWK conversion from M1 makes this transparent).
- Map mdoc claims into `clientmodels.SelectableCredentialInstance` /
  `CredentialDescriptor` so the app UI can render them (claim path = `[namespace,
  element]`); wire into credential listing, deletion, and `eudi_logs`.
- `yivi eudi credentials` CLI (`yivi/cli/eudicli/credentials.go`) lists mdocs; add a
  `yivi eudi mdoc` inspect command analogous to `sdjwt.go` (decode + verify a
  base64url IssuerSigned/DeviceResponse blob).

**Automated tests:**

- Storage round-trip incl. encryption-at-rest, batch bookkeeping (`RemainingCount`),
  and migration-from-existing-DB test.
- Listing/log tests extended from the existing `eudi_logs_test.go` patterns, with
  fixtures generated by M3.

### M5 — OpenID4VCI issuance of mso_mdoc

**Deliverable:** the wallet completes pre-authorized-code and authorization-code flows
for an `mso_mdoc` credential configuration, verifies, and stores the result.

- Implement `MdocFormatVerifier.Verify()` for real
  (`eudi/openid4vci/metadata_validators.go:161`): require `doctype`, validate `claims`
  paths (`[namespace, element]`), check `cryptographic_binding_methods_supported`
  contains `cose_key` and signing algs are supported (ES256 first).
- Lift the SD-JWT-only gate in `ValidateSupportedFeatures()`
  (`metadata_validators.go:176`) for `mso_mdoc`.
- Credential response handling in `eudi/openid4vci/session.go`: for `mso_mdoc`,
  base64url-decode the credential into `IssuerSigned` CBOR, then:
  1. verify with M2 (issuer signature, IACA trust anchors, digests, validity);
  2. check MSO `deviceKeyInfo.deviceKey` equals the key sent in the proof JWT `cnf`;
  3. check docType matches the offered credential configuration;
  4. store via M4 (batch issuance: one device key + one mdoc per instance).
- Display/consent: derive the preview shown to the user from the credential
  configuration `claims` metadata + decoded element values.

**Automated tests:**

- Unit tests for the metadata validator (valid/invalid doctype, claims, binding
  methods) mirroring the existing SD-JWT validator tests.
- Hermetic integration test: a minimal in-process Go mdoc issuer (httptest server
  implementing the OID4VCI endpoints, minting credentials with M3) driven through the
  full client flow in `internal/sessiontest/openid4vci_issuance_test.go` style —
  pre-auth flow, auth-code flow, batch size 2, tampered-credential rejection,
  device-key-mismatch rejection.
- Interop test: enable the mdoc PID variant in the dockerized python EUDI issuer
  (`testdata/eudi-pid-issuer-py/conf/config_issuer_backend.yaml` currently notes
  "mdoc variants are not configured") and extend
  `internal/sessiontest/eudi_pid_python_issuer_test.go` to issue
  `eu.europa.ec.eudi.pid_mdoc`.
- `yivi eudi receive` works against both issuers (manual smoke; CLI flag coverage in
  unit tests).

### M6 — OpenID4VP disclosure of mso_mdoc

**Deliverable:** the wallet answers DCQL queries with format `mso_mdoc` end to end.

- **Interface change** (small, cross-format): extend
  `DcqlCredentialQueryHandler.PrepareDisclosure` to take a `DisclosureContext{Nonce,
  ClientId, ResponseUri, VerifierEncryptionJwk}`; update the two SD-JWT handlers
  (they ignore the new fields) and `eudi/openid4vp/client.go`.
- New package `eudi/openid4vp/mdoc_dcql/` implementing the handler:
  - `CanHandleCredentialQuery`: format `mso_mdoc` (+ `meta.doctype_value`).
  - `FindCandidates`: match stored mdocs by docType; map requested claim paths
    `[namespace, element]` against the stored claims projection; honor `claim_sets`.
  - `PrepareDisclosure`: build HandoverInfo/SessionTranscript (per §3.6), filter
    IssuerSignedItems per user selection, sign `DeviceAuthentication` with the stored
    device key, assemble `DeviceResponse` (one per query), base64url-encode into the
    vp_token map, emit `CredentialLogs`.
- Respect `client_metadata.vp_formats["mso_mdoc"].alg`; single-use instance
  bookkeeping identical to SD-JWT batches.
- Encrypted responses: `direct_post.jwt` already exists for SD-JWT
  (`eudi/openid4vp/response.go`); ensure the mdoc vp_token flows through it and the
  verifier's encryption JWK thumbprint lands in HandoverInfo.

**Automated tests:**

- Unit tests for query matching (docType, claims, claim_sets, multiple credentials,
  no-candidates → obtainable descriptors).
- Hermetic end-to-end test: in-process verifier (M2 + handover reconstruction)
  receives `direct_post` and `direct_post.jwt` responses; asserts issuer signature,
  digests, DeviceAuth against the reconstructed SessionTranscript, and that
  *undisclosed elements are absent*.
- Negative tests: wrong nonce / clientId / responseUri in transcript ⇒ DeviceAuth
  verification fails; replayed device signature with new nonce fails.
- Interop test against a dockerized external verifier supporting mdoc (extend
  `testdata/openid4vp-verifier` config, or add the multipaz / EUDI reference verifier
  to `docker-compose.yml`), in the style of `openid4vp_veramo_disclosure_test.go`.
- Combined query test: one DCQL query set requesting an SD-JWT VC *and* an mdoc in the
  same session.

### M7 — hardening, conformance, docs

**Deliverable:** release-ready quality gate.

- Run the OpenID Foundation OID4VP/OID4VCI conformance suite where applicable; record
  results in `docs/`.
- Fuzz tests on the CBOR parsers (`go test -fuzz` targets for `IssuerSigned`,
  `DeviceResponse`, `MSO`) — untrusted input enters here from issuers and requests.
- Cross-implementation fixture exchange: verify multipaz-generated DeviceResponses in
  irmago and vice versa (check a small fixture corpus into `testdata/eudi/mdoc/`).
- CHANGELOG entry, package-level docs in `eudi/credentials/mdoc/`, update branch docs.

---

## 5. Dependency graph

```
M1 (CBOR/COSE) ─→ M2 (parse/verify) ─→ M3 (build/sign) ─→ M4 (storage/client)
                                                            ├─→ M5 (OpenID4VCI)
                                                            └─→ M6 (OpenID4VP)  ─→ M7
M5 and M6 are independent of each other and can be developed in parallel.
```

## 6. Risks and open questions

- **OpenID4VP draft alignment.** The handover structure changed between drafts (origin
  vs client_id ordering, jwk thumbprint addition). Must pin against what the Yivi
  verifier stack and the chosen interop verifiers implement; isolated in one function.
- **cbor v1/v2 coexistence.** Two CBOR libraries in the module is acceptable but the
  legacy v1 usage (revocation) should eventually migrate; out of scope here.
- **`go-cose` API fit.** go-cose enforces its own header handling; if x5chain or raw
  R||S signature handling fights us, fall back to a minimal in-repo COSE_Sign1 over
  cbor/v2 (it is ~4 fields). Decide during M1.
- **Claims projection fidelity.** mdoc element values are CBOR (can include tdate,
  full-date, binary like portraits). The JSON projection for UI/DCQL matching must
  define a stable mapping (e.g. tag 1004 → `"YYYY-MM-DD"` string, bstr → base64url);
  DCQL value matching must follow OpenID4VP rules for non-string values.
- **Python EUDI issuer mdoc config.** Enabling the mdoc PID variant requires IACA/DS
  certificate config in `testdata/eudi-pid-issuer-py/`; budget time for this in M5.
