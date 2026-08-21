# EU Age Verification profile compliance plan

Cross-check of the [mdoc implementation plan](./mdoc-implementation-plan.md) (issues
[#562](https://github.com/privacybydesign/irmago/issues/562)–[#569](https://github.com/privacybydesign/irmago/issues/569))
against the **EU Age Verification (AV) technical specification**, plus a delivery plan for
making **go-passport-issuer** an AV-compliant Attestation Provider issuing over OpenID4VCI.

Sources:

- [AV architecture & technical specifications](https://ageverification.dev/av-doc-technical-specification/docs/architecture-and-technical-specifications/)
- [Annex A — AV profile](https://ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/)
- Local reference issuer: `~/code/go-passport-issuer` (currently issues passport/idcard/eDL
  credentials over the IRMA protocol via signed IRMA session-request JWTs)

Spec versions are pre-1.0 and several items are marked "TBD" in Annex A; re-verify
identifiers against the published profile before each milestone lands.

---

## 1. What the AV profile requires (normative summary)

**Credential** (Annex A):

| Item | Value |
|---|---|
| Format | ISO/IEC 18013-5 mdoc (`mso_mdoc`) — *only* format; no SD-JWT VC option |
| DocType | `eu.europa.ec.av.1` |
| Namespace | `eu.europa.ec.av.1` |
| Attributes | `age_over_18` (bool, mandatory); optional further `age_over_NN` (bool). **"SHALL NOT include any other attribute"** |
| Crypto | P-256 / ES256 mandatory everywhere; SHA-256 for MSO value digests |
| Validity | Single-use attestations, max ~3 months validity (main spec §3.4.3); revocation explicitly **not required** |
| Privacy | Batch issuance (recommended batch size **30**, main spec §3.4.1); ValidityInfo timestamps with reduced precision (hh:mm:ss set to the same value) to limit linkability |

**Issuance — OpenID4VCI** (Annex A):

- Grant types: **both** `authorization_code` *and* `urn:ietf:params:oauth:grant-type:pre-authorized_code` are mandatory for the Attestation Provider (AP).
- PKCE (RFC 7636) with `S256` MUST be supported and used by both wallet (AVI) and AP.
- Authorization request scope: `proof_of_age`; `credential_configuration_ids` is an array with the single element `proof_of_age`.
- Credential endpoint: `proofs` parameter, array of proofs of type **JWT** (→ batch issuance via multiple proofs in one request).
- Credential offer invocation: custom URL scheme **`av://`** MUST be supported.
- Enrolment at LoA *substantial*: via eID/IdP (auth-code flow) or document-based ICAO 9303 NFC verification (pre-auth flow) — the latter is exactly what go-passport-issuer does.
- AP metadata profile: marked **TBD** in Annex A.

**Presentation** (Annex A):

- **Primary**: W3C **Digital Credentials API** with protocol `org-iso-mdoc` per ISO/IEC 18013-7 Annex C — request carries base64url CBOR `DeviceRequest` + `EncryptionInfo`; response is a CBOR `EncryptedResponse` (`enc`, `cipherText`) using **HPKE (RFC 9180)**. Reader authentication out of scope.
- **Fallback**: OpenID4VP when the DC API is unavailable:
  - response type `vp_token`, response mode **`direct_post`** (explicitly *not* `direct_post.jwt`),
  - request passed **by value, unsigned** (no JAR), client identifier scheme **`redirect_uri`**, no client authentication,
  - **DCQL** query language, mandatory `nonce`, optional `state`.
- Proximity presentation: out of scope.

**Trust model**:

- APs register on an AV **trusted list** (ETSI TS 119 612, published on the eIDAS dashboard `av-tl`); document signer certificate per **ETSI EN 319 411-1 (NCP)** or AP-operated trust anchor CA.
- No trusted lists / registration for wallets or relying parties; RP authentication relies on TLS/Web PKI.
- Out of scope in the current profile: device-bound attestations (hardware key attestation / WSCD), re-issuance via refresh tokens, revocation, LoA high.

**ZKP** (SHOULD, not MUST): wallets SHOULD support ZK presentations using "Anonymous
credentials from ECDSA" (Frigo & shelat; google/longfellow-zk); RPs SHOULD verify them.

---

## 2. Cross-check against the mdoc implementation plan

### 2.1 Already aligned — no changes needed

| AV requirement | Where the plan covers it |
|---|---|
| `mso_mdoc` format, ES256/P-256, SHA-256 digests | M1/M2 (#563, #564) — ES256-first is already the stated default |
| DocType `eu.europa.ec.av.1`, `age_over_NN` claims | Plan is docType/namespace-agnostic; pure configuration, no code change. Boolean CBOR values are part of the M4 claims-projection mapping |
| Pre-authorized code + authorization code flows | M5 (#567) covers both; irmago's OpenID4VCI client already implements both incl. PKCE |
| JWT proofs, `proofs` array → batch issuance | M5; matches the existing SD-JWT batch pattern (one key per instance) |
| Single-use attestations, batch bookkeeping | M4 (#566) reuses `RemainingCount` single-use semantics; batch size 30 is configuration |
| DCQL with `[namespace, element]` claim paths | M6 (#568) |
| `direct_post` response mode | M6 — already in scope (the *plain* variant is what AV mandates) |
| No revocation requirement | Plan already defers status lists — now confirmed acceptable for AV |
| No proximity / BLE-NFC | Plan already out of scope — confirmed acceptable for AV |
| Device keys without hardware attestation | The profile keeps JWT proofs and the ZKP spec references "the attestation public key", so the MSO `deviceKeyInfo`/DeviceAuth machinery from M2/M3/M6 stays; WSCD-grade key attestation is explicitly out of scope. ⚠️ Verify against the AV reference apps during interop whether their attestations are actually device-bound (Annex A's "device bound … out of scope" wording is ambiguous) |

### 2.2 Amendments to existing milestones (small deltas)

1. **M3 (#565) — timestamp precision reduction.** The MSO builder must support the
   linkability mitigation from main spec §3.4.1: `signed`/`validFrom`/`validUntil` with
   hh:mm:ss forced to a fixed value (per the ISO 18013-5 recommendation). Add a
   `ValidityInfo` truncation option + tests asserting equal time-of-day across a batch.
2. **M3/M5 — validity window policy.** Make max validity configurable and add an AV
   preset (≤ 3 months). Wallet-side (M5) only needs to *not reject* short-lived
   credentials; issuer-side enforcement lands in go-passport-issuer (§3 below).
3. **M5 (#567) — AV credential configuration fixture.** Add a `proof_of_age` /
   `eu.europa.ec.av.1` credential configuration (scope `proof_of_age`, single-element
   `credential_configuration_ids`, claims metadata for `age_over_18`) to the hermetic
   test issuer and the metadata-validator tests, so AV compliance is continuously
   tested rather than assumed. Batch test should include size 30.
4. **M5/M6 — `av://` invocation scheme.** Credential-offer and authorization-request
   parsing must accept the `av://` custom scheme in addition to `openid-credential-offer://`
   / `openid4vp://` / https links. Mostly app-level URL routing, but irmago's
   offer/request URI parsing should be scheme-lenient; add unit tests.
5. **M6 (#568) — unsigned requests with `client_id` scheme `redirect_uri`.** Gap found
   during cross-check: irmago's OpenID4VP client currently *requires* a signed request
   JWT (`ParseAndVerifyAuthorizationRequest(requestJwt)` in
   `eudi/openid4vp/verifier_validator.go:15`, with X.509/DID verifier validation).
   The AV fallback profile mandates plain, unsigned, by-value authorization requests
   with the `redirect_uri` client-id scheme and **no** client authentication. Add a
   trust-policy-gated request path (e.g. only for queries targeting AV docTypes, or an
   explicit "web-PKI verifier" mode) that accepts unsigned requests; the
   SessionTranscript handover must then bind `client_id = redirect_uri value`. Update
   the `DisclosureContext` design in M6 accordingly.
6. **M2/M7 — AV trusted list as trust-anchor source.** Extend the IACA trust-anchor
   configuration (M2 verification) with an ETSI TS 119 612 trusted-list (XML TSL)
   fetcher/parser feeding `eudi/trustmodel.go`, pointed at the eIDAS `av-tl` dashboard
   list. Cache + signature validation of the TSL itself. Can land as part of M7 or as
   its own small milestone; verification tests with a self-built TSL fixture.

### 2.3 New features required by the AV profile (proposed new milestones)

**M8 — Digital Credentials API presentation (ISO/IEC 18013-7 Annex C).** The AV profile
makes the DC API the *primary* presentation channel; OpenID4VP is only the fallback. The
original plan explicitly scoped DC API out. New milestone, depends on M2/M3 (+M6 for the
shared selective-disclosure machinery):

- Parse `org-iso-mdoc` protocol requests: base64url CBOR `DeviceRequest`
  (ISO 18013-5 §8.3.2.1.2.1 — itemsRequest with docType + namespace/element map +
  intentToRetain) and `EncryptionInfo`.
- Build the Annex C SessionTranscript / DC-API handover (distinct from
  `OpenID4VPHandover`; keep both in the one isolated handover-construction function
  already planned in M6).
- Encrypt the `DeviceResponse` as `EncryptedResponse{enc, cipherText}` with **HPKE
  (RFC 9180)** — new dependency (e.g. `github.com/cisco/go-hpke` or x/crypto HPKE),
  P-256/HKDF-SHA256/AES-GCM suite.
- Wallet-app plumbing (Android/iOS DC API registration, `av://`) is out of irmago's
  scope but the irmago API must expose a "answer this DeviceRequest" entry point that
  the app can call from the OS credential-provider callback.
- Tests: hermetic request→encrypted-response→decrypt→verify round trip; ISO 18013-7
  Annex C test vectors if available; interop against the AV reference verifier service.

**M9 (optional, SHOULD) — ZK presentations.** Annex A recommends "Anonymous credentials
from ECDSA" (longfellow-zk). Treat as an exploratory follow-up: track upstream Go
support, do not block AV compliance on it (it is a SHOULD for wallets). Out of plan
until the profile hardens.

---

## 3. go-passport-issuer: becoming an AV Attestation Provider

Current state (from code review): a Go service that performs ICAO 9303 passive + active
authentication of passports/ID cards/eDLs (via `gmrtd`), extracts attributes incl.
ready-made `Over12/16/18/21/65` age predicates, and issues credentials by returning a
**signed IRMA session-request JWT** (`jwt_creator.go`, `irma.SignSessionRequest`, RS256)
that the app redeems at a Yivi IRMA server. No OAuth2/OpenID4VCI/COSE code today; the
document-validation side is cleanly separated from issuance and reusable as-is.

go-passport-issuer maps onto the AV architecture as an **AP doing document-based
enrolment** (main spec §3.3.2: ICAO 9303 MRZ+NFC, which it already implements) — the
pre-authorized code flow is the natural fit, with the auth-code flow added for profile
completeness (both grants are mandatory).

Phases, each independently deliverable and automatically tested:

### P1 — proof_of_age mdoc minting

Depends on irmago M3 (#565); go-passport-issuer already depends on irmago, so consume
`eudi/credentials/mdoc` as a library (bump to the branch/tag that ships it).

- New `backend/mdocissuer/` package: build an `eu.europa.ec.av.1` mdoc from a validated
  document: `age_over_18` (+ configurable extra `age_over_NN`) computed from DOB at
  issuance time — reuse the existing age-predicate logic, but emit **only** age claims
  (Annex A forbids any other attribute, so this is a *separate* credential from the
  existing full passport credential).
- ES256/P-256 DS key + IACA chain handling: new key material alongside the existing RSA
  IRMA-JWT key; config entries for DS cert/key and IACA chain paths.
- AV policy knobs: validity ≤ 3 months, ValidityInfo timestamp truncation, batch size
  (default 30).
- Tests: unit tests minting from fixture `PassportData`; verification with irmago's M2
  verifier; golden-file CBOR fixture; negative test that non-age attributes are rejected.

### P2 — OpenID4VCI issuer core

- New `backend/openid4vci/` package implementing the AP endpoints:
  - `/.well-known/openid-credential-issuer` + `/.well-known/oauth-authorization-server`
    metadata with the `proof_of_age` credential configuration (`format: mso_mdoc`,
    `doctype: eu.europa.ec.av.1`, claims, `cryptographic_binding_methods_supported:
    [cose_key]`, `credential_signing_alg_values_supported: [ES256]`, batch size). AP
    metadata details are TBD in Annex A — keep this table config-driven.
  - Token endpoint: `pre-authorized_code` grant (+ optional tx_code) and
    `authorization_code` grant, PKCE `S256` enforced on both per the profile.
  - Nonce endpoint (`c_nonce`) and credential endpoint: validate `proofs` JWT array
    (nonce freshness, ES256, `cnf` key extraction), mint one mdoc per proof via P1,
    return base64url CBOR credentials.
  - Credential-offer generation: `openid-credential-offer://` and **`av://`** URIs + QR.
- Reuse the existing `TokenStorage` (memory/Redis/Sentinel) for pre-auth codes, auth
  codes, nonces and PKCE challenges (same TTL semantics as today's session nonces).
- Tests: httptest-level unit tests per endpoint; **hermetic end-to-end test using the
  irmago OpenID4VCI wallet client (M5) as the harness** — the same client the Yivi app
  uses, giving continuous wallet↔issuer interop coverage in CI.

### P3 — wire into the document-validation flow

- Extend the validation API: after successful passive+active authentication, offer the
  result over either protocol, config-driven per deployment:
  - existing: IRMA session-request JWT (unchanged),
  - new: `POST /api/issue-proof-of-age` → credential offer (pre-auth code bound to the
    validated session's derived age predicates in `TokenStorage`; the full
    `PassportData` need not be retained — data minimisation).
- Session hygiene: one credential offer per validated session, single redemption,
  existing session-reuse protections extended to the pre-auth code.
- Tests: extend `integration_test.go` to cover validate→offer→token→credential against
  the in-process OID4VCI server with the irmago client; negative tests for replayed
  sessions/codes and expired offers.

### P4 — authorization code flow (eID/IdP-less variant)

Annex A makes the `authorization_code` grant mandatory for APs. Implement a minimal
authorization endpoint that drives the existing browser-based NFC validation UI as the
"authorization" interaction (user lands on the frontend, scans the document, the
completed validation redeems the auth code), with PKCE. An eIDAS/IdP connector (the
other enrolment path from main spec §3.3.1) is out of scope for this service.

- Tests: full auth-code+PKCE flow with the irmago client and a fake validator.

### P5 — AV trust & operational compliance

- DS certificate per **ETSI EN 319 411-1 (NCP)** or an own IACA; document the chosen
  PKI path and key ceremony; config validation that refuses non-P-256 keys for AV.
- Registration of the AP on the AV trusted list (eIDAS dashboard `av-tl`) — operational
  task; track in deployment runbooks. Test environments use a self-signed IACA + local
  TSL fixture (shared with the irmago trusted-list work, §2.2 item 6).
- Privacy review against main-spec §2.4: confirm no PII beyond `age_over_NN` leaves the
  issuance path, batch unlinkability (fresh salts/digestIDs per mdoc — guaranteed by
  the M3 builder), truncated timestamps, no retention of passport data after issuance.

### P6 — AV interop & conformance

- Interop against the AV reference implementation (white-label app + verification
  service from ageverification.dev / GitHub): issue from go-passport-issuer into the
  reference AVI; present from the Yivi app to the reference verifier (OpenID4VP
  fallback first, DC API once irmago M8 lands).
- Add a docker-compose profile with the AV reference verifier for CI, mirroring the
  existing veramo/python-issuer interop setup in irmago.

```
P1 (minting) → P2 (OID4VCI core) → P3 (flow wiring) → P5 (trust/ops) → P6 (interop)
                                  └→ P4 (auth-code flow, parallel with P3)
irmago prerequisites: M3 for P1; M5 for the P2/P3/P4 test harness; M6 (+ amendments) and M8 for P6 presentation interop.
```

---

## 4. Open questions / risks

1. **Device binding ambiguity.** Annex A lists "device bound Proof of Age attestations"
   as out of scope, yet mandates JWT proofs at issuance and the ZKP section references
   the attestation public key. Working assumption: MSO carries a device key and
   DeviceAuth works as in 18013-5, but hardware-backed key attestation is not required.
   Confirm against the AV reference issuer's actual MSOs during P6 — if reference
   attestations carry **no** device key, irmago M2/M6 must tolerate MSOs without
   `deviceKeyInfo` and DeviceResponses without DeviceAuth, which is a (small) data-model
   delta worth knowing early.
2. **Unversioned spec references.** Annex A pins neither the OID4VCI nor the OID4VP
   draft, and AP metadata is "TBD". The M6 handover-isolation decision and the
   config-driven AP metadata in P2 are the mitigations; re-check the profile before
   each milestone.
3. **`direct_post` without response encryption** means the age signal travels in a
   plain POST (TLS only). That follows the profile, but keep `direct_post.jwt` support
   (already in the plan) for non-AV deployments.
4. **DC API dependency on app/platform work.** irmago M8 delivers the protocol layer,
   but AV-primary-path compliance also needs Android/iOS credential-provider
   integration in the Yivi app — track that in the app repos, it is not covered here.
5. **Trusted-list operational dependency.** P5 registration on the `av-tl` list is a
   process with the Commission, not code; start it early since P6 interop against
   production-profile verifiers may depend on it (test lists exist for development).
