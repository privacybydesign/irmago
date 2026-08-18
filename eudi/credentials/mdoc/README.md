# mDoc Issuer → Holder → Verifier (Go)

An implementation of ISO 18013-5 mDoc selective disclosure, built against the EU Age
Verification Blueprint (Annex A, `eu.europa.ec.av.1`).

This package (`mdoc`) is the core format library only: `Issuer`, `Holder`, `Verifier`,
`MDoc`, `DeviceResponse`, `SelectiveDisclose`, and the CBOR/COSE crypto helpers. It has
no HTTP/protocol code of its own — the same role `eudi/credentials/sdjwtvc` plays for
SD-JWT VC. Everything OpenID4VP/OpenID4VCI-shaped now lives in the real, format-agnostic
protocol packages that also serve SD-JWT:

- **Presentation (OpenID4VP):** `eudi/openid4vp/mdoc_dcql` implements
  `dcql.DcqlCredentialQueryHandler` for `mso_mdoc`, mirroring `eudi_sdjwt_dcql` for
  SD-JWT. The mdoc-specific session-transcript construction lives there too, next to
  the rest of the real disclosure logic rather than in a separate subpackage here —
  both handover variants: `newOpenID4VPSessionTranscript` for a URL-invoked session
  and `newDcApiSessionTranscript` for one delivered through the Digital Credentials
  API.
- **Issuance (OpenID4VCI):** `eudi/openid4vci` is the real, format-agnostic issuance
  client (credential offer, token/nonce endpoints, proof-of-possession JWT via
  `eudi/credentials/proofs.JwtProofBuilder` — none of that is mdoc-specific).
  `eudi/services/credential_format_parser_mdoc.go` implements `CredentialFormatParser`
  for `mso_mdoc`: decoding, verifying, and extracting holder-binding data from a freshly
  issued mdoc, the issuance-side analogue of the DCQL handler above.

This package previously carried its own hand-rolled copies of both protocols
(`openid4vp/`, `openid4vci/` subpackages) plus a standalone `cmd/demo` driving them —
built before mdoc was wired into the real client. That duplication has been removed now
that both directions are wired for real; see the sections below for what's left. What
replaced the old demo lives in `yivi/cli/eudicli`: `mdoc-demo` walks a credential
through issue → disclose → verify against this package in-process, and `mdoc-e2e` does
the same over the real protocols against the EUDI reference containers.

---

## What it implements

| Component | Status | Notes |
|---|---|---|
| `IssuerSignedItem` (4-field envelope) | ✓ | digestID, random, elementIdentifier, elementValue |
| CBOR encoding | ✓ | shortest-form deterministic, fxamacker/cbor |
| Tag-24 wrapping | ✓ | freezes bytes before hashing |
| Per-item random value (salt) | ✓ | 16 bytes from `crypto/rand`, one per item. ISO/IEC 18013-5 puts the floor at 16; `Issue` sits on it, and both a compile-time assertion and a runtime check in `Issue` reject anything shorter. The salt is what stops a verifier brute-forcing an undisclosed boolean claim, since the digest of every item travels whether or not the item does. Enforced on receipt as well — see "Short-salt rejection" below |
| SHA-256 valueDigests | ✓ | `hash(Tag24(CBOR(item)))` per item |
| Randomized digest-ID assignment | ✓ | claim order is cryptographically shuffled before digestID assignment (not sorted) — prevents a verifier inferring undisclosed claims' relative order from a disclosed claim's digestID, matching Multipaz's `MdocUtil.generateIssuerNameSpaces` |
| MSO construction | ✓ | version, digestAlgorithm, valueDigests, docType, validityInfo, deviceKeyInfo |
| `deviceKeyInfo` in MSO | ✓ | holder's public key embedded at issuance, COSEKey uses `keyasint` (real CBOR int keys per RFC 9053) |
| `MobileSecurityObjectBytes`/`DeviceAuthenticationBytes` framing | ✓ | issuerAuth's and deviceAuth's payloads are each Tag24-wrapped as a whole (`24(<<{...}>>)`), not just the individual items inside them — confirmed against the AV Blueprint's own §A.11 worked example (MSO) and Multipaz's `MdocDocument.kt` signing code (DeviceAuthentication) |
| COSE_Sign1 issuerAuth | ✓ | ES256, x5chain (header 33) carries DS + IACA cert. Written as the bare four-element array ISO 18013-5 specifies, not go-cose's tag-18 `COSE_Sign1_Tagged`; `decodeCoseSign1` reads either, since the tag is outside `Sig_structure` |
| ISO wire shape at every CBOR position | ✓ | `issuerAuth`/`deviceSignature` inline COSE arrays, `IssuerSignedItemBytes` and `deviceSigned.nameSpaces` bare `#6.24(bstr)`. A Go `[]byte` field encodes as a byte string *wrapping* the value, and a one-field struct as a map keyed by the Go field name — both round-trip against this package and no other implementation, so `wireformat_test.go` decodes a real `DeviceResponse` generically (into `any`) and asserts each position |
| Two-level certificate chain | ✓ | IACA root CA → DS cert, real x509 chain walk |
| Chain attack rejection | ✓ | untrusted root rejected before signature check |
| Document Signer extended key usage | ✓ | the DS cert must be authorized for an mdoc document-signer usage: `1.0.18013.5.1.2` (ISO 18013-5 Annex B.1.2) or `1.0.23220.4.1.2` (ISO 23220-4, the generic-mdoc equivalent, which is what a non-mDL doctype such as `eu.europa.ec.av.1` may legitimately carry) — see `checkDocumentSignerEKU`. Chaining to a trusted IACA root is not on its own evidence of being a document signer: a real trust model issues for several roles under one root, so a certificate issued for another purpose (TLS, reader auth) must not be able to sign an MSO. A certificate with no EKU extension is accepted, per RFC 5280 §4.2.1.12 |
| Configurable verifier clock | ✓ | `NewVerifierWithClock` — tests expired / not-yet-valid certs and MSO validity deterministically |
| Unlinkable `validityInfo` timestamps | ✓ | `Issue` coarsens `signed`/`validFrom`/`validUntil` to midnight UTC. Single-use attestations issued in batches are only unlinkable if their timestamps are: at second precision every attestation in a batch carries a distinct `validUntil`, correlating what the batch exists to hide. Annex A sets hh/mm/ss to the same value on every attestation, as the EU reference issuer does for batch credentials |
| MSO `validityInfo` check (validFrom/validUntil) | ✓ | checked separately from X.509 cert expiry — both are mandatory per ISO 18013-5 |
| Selective disclosure | ✓ | holder filters items, issuerAuth reused unchanged |
| Requested-element check | ✓ | `VerificationResult.RequireElements` — the digests prove every disclosed element is authentic and `deviceAuth` proves the session, but neither covers *which* elements were selected: the device signature is over the session transcript and docType, not the disclosed set. A holder can drop an element and still pass every other check, so a verifier that cares what it received must ask separately. Left to the caller rather than folded into `Verify`, which does not know what was requested |
| Digest verification | ✓ | constant-time comparison via `crypto/subtle` |
| Tamper detection | ✓ | digest mismatch on value tampering |
| Short-salt rejection | ✓ | an `IssuerSignedItem` whose `random` is under the ISO floor of 16 bytes is refused on receipt, before the digest comparison, so a defective credential is reported as defective rather than as a digest mismatch. `Issue` enforces the same floor on what this package mints, but that says nothing about credentials minted elsewhere, and a trust anchor attests to who an issuer is rather than to whether it implements 18013-5 correctly. The party this protects is the holder: the MSO carries a digest for every element whether or not the item travels, so for a one-bit value like `age_over_NN` a short salt turns that digest into a lookup instead of a commitment |
| `docType` bound to the signed MSO | ✓ | `MDoc.docType` is covered by no digest and no signature, so it is compared against `MSO.docType` and a mismatch is rejected; `VerificationResult.DocType` reports the signed value and stays empty on failures rather than echoing an unauthenticated one. Without this, re-labelling one unsigned field yielded a valid result carrying the attacker's docType — which `credential_format_parser_mdoc.go` stores as the credential's type, and DCQL `doctype_value` matching keys off. See `verifier_doctype_test.go` |
| `deviceSigned` / `deviceAuth` | ✓ | `SignDeviceAuth` + `VerifyWithDeviceAuth` — fresh COSE_Sign1 per session, checked against `deviceKeyInfo` |
| Device-binding replay/clone rejection | ✓ | wrong signer and wrong-session deviceAuth both rejected |
| `DeviceSigned` wrapper struct | ✓ | `AttachDeviceSigned` populates an `MDoc.DeviceSigned` field (deviceAuth + empty deviceNameSpaces), matching ISO 18013-5's actual document shape instead of passing deviceAuth bytes around separately |
| `DeviceResponse` container | ✓ | `NewDeviceResponse`/`VerifyDeviceResponse` — real response container, holds one or more documents; reader authentication deliberately omitted per Annex A §A.6 |
| Issuance-time verification (all namespaces) | ✓ | `VerifyAllDisclosedNamespaces` — verifies issuerAuth/MSO/digests across every namespace present, for the credential-endpoint response before selective disclosure has happened; `Verify` remains the single-namespace, presentation-time entry point |
| Real OpenID4VP `SessionTranscript`/`Handover` | ✓ | now built in `eudi/openid4vp/mdoc_dcql` (production code), not in this package — `["OpenID4VPHandover", SHA-256(CBOR([clientId, nonce, jwkThumbprint, responseUri]))]`, the redirect variant of OpenID4VP Annex B.2.6.1, matching Multipaz's `OpenID4VP.kt`. `jwkThumbprint` is the SHA-256 JWK thumbprint of the verifier's response encryption key, and CBOR null when the response is unencrypted — which is the AV Blueprint's `response_mode=direct_post` case, so that profile produces the null form. A request delivered through the W3C Digital Credentials API signs the other variant, `["OpenID4VPDCAPIHandover", SHA-256(CBOR([origin, nonce, jwkThumbprint]))]` (Annex B.2.6.2), built alongside it in the same file. Which one applies follows the transport the request arrived on, never the shape of the values |
| OpenID4VCI `pre-authorized_code` issuance | ✓ | wired for real through `eudi/openid4vci` (generic) + `eudi/services/credential_format_parser_mdoc.go` (mdoc-specific parsing/verification) — not modeled in this package |
| OpenID4VCI `authorization_code` grant | ✓ | inherited for free — `eudi/openid4vci` already implements it generically for every format |
| Session encryption (BLE/NFC) | ✗ | transport layer not built; also explicitly out of scope for the AV Blueprint (proximity presentation is excluded — see Annex A §A.6) |
| W3C Digital Credentials API path (`DeviceRequest`, HPKE `EncryptedResponse`) | ✗ | out of scope for this package by design — see "OpenID4VP only" below |

---

## Containment hierarchy — what actually wraps what

`DeviceResponse` is the top-level *Go type* in this package — `MDoc` doesn't know or
care whether it's traveling alone or bundled with other documents, `DeviceResponse` is
what holds a list of them (`Documents []MDoc`, plural — see
`TestNewDeviceResponseSupportsMultipleDocuments`):

```
DeviceResponse                                  ← NewDeviceResponse / VerifyDeviceResponse
  └── Documents []MDoc                          ← one or more, per presentation
        ├── DocType
        ├── IssuerSigned{NameSpaces, IssuerAuth}  ← issuer's signature, fixed since issuance
        └── DeviceSigned{NameSpaces, DeviceAuth}  ← holder's signature, fresh per session
```

On the real OpenID4VP wire, `eudi/openid4vp/mdoc_dcql.PrepareDisclosure` CBOR-encodes and
base64url-encodes a `DeviceResponse` directly into the `dcql.QueryResponse.Credentials`
slice that `eudi/openid4vp`'s generic response builder sends — this package has no
opinion on the surrounding JSON/form-body shape, that's entirely the generic OpenID4VP
layer's job (same as it is for SD-JWT).

---

## Test suite

Tests are split one-per-source-file (`issuer.go` ↔ `issuer_test.go`, etc.), the same
layout as this repo's other eudi credential packages (e.g. `sdjwtvc`), rather than one
monolithic test file:

| File | Tests | What it checks |
|---|---|---|
| `mdoc_test.go` | `TestFullIssuanceFlow_ProducesValidMDoc` | Full issuer → holder → verifier round trip; also logs the real CBOR/COSE hex of the presented mdoc, `issuerAuth`, and `deviceAuth` for external inspection (e.g. via [cbor.me](https://cbor.me)) |
| `mdoc_test.go` | `TestDeviceSignedOmittedWhenNilPresentWhenAttached` | `deviceSigned,omitempty` actually omits the key pre-presentation and includes it only after `AttachDeviceSigned` |
| `crypto_test.go` | `TestCOSEKeyUsesIntegerMapKeys` | Decodes the real MSO bytes generically and asserts `deviceKey`'s map keys are actual CBOR integers — regression test for the `keyasint` struct-tag fix |
| `crypto_test.go` | `TestTag24WrapUnwrapRoundTrip` | `tag24Unwrap` is the exact inverse of `tag24Wrap` — wrapped bytes carry a real CBOR tag 24, and the round-tripped value matches the original |
| `crypto_test.go` | `TestTag24WrapWithModeUsesGivenEncMode` | `tag24WrapWithMode`'s inner payload is encoded with the `EncMode` actually passed in (using `avTimeEncMode`'s RFC3339 tagging as the observable difference), not `cbor.Marshal`'s default mode |
| `crypto_test.go` | `TestValidityInfoUsesRFC3339Tag` | Confirms `signed`/`validFrom`/`validUntil` are CBOR tag-0 RFC3339 strings, matching the AV Blueprint's own worked example, not a bare Unix epoch integer |
| `holder_test.go` | `TestDeviceAuthPayloadIsDetached` | Transmitted `deviceAuth` has `payload = null` (detached), matching the spec's `deviceSignature` example |
| `issuer_test.go` | `TestClaimOrderingIsRandomized` | Issues the same claims 30 times, confirms `digestID` assignment varies across issuances (not a fixed/predictable order) while every claim stays reachable via its digestID |
| `issuer_test.go` | `TestIssueAcceptsArbitraryDocTypeAndClaims` | `Issue()` signs any docType/namespace/claims combination as given (age verification, PID, mDL, email) — pins the doc-type-agnostic contract described under "Data model" |
| `verifier_test.go` | `TestUntrustedRootIsRejected` | Attacker's own valid IACA→DS chain, signed correctly, still rejected — root isn't in the verifier's trust pool |
| `verifier_test.go` | `TestTamperedDigestIsRejected` | Flipped claim value fails the digest check |
| `verifier_test.go` | `TestDeviceAuthWrongSignerIsRejected` | Cloned mdoc — deviceAuth signed by a different device's key — rejected |
| `verifier_test.go` | `TestDeviceAuthWrongSessionIsRejected` | Correct device key, but signed over a different session transcript (replay) — rejected |
| `verifier_test.go` | `TestUnknownDigestIDIsRejected` | A digestID absent from the MSO's `valueDigests` is rejected |
| `verifier_salt_test.go` | `TestVerifyNamespaceDigestsRejectsShortSalt` | A 15-byte `random` — one byte under the ISO floor — is refused, and the error names the random value rather than surfacing as a digest mismatch. The item is paired with a matching digest so the rejection is attributable to the salt alone |
| `verifier_salt_test.go` | `TestVerifyNamespaceDigestsAcceptsSaltAtFloor` | Exactly 16 bytes passes — a check written `>` rather than `>=` would reject every credential this issuer mints |
| `verifier_salt_test.go` | `TestVerifyNamespaceDigestsRejectsMissingSalt` | A nil `random` decodes fine from CBOR, so the zero value is refused explicitly rather than by relying on the length comparison being reached |
| `verifier_salt_credential_test.go` | `TestShortSaltIsRejectedAtIssuance` | The same floor through `VerifyAllDisclosedNamespaces`, on a complete credential signed by a real document signer with a real x5chain and digests that match — everything verifies except the salt. The unit tests above pin the comparison; this pins that it is *reached* from the entry point a wallet uses on what an issuer hands it |
| `verifier_salt_credential_test.go` | `TestLegalSaltFromTheSameConstructionIsAccepted` | The control for the file: the identical hand-assembled credential at 16 bytes must verify, so a passing rejection test cannot be explained by the envelope being broken some other way |
| `verifier_salt_credential_test.go` | `TestSaltLengthBoundary` | 0, 1, 8 and 15 bytes rejected; 16, 17 and 32 accepted — pins the comparison at exactly the floor rather than somewhere near it |
| `verifier_salt_credential_test.go` | `TestShortSaltIsRejectedAtPresentation` | The other entry point: a short-salted credential taken through `SelectiveDisclose` and then `Verify` is still refused |
| `verifier_salt_credential_test.go` | `TestShortSaltRejectedEvenWhenOnlyOneItemIsDefective` | Two sound items and one defective one under the same MSO — guards the loop rather than the comparison, since every other salt test uses a single-item namespace and so cannot show the check runs past the first item |
| `verifier_test.go` | `TestFreshCertsVerifyUnderCurrentTime` | Sanity check — freshly issued certs verify under the real current time (no off-by-one in validity math) |
| `verifier_test.go` | `TestExpiredDSCertIsRejected` | Verifier clock pinned ~400 days ahead (past the DS cert's 365-day window) — chain correctly rejected as expired |
| `verifier_test.go` | `TestExpiredMSOValidityIsRejected` | Verifier clock pinned ~100 days ahead (past the MSO's 90-day `validUntil`, but still within the DS cert's 365-day window) — rejected on the MSO's own validity, distinct from the cert check |
| `verifier_test.go` | `TestNotYetValidMSOIsRejected` | Verifier clock pinned between the (backdated) cert `NotBefore` and the MSO's `validFrom` — isolates the MSO validityInfo check specifically, distinct from cert validity |
| `verifier_test.go` | `TestNotYetValidCertIsRejected` | Verifier clock pinned before the certs' `NotBefore` — chain correctly rejected as not-yet-valid |
| `verifier_test.go` | `TestDeviceAuthStillVerifiesWithDetachedPayload` | Detaching the deviceAuth payload doesn't break verification — the verifier reconstructs it itself |
| `verifier_issuance_test.go` | `TestVerifyAllDisclosedNamespaces_HappyPath` | Verifies a freshly issued (not yet selectively disclosed) mdoc across every namespace it carries |
| `verifier_issuance_test.go` | `TestVerifyAllDisclosedNamespaces_TamperedDigestIsRejected` | Same tamper-detection guarantee as `Verify`, for the multi-namespace entry point |
| `verifier_issuance_test.go` | `TestVerify_PopulatesDeviceKeyAndValidityInfo` | `VerificationResult.DeviceKey` matches the holder's real public key, `ValidityInfo` is populated |
| `verifier_issuance_test.go` | `TestNewVerifierFromPool` | `NewVerifierFromPool` behaves identically to `NewVerifier` given an equivalent trust pool |
| `deviceresponse_test.go` | `TestAttachDeviceSignedRoundTrips` | `AttachDeviceSigned` populates `MDoc.DeviceSigned` with the exact deviceAuth bytes passed in, and returns a copy — the original mdoc is left untouched |
| `deviceresponse_test.go` | `TestVerifyDeviceResponseSucceeds` | Full flow through the real `DeviceResponse` container (`AttachDeviceSigned` → `NewDeviceResponse` → `VerifyDeviceResponse`) produces the same result as calling `VerifyWithDeviceAuth` directly |
| `deviceresponse_test.go` | `TestVerifyDeviceResponseRejectsMissingDeviceSigned` | A document without `DeviceSigned` attached is rejected with a descriptive error, not a nil-dereference panic |
| `deviceresponse_test.go` | `TestNewDeviceResponseSupportsMultipleDocuments` | A `DeviceResponse` bundling two distinct holders' documents from the same issuer verifies each document independently and correctly |
| `deviceresponse_test.go` | `TestDeviceAuthSignatureEncodesInline` | `DeviceAuth.DeviceSignature` embeds as structured CBOR (`cbor.RawMessage`), not as an opaque re-encoded byte string |
| `wireformat_test.go` | `TestWireIssuerAuthIsBareCoseSign1Array`, `TestWireIssuerSignedItemsAreTag24`, `TestWireDeviceSignedShape`, `TestWireRoundTripsThroughGenericCBOR`, `TestVerifierAcceptsTaggedCoseSign1` | Decodes a real `DeviceResponse` **generically** — into `any`, never this package's structs, since a round trip through the same types cannot detect a wrong shape — and asserts the ISO 18013-5 encoding at each position, plus that the frozen item bytes survive the round trip and the document still verifies |
| `verifier_doctype_test.go` | `TestTamperedEnvelopeDocTypeIsRejectedByVerify`, `…AtIssuanceVerification`, `TestVerifierRequestedDocTypeMustMatchSignedMSO`, `TestSignedDocTypeIsReportedNotTheEnvelopeValue` | The unsigned envelope `docType` must equal the signed `MSO.docType`, at every entry point that reports or consumes one |

`testhelpers_test.go` holds `buildHappyPathMDoc`, `keysOf`, and `unwrapTag24Generic` —
shared fixtures/helpers used across the files above, rather than duplicated per-file.

Run with:

```bash
go test -v .
```

Tests for the protocol layers live with the code they cover, not here:

| Location | Covers |
|---|---|
| `eudi/openid4vp/mdoc_dcql/sessiontranscript_test.go` | `TestOpenID4VPSessionTranscriptShape`, `…BindsAllInputs`, `…IntegratesWithDeviceAuth`, the same pair for `TestDcApiSessionTranscript…`, and `TestSessionTranscriptVariantsNeverCollide` — the byte-level handover formula, and that a `deviceAuth` signed over it verifies. `…CarriesEncryptionKeyThumbprint` covers the other axis: the third handover slot, which carries the response encryption key's thumbprint when the response is encrypted and CBOR null when it is not |
| `eudi/services/credential_format_parser_mdoc_test.go` | `TestMdocCredentialFormatParser_ParseAndVerify` (+ `_UntrustedRootRejected`, `_InvalidBase64`) and `_CheckBatchUniqueness` — the issuance-side parse/verify path |
| `eudi/services/credential_service_test.go` | `TestBuildMdocAttributesFromResolvedClaims_OrdersAndConvertsDisplayNames`, `…_NoMetadataStillEmitsValues` — permission-dialog attribute building |
| `eudi/openid4vci/metadata_validators_test.go` | `mso_mdoc` accepted as a supported credential format, and `credential_signing_alg_values_supported` validated as COSE algorithm identifiers — ES256 (`-7`) required, an identifier ISO 18013-5 permits but this wallet cannot verify distinguished from one it does not permit at all |
| `eudi/storage/db/credential_store_test.go` | `GetBatchesByDocType` against an `mso_mdoc` batch |
| `eudi/openid4vp/mdoc_age_verification_test.go` | `TestOpenID4VP_MdocAgeVerification` — the EU Age Verification profile (`eu.europa.ec.av.1`) across the two stages that decide a presentation and fail independently: whether the relying party is authorized to ask (its certificate's authorized sets, via the real `SchemeQueryValidator`) and whether the wallet can answer (a genuinely issued mdoc in storage, matched by `mdoc_dcql`). Also pins display-name resolution, including from the one-component claim path an issuer may publish |
| `internal/sessiontest/openid4vp_mdoc_av_disclosure_test.go` | `TestSessionHandler/openid4vp/mdoc-av` — the only mdoc disclosure that runs end to end against a real verifier (the EU reference `eudi-srv-web-verifier-endpoint` container): DCQL matching, the device-signed `DeviceResponse`, and the verifier accepting it, with the returned `vp_token` decoded from CBOR and its Tag-24 items unwrapped. A second subtest asks for an unauthorized docType and requires the refusal, so the passing case cannot pass by a skipped authorization check |

### `mdoc-decode` — standalone CBOR/COSE inspector

A separate CLI tool, in `yivi/cli/eudicli/mdoc-decode` with the other command line
programs (Go requires each binary its own package), for manually inspecting any
hex-encoded COSE_Sign1 or CBOR blob produced by this package:

```bash
go run ./yivi/cli/eudicli/mdoc-decode <hex-string>
go run ./yivi/cli/eudicli/mdoc-decode -      # hex on stdin
```

For a whole presentation rather than a fragment, reach for `vptoken-decode`
instead: it takes a verifier's `vp_token` directly and resolves the Tag-24 items
and the x5chain that this tool leaves raw.

Detects COSE_Sign1 structures (breaks out protected/unprotected headers, `x5chain`
cert previews, payload, and ECDSA `r`/`s` signature halves), recursively unwraps
Tag-24 embedded CBOR, and falls back to generic CBOR pretty-printing otherwise.
Read-only — it does not verify signatures, chains, or digests; use the real
`Verifier` for that.

---

## Certificate chain

```
IACA root CA  (self-signed, IsCA=true, offline in production)
      ↓ signs
DS cert       (IsCA=false, signs every MSO)
      ↓ signs
MSO           (inside COSE_Sign1 issuerAuth, includes deviceKeyInfo)
```

x5chain header 33 carries `[DS cert, IACA cert]`.
The verifier pre-installs only the IACA root cert — DS cert arrives with each mDoc.
Trust in the chain comes from the verifier independently walking and validating the
X.509 chain (`x509.Verify`) — not from the COSE signature, since x5chain lives in the
*unprotected* header.

The chain walk is followed by a role check: the DS certificate must be authorized for
an mdoc Document Signer extended key usage — either `1.0.18013.5.1.2` from ISO
18013-5, or `1.0.23220.4.1.2`, which is ISO 23220-4's equivalent for mdocs that are
not mobile driving licences and so the one a conformant `eu.europa.ec.av.1` issuer may
well use. Go's
`x509.VerifyOptions.KeyUsages` cannot express that OID (its `ExtKeyUsage` enum has no
member for it), which is why the walk still passes `ExtKeyUsageAny` — that only stops
Go defaulting to `ExtKeyUsageServerAuth` — and the EKU is checked separately against
the parsed certificate's `UnknownExtKeyUsage`.

The requirement comes from ISO 18013-5, **not** from the AV Blueprint, which says
nothing about certificate profiles: it specifies no IACA or DS profile, never references
ISO 18013-5 Annex B, and defers security considerations to OpenID4VCI/OpenID4VP. That
silence is exactly why a certificate with no EKU extension has to be accepted — an
issuer following the Blueprint literally is never told to add the usage, so mandating it
would reject conformant issuers. Only a certificate that enumerates its usages and omits
this one is refused.

> **Interop note.** The EUDI reference issuer's development certificate
> (`testdata/eudi-pid-issuer-py/certs/issuer.pem`) carries `clientAuth`, not the mdoc
> DS usage, so it is rejected by this check. When the mdoc integration test is wired
> up, either regenerate that certificate with the correct EKU (its `certs/generate.sh`
> is in-tree) or introduce an explicit developer-mode relaxation. Do not widen the
> production check to accommodate it.

Two separate validity windows are checked, per ISO 18013-5: the X.509 certificates'
own `NotBefore`/`NotAfter` (via the chain walk above), and the MSO's own
`validityInfo.validFrom`/`validUntil` (checked independently in `Verify`, right after
MSO decode). A cert being valid does not imply the specific credential's claimed
window is — both must hold.

Both certs' `NotBefore` are backdated 5 minutes from issuance time — standard practice
to absorb clock skew between issuer and verifier, and what makes it possible to test
the MSO validity check in isolation from cert validity (see `TestNotYetValidMSOIsRejected`).

### Deployment phases

| Phase | Trust anchor | Status |
|---|---|---|
| 1 — testing | self-signed IACA root (this code) | current |
| 2 — pilot | Yivi's own IACA root, manually configured on verifiers | next |
| 3 — production | EU AV Blueprint root CA, registered AP trust list | future |

---

## Device binding

At issuance, the holder generates an EC P-256 key pair locally (in production: inside
Secure Enclave / TrustZone / StrongBox — private key never extractable) and sends
**only the public key** to the issuer. The issuer embeds it in `MSO.deviceKeyInfo`
and signs the whole MSO — this is a one-time **binding**, not proof of anything live.

At each presentation, the holder signs a fresh `deviceAuth` (COSE_Sign1) over
`["DeviceAuthentication", sessionTranscript, docType, deviceNameSpaces]` using that
same private key. The verifier pulls the public key back out of the now-trusted MSO
and checks the signature against it, and against its own session transcript — this is
the live **authentication** step that proves the presenting device is the one the
credential was bound to, not a copy of the data on another device.

```
binding (once, at issuance):        deviceKeyInfo says "this key belongs to this credential"
authentication (every presentation): deviceAuth proves "I am that key, right now"
```

The real client generates and stores this device key the same way it does for SD-JWT
holder-binding keys — via `eudi/services.HolderBindingKeyService.CreateKeyPairsWithProofs`
— then reconstructs a signing-capable `Holder` from the stored PKCS#8 private key at
presentation time via `mdoc.NewHolderFromPrivateKey` (see
`eudi/openid4vp/mdoc_dcql.PrepareDisclosure`).

---

## Crypto suite

Matches EU AV Blueprint Annex A §A.7:

```
Key type:   P-256 (secp256r1)
Algorithm:  ES256 (ECDSA + P-256 + SHA-256), COSE alg id = -7
Hash:       SHA-256
Encoding:   CBOR (RFC 8949), deterministic shortest-form
Signing:    COSE_Sign1 (RFC 9052)
COSE keys:  integer map keys per RFC 9053 (kty=1, crv=-1, x=-2, y=-3)
```

---

## Data model

```
docType:    eu.europa.ec.av.1
namespace:  eu.europa.ec.av.1
attributes: age_over_18 (mandatory), age_over_NN (optional)
```

The docType and namespace are the Blueprint's, and are corroborated by the EUDI
reference issuer's own credential configuration
(`age_verification_mdoc.json` in
`ghcr.io/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py`), which declares
`doctype: eu.europa.ec.av.1` and claims at
`["eu.europa.ec.av.1", "age_over_NN"]` — `age_over_18` with `mandatory: true`, and
`age_over_13/15/16/21/23/25` with `mandatory: false`. That is the strongest evidence
for the attribute set, being a running implementation rather than prose.

An earlier revision of this section cited "Annex A §4.1.1 and §4.1.2" and added "no
other attributes permitted". Neither survived checking: the Blueprint's own data-model
section shows a minimal example carrying `age_over_18` alone and does not enumerate the
`age_over_NN` variants or forbid further attributes, and the `§4.1.x` numbering does not
match Annex A's `§A.x` scheme, so it pointed at something other than the annex — if at
anything. Treat every Annex A section number in this package as unverified (see
References).

**This attribute restriction is not currently enforced anywhere in irmago.**
`mdoc.Issuer.Issue()` signs whatever docType/namespace/claims it is given (a
passport, a driving licence, ...) — see `TestIssueAcceptsArbitraryDocTypeAndClaims`,
which pins that as intended behaviour for the doc-type-agnostic core. Earlier
revisions of this package enforced the restriction in `Issue()` and asserted it in
four issuer tests; both were dropped when the package's own issuance path was
removed.

Nothing regressed by dropping them, because irmago never plays the issuer role in
production: `Issuer` exists for tests, and the real AV issuer is an external
service. The holder side has no use for the rule either — a wallet verifies what it
is sent, and `credential_format_parser_mdoc.go` deliberately accepts any docType so
that the same parser serves every mdoc credential type. Should irmago ever issue
mdocs itself, the check belongs in that issuance path, not in `Issue()`.

---

## Known gaps vs real mDoc

### OpenID4VP only — ISO 18013-5's own DC API wire format is out of scope by design

The AV Blueprint's Annex A §A.6 states the W3C Digital Credentials API is the
*default* presentation method, with OpenID4VP only as a *fallback*. Both transports are
supported, but only as OpenID4VP carries them: `eudi/openid4vp` handles a DC API request
delivered by the platform (`Client.NewDcApiSession`), and `mdoc_dcql` signs that
transport's session transcript. What stays out of scope is ISO 18013-5's own wire format
for that path, which the blueprint pairs with the DC API:

- ISO 18013-5's native `DeviceRequest` CBOR object (§8.3.2.1.2.1) — the blueprint
  confirms this is used *exclusively* by the DC API path; OpenID4VP requests
  attributes via a DCQL query instead (JSON), which `eudi/openid4vp/dcql` implements
  generically for every format.
- The DC API's `EncryptedResponse = ["dcapi", {enc, cipherText}]` wrapper, where
  `cipherText` is `DeviceResponse` encrypted with HPKE (RFC 9180). This package still
  has no HPKE layer: `response_mode=direct_post` and `dc_api` send `DeviceResponse`
  unencrypted (as base64url CBOR), and the encrypted modes (`direct_post.jwt`,
  `dc_api.jwt`) are JWE at the OpenID4VP layer, built in `eudi/openid4vp`, not HPKE
  around the mdoc.
  What this package's callers do supply is the response encryption key's thumbprint, so
  the session transcript commits to it — see the handover row above.

### No session encryption / transport layer

Real ISO 18013-5 *proximity* presentations happen over BLE or NFC, with session keys
derived via ECDH from a QR-code-carried verifier ephemeral key, then AES-GCM/AES-CCM
encrypting the actual `DeviceRequest`/`DeviceResponse` exchange. None of that transport
layer is modeled here — and per the AV Blueprint's own Annex A §A.6, it doesn't need to
be: proximity presentation is explicitly out of scope for this profile. The real client
only ever presents over HTTPS via OpenID4VP (`eudi/openid4vp`).

### Verifier sees total digest count

The full `issuerAuth` (all digests) travels with every presentation. The verifier can
call `len(mso.ValueDigests[namespace])` to learn how many total claims exist, even for
undisclosed ones. Values are hidden — count is not.

(Digest *order* is a separate concern and is handled: `Issue()` assigns digestIDs via a
cryptographically random shuffle, not a sorted/deterministic order — see the comment on
`shuffleIdentifiers` in `issuer.go` — so a disclosed claim's digestID reveals nothing
about undisclosed claims' relative position. Only the *count* remains visible.)

### Issuer-advertised `batch_size` is unbounded

Batch issuance is what buys unlinkability: because the issuer fixes each item's `random`
salt before signing, the disclosed bytes of one credential instance are identical on
every presentation, so two verifiers shown the same instance can trivially correlate
them. One instance per presentation is the mitigation, and `RemainingCount` reaching
zero is what the exhausted-batch path in `mdoc_dcql` reports.

How many instances to mint is the *issuer's* policy — it knows its own unlinkability
requirements and how often its users present — so the wallet honours the advertised
`batch_credential_issuance.batch_size` rather than holding an opinion
(`eudi/openid4vci/session.go`). That part is deliberate: a wallet hardcoding the AV
Blueprint's recommended 30 would under-request from an issuer offering more, and refuse
a conformant issuer offering fewer.

**What is missing is an upper bound.** The only check is that the value exceeds 1
(`eudi/openid4vci/metadata_validators.go`). An issuer advertising `batch_size: 100000`
would have the wallet generate that many device keys and proof JWTs, on a phone, inside
a session the user is waiting on — so a hostile or merely misconfigured issuer turns a
metadata field into a client-side resource exhaustion. Neither OpenID4VCI nor the AV
Blueprint states a ceiling, so a conformant implementation has to pick its own.

For calibration: the AV Blueprint recommends **30**; the EU reference Python issuer we
test against advertises **100** as its own default (not configured by us — it is absent
from `testdata/eudi-pid-issuer-py/conf/config_issuer_backend.yaml`). A cap somewhere
above the latter, refusing anything larger with a clear error rather than silently
truncating the batch, would close this without breaking either.

### No verifier-side certificate / relying-party authentication

Real deployments (e.g. Yivi's production trust model) also have a separate CA branch
for relying parties (`Yivi Relying Parties CA` alongside `Yivi Attestation Providers
CA`, both under one root), letting a verifier authenticate *itself* to the holder's
wallet before requesting data. This program only models the issuer-side chain; there
is no equivalent verifier-side cert or check.

### Issuer does not authenticate the wallet either (by design, not oversight)

The issuance side has the symmetric gap: Annex A §A.5 states client authentication is
"out of scope of this profile" for OpenID4VCI, and §A.9 explains why PAR
([RFC 9126](https://www.rfc-editor.org/rfc/rfc9126))/HAIP-style wallet attestation is
deliberately, *permanently* not used — "the Age Verification solution does not
incorporate such a trust list. Using a self-signed certificate does not offer any
value." This isn't a phased limitation (§A.3's own "may be added in future versions"
list doesn't mention PAR or trust lists at all) — it's a stated architectural choice.
Trust rests entirely on `tx_code` possession (a PIN/OTP delivered out-of-band, e.g.
email) plus TLS/Web PKI, not on any pre-registered or attested wallet identity — this
is generic `eudi/openid4vci` behavior, not something specific to mdoc.

### Proof of possession has no replay window

`eudi/credentials/proofs.JwtProofBuilder`'s proof JWT carries `iat`, `aud`, and `nonce`,
but the real client does not track proof-JWT freshness or `c_nonce` single-use itself —
that's the issuer's own session state to enforce (a nonce store marking a `c_nonce` as
spent the moment it's redeemed), which is genuine server-side state no client package
models. A real issuer is expected to enforce single-use nonce redemption itself.

### Real clock, not injected, by default

`NewVerifier` uses the real system clock. `NewVerifierWithClock` exists for testing
expired/not-yet-valid rejection deterministically, but production code paths always
use `time.Now()`.

---

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/fxamacker/cbor/v2` | CBOR encoding/decoding, Tag-24 wrapping |
| `github.com/veraison/go-cose` | COSE_Sign1 signing and verification |
| `crypto/ecdsa`, `crypto/elliptic` | P-256 key generation (issuer DS/IACA keys, holder device key) |
| `crypto/rand` | OS CSPRNG (`/dev/urandom` / `BCryptGenRandom`) |
| `crypto/sha256` | SHA-256 digest computation |
| `crypto/subtle` | Constant-time digest / payload comparison |
| `crypto/x509` | Certificate generation and chain validation |

---

## References

- ISO 18013-5 — mDoc/mDL standard
- RFC 8949 — CBOR
- RFC 9052 — COSE (COSE_Sign1, Sig_structure)
- RFC 9053 — COSE Key (integer map keys for `COSEKey`)
- EU Age Verification Blueprint Annex A — `eu.europa.ec.av.1` profile
  ([ageverification.dev](https://ageverification.dev/Technical%20Specification/annexes/annex-A/annex-A-av-profile))

> **The Annex A section numbers cited throughout this package are unverified.** They
> were not all taken from one reading and they disagree with each other: the crypto
> suite is cited here as both §A.6 and §A.7, the OpenID4VP requirements as §A.6 while
> the published annex appears to put `response_mode` under §A.5, the worked example as
> §A.11 against an apparent §A.10, and the data model formerly as §4.1.x, which is not
> Annex A's numbering at all. The *content* of each claim was checked and holds — P-256
> with ES256 and SHA-256, `response_mode` MUST be `direct_post`, proximity presentation
> out of scope, no AP metadata or certificate profile specified. Only the numbering is
> in doubt. The `direct_post` restriction is narrower than OpenID4VP and ISO 18013-7,
> which both allow the encrypted variant and which this wallet implements; a deployment
> serving the AV profile holds itself to the narrower rule with
> `openid4vp.Client.RequireUnencryptedDirectPost`, off by default so ordinary 18013-7
> verifiers are not refused. Anyone relying on a specific citation should confirm it against the
> authoritative document first, and ideally pin the Blueprint revision here once
> someone has it open.
- IANA COSE Algorithms registry — `-7` = ES256
- IANA COSE Key Types registry — `1`=kty, `-1`=crv, `-2`=x, `-3`=y
