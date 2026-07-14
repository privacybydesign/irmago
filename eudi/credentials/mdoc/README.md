# mDoc Issuer → Holder → Verifier (Go)

A minimal, self-contained implementation of ISO 18013-5 mDoc selective disclosure,
built against the EU Age Verification Blueprint (Annex A, `eu.europa.ec.av.1`).

Not production code — written to understand how mDoc, CBOR, COSE_Sign1, Tag-24,
certificate chains, device binding, and selective disclosure fit together.

---

## What it implements

| Component | Status | Notes |
|---|---|---|
| `IssuerSignedItem` (4-field envelope) | ✓ | digestID, random, elementIdentifier, elementValue |
| CBOR encoding | ✓ | shortest-form deterministic, fxamacker/cbor |
| Tag-24 wrapping | ✓ | freezes bytes before hashing |
| SHA-256 valueDigests | ✓ | `hash(Tag24(CBOR(item)))` per item |
| Randomized digest-ID assignment | ✓ | claim order is cryptographically shuffled before digestID assignment (not sorted) — prevents a verifier inferring undisclosed claims' relative order from a disclosed claim's digestID, matching Multipaz's `MdocUtil.generateIssuerNameSpaces` |
| MSO construction | ✓ | version, digestAlgorithm, valueDigests, docType, validityInfo, deviceKeyInfo |
| `deviceKeyInfo` in MSO | ✓ | holder's public key embedded at issuance, COSEKey uses `keyasint` (real CBOR int keys per RFC 9053) |
| `MobileSecurityObjectBytes`/`DeviceAuthenticationBytes` framing | ✓ | issuerAuth's and deviceAuth's payloads are each Tag24-wrapped as a whole (`24(<<{...}>>)`), not just the individual items inside them — confirmed against the AV Blueprint's own §A.11 worked example (MSO) and Multipaz's `MdocDocument.kt` signing code (DeviceAuthentication) |
| COSE_Sign1 issuerAuth | ✓ | ES256, x5chain (header 33) carries DS + IACA cert |
| Two-level certificate chain | ✓ | IACA root CA → DS cert, real x509 chain walk |
| Chain attack rejection | ✓ | untrusted root rejected before signature check |
| Configurable verifier clock | ✓ | `NewVerifierWithClock` — tests expired / not-yet-valid certs and MSO validity deterministically |
| MSO `validityInfo` check (validFrom/validUntil) | ✓ | checked separately from X.509 cert expiry — both are mandatory per ISO 18013-5 |
| Selective disclosure | ✓ | holder filters items, issuerAuth reused unchanged |
| Digest verification | ✓ | constant-time comparison via `crypto/subtle` |
| Tamper detection | ✓ | digest mismatch on value tampering |
| `deviceSigned` / `deviceAuth` | ✓ | `SignDeviceAuth` + `VerifyWithDeviceAuth` — fresh COSE_Sign1 per session, checked against `deviceKeyInfo` |
| Device-binding replay/clone rejection | ✓ | wrong signer and wrong-session deviceAuth both rejected |
| Real OpenID4VP `SessionTranscript`/`Handover` | ✓ | `NewOpenID4VPSessionTranscript` — `["OpenID4VPHandover", SHA-256(CBOR([clientId, nonce, null, responseUri]))]`, matching Multipaz's `vpSessionTranscript` for the AV Blueprint's `response_mode=direct_post` case |
| `DeviceSigned` wrapper struct | ✓ | `AttachDeviceSigned` populates an `MDoc.DeviceSigned` field (deviceAuth + empty deviceNameSpaces), matching ISO 18013-5's actual document shape instead of passing deviceAuth bytes around separately |
| `DeviceResponse` container | ✓ | `NewDeviceResponse`/`VerifyDeviceResponse` — real response container, holds one or more documents; reader authentication deliberately omitted per Annex A §A.6 |
| DCQL request (`dcql_query`) | ✓ | `NewDCQLQuery`/`RequestedAttributes`/`CredentialQueryId` — mirrors `eudi/openid4vp/dcql`'s `DcqlQuery`/`CredentialQuery`/`Claim` shape (`format: mso_mdoc`, `meta.doctype_value`, `claims[].path = [namespace, elementIdentifier]`), matching the AV Blueprint's own worked example byte-for-byte in JSON form |
| `vp_token` encode/decode | ✓ | `NewVPTokenJSON`/`ParseVPTokenJSON` — base64url CBOR `DeviceResponse` wrapped in the `{queryId: [credential]}` JSON shape `response_mode=direct_post` actually POSTs, mirroring `eudi/openid4vp/response.go`'s `createDirectPostVpToken` |
| `direct_post` form body + `state` | ✓ | `NewDirectPostForm`/`ParseDirectPostForm` — the real `application/x-www-form-urlencoded` body (`vp_token=...&state=...`), matching `eudi/openid4vp/response.go`'s `createAuthorizationResponseHttpRequest` exactly; `state` (`AuthorizationRequest.State`) is carried through opaque and unchanged — unlike `nonce`, it never enters any hash or signature, it's pure anti-CSRF/session-correlation bookkeeping |
| Session encryption (BLE/NFC) | ✗ | transport layer not built; also explicitly out of scope for the AV Blueprint (proximity presentation is excluded — see Annex A §A.6) |
| W3C Digital Credentials API path (`DeviceRequest`, HPKE `EncryptedResponse`) | ✗ | out of scope for this package by design — see "OpenID4VP only" below |

---

## Containment hierarchy — what actually wraps what

`DeviceResponse` is the top-level *Go type* in this package — `MDoc` doesn't know or
care whether it's traveling alone or bundled with other documents, `DeviceResponse` is
what holds a list of them (`Documents []MDoc`, plural — see
`TestNewDeviceResponseSupportsMultipleDocuments`). But `DeviceResponse` itself isn't the
outermost thing on the wire. Over OpenID4VP, two more layers sit on top of it:

```
direct_post form body (application/x-www-form-urlencoded, the actual HTTP POST body)
  └── "vp_token=...&state=..."                              ← NewDirectPostForm / ParseDirectPostForm
        └── vp_token value (JSON)
              └── {queryId: [ base64url( CBOR( DeviceResponse ) ) ]}   ← NewVPTokenJSON / ParseVPTokenJSON
                    └── DeviceResponse                                  ← NewDeviceResponse / VerifyDeviceResponse
                          └── Documents []MDoc                          ← one or more, per presentation
                                ├── DocType
                                ├── IssuerSigned{NameSpaces, IssuerAuth}  ← issuer's signature, fixed since issuance
                                └── DeviceSigned{NameSpaces, DeviceAuth}  ← holder's signature, fresh per session
```

`state` rides alongside `vp_token` as a sibling form field, not nested inside it — it's
opaque bookkeeping the verifier invents and the holder echoes back unchanged, and never
touches the CBOR/JSON payload at all (see `NewDirectPostForm`).

So "the topmost container" depends on which layer you mean: within this package's own
Go types, `DeviceResponse` is outermost. On the actual OpenID4VP wire, the
`application/x-www-form-urlencoded` HTTP body is outermost, `vp_token`'s JSON object is
one layer inside that, and `DeviceResponse` is the (CBOR-encoded, base64url'd) payload
sitting inside one of its array entries.

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
| `issuer_test.go` | `TestIssueRejectsDisallowedAttribute` | Any attribute other than `age_over_18`/`age_over_NN` (e.g. `family_name`) is rejected per Annex A §4.1.2 |
| `issuer_test.go` | `TestIssueRejectsNonBooleanValue` | A non-bool value (e.g. `"true"` as a string) is rejected |
| `issuer_test.go` | `TestIssueRejectsMissingMandatoryAgeOver18` | Claim sets missing the mandatory `age_over_18` are rejected |
| `issuer_test.go` | `TestIssueAcceptsValidAgeOverNNVariants` | Multiple valid `age_over_NN` variants alongside `age_over_18` issue cleanly |
| `verifier_test.go` | `TestUntrustedRootIsRejected` | Attacker's own valid IACA→DS chain, signed correctly, still rejected — root isn't in the verifier's trust pool |
| `verifier_test.go` | `TestTamperedDigestIsRejected` | Flipped claim value fails the digest check |
| `verifier_test.go` | `TestDeviceAuthWrongSignerIsRejected` | Cloned mdoc — deviceAuth signed by a different device's key — rejected |
| `verifier_test.go` | `TestDeviceAuthWrongSessionIsRejected` | Correct device key, but signed over a different session transcript (replay) — rejected |
| `verifier_test.go` | `TestUnknownDigestIDIsRejected` | A digestID absent from the MSO's `valueDigests` is rejected |
| `verifier_test.go` | `TestFreshCertsVerifyUnderCurrentTime` | Sanity check — freshly issued certs verify under the real current time (no off-by-one in validity math) |
| `verifier_test.go` | `TestExpiredDSCertIsRejected` | Verifier clock pinned ~400 days ahead (past the DS cert's 365-day window) — chain correctly rejected as expired |
| `verifier_test.go` | `TestExpiredMSOValidityIsRejected` | Verifier clock pinned ~100 days ahead (past the MSO's 90-day `validUntil`, but still within the DS cert's 365-day window) — rejected on the MSO's own validity, distinct from the cert check |
| `verifier_test.go` | `TestNotYetValidMSOIsRejected` | Verifier clock pinned between the (backdated) cert `NotBefore` and the MSO's `validFrom` — isolates the MSO validityInfo check specifically, distinct from cert validity |
| `verifier_test.go` | `TestNotYetValidCertIsRejected` | Verifier clock pinned before the certs' `NotBefore` — chain correctly rejected as not-yet-valid |
| `verifier_test.go` | `TestDeviceAuthStillVerifiesWithDetachedPayload` | Detaching the deviceAuth payload doesn't break verification — the verifier reconstructs it itself |
| `sessiontranscript_test.go` | `TestOpenID4VPSessionTranscriptShape` | `NewOpenID4VPSessionTranscript` produces `[null, null, ["OpenID4VPHandover", digest]]`, and the digest matches an independently-computed `SHA-256(CBOR([clientId, nonce, null, responseUri]))` |
| `sessiontranscript_test.go` | `TestOpenID4VPSessionTranscriptBindsAllInputs` | `clientId`, `nonce`, and `responseUri` each independently change the resulting digest — none of them can be silently ignored |
| `sessiontranscript_test.go` | `TestOpenID4VPSessionTranscriptIntegratesWithDeviceAuth` | A real OpenID4VP-shaped transcript actually plugs into `SignDeviceAuth`/`VerifyWithDeviceAuth`; a verifier deriving the transcript from a mismatched nonce correctly rejects the signature |
| `dcqlquery_test.go` | `TestNewDCQLQueryRoundTrips` | `NewDCQLQuery` + `RequestedAttributes` round-trips the exact namespace and attribute list requested |
| `dcqlquery_test.go` | `TestDCQLQueryRejectsUnknownDocType` | `RequestedAttributes` errors for a docType that was never requested, instead of silently returning a zero result |
| `dcqlquery_test.go` | `TestDCQLQueryRejectsMismatchedNamespaceClaims` | A (malformed, for this single-namespace profile) query whose claims span more than one namespace is rejected rather than silently returning just the first claim's namespace |
| `dcqlquery_test.go` | `TestDCQLQueryMatchesBlueprintWorkedExample` | `NewDCQLQuery`'s JSON output matches the AV Blueprint's own worked example shape (`format`, `meta.doctype_value`, `claims[].path`) field-for-field |
| `dcqlquery_test.go` | `TestCredentialQueryIdRoundTrips` | `CredentialQueryId` returns the exact id the query was built with, and errors for an unrequested docType |
| `deviceresponse_test.go` | `TestAttachDeviceSignedRoundTrips` | `AttachDeviceSigned` populates `MDoc.DeviceSigned` with the exact deviceAuth bytes passed in, and returns a copy — the original mdoc is left untouched |
| `deviceresponse_test.go` | `TestVerifyDeviceResponseSucceeds` | Full flow through the real `DeviceResponse` container (`AttachDeviceSigned` → `NewDeviceResponse` → `VerifyDeviceResponse`) produces the same result as calling `VerifyWithDeviceAuth` directly |
| `deviceresponse_test.go` | `TestVerifyDeviceResponseRejectsMissingDeviceSigned` | A document without `DeviceSigned` attached is rejected with a descriptive error, not a nil-dereference panic |
| `deviceresponse_test.go` | `TestNewDeviceResponseSupportsMultipleDocuments` | A `DeviceResponse` bundling two distinct holders' documents from the same issuer verifies each document independently and correctly |
| `deviceresponse_test.go` | `TestDeviceAuthSignatureEncodesInline` | `DeviceAuth.DeviceSignature` embeds as structured CBOR (`cbor.RawMessage`), not as an opaque re-encoded byte string |
| `vptoken_test.go` | `TestVPTokenRoundTrips` | `NewVPTokenJSON` + `ParseVPTokenJSON` is a faithful round trip — the `DeviceResponse` that comes back out verifies exactly like the original |
| `vptoken_test.go` | `TestVPTokenShape` | The vp_token JSON is `{queryId: [base64url(no padding) CBOR credential]}`, matching `response_mode=direct_post`'s actual wire shape |
| `vptoken_test.go` | `TestVPTokenRejectsUnknownQueryId` | `ParseVPTokenJSON` errors for a query id the vp_token has no credential for, instead of returning a zero-value `DeviceResponse` |
| `directpost_test.go` | `TestDirectPostFormRoundTrips` | `NewDirectPostForm` + `ParseDirectPostForm` round-trips both the `DeviceResponse` and the `state` value; the response still verifies correctly |
| `directpost_test.go` | `TestDirectPostFormShape` | The body is real `application/x-www-form-urlencoded` with `vp_token` and `state` as separate fields, matching `eudi/openid4vp/response.go`'s `createAuthorizationResponseHttpRequest` shape |
| `directpost_test.go` | `TestDirectPostFormPreservesEmptyState` | An empty `state` round-trips as empty, rather than being conflated with "field absent" |
| `directpost_test.go` | `TestDirectPostFormRejectsMissingVPToken` | A malformed body with no `vp_token` field errors out instead of returning a zero-value `DeviceResponse` |

`testhelpers_test.go` holds `buildHappyPathMDoc`, `keysOf`, and `unwrapTag24Generic` —
shared fixtures/helpers used across the files above, rather than duplicated per-file.

Run with:

```bash
go test -v .
```

### `decode/` — standalone CBOR/COSE inspector

A separate CLI tool (own `package main`, own directory — Go requires each binary to
live in its own package) for manually inspecting any hex-encoded COSE_Sign1 or CBOR
blob produced by the program:

```bash
cd decode
go run decode.go <hex-string>
```

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

Per EU AV Blueprint Annex A §4.1.1 and §4.1.2:

```
docType:    eu.europa.ec.av.1
namespace:  eu.europa.ec.av.1
attributes: age_over_18 (mandatory), age_over_NN (optional)
            no other attributes permitted
```

---

## Running

This is a library package (`package mdoc`) — `main.go` no longer lives at the module
root, so there's nothing to `go run .` directly. Two ways to run it:

```bash
# first time only
go mod tidy

# runnable walkthrough — a separate package main under cmd/ that imports mdoc
# and drives it purely through the exported API (NewIssuer, Issue, Verify, ...)
go run ./cmd/demo

# full test suite — same walkthrough plus all regression/negative cases.
# The library itself (Issue, SelectiveDisclose, Verify, VerifyWithDeviceAuth)
# prints nothing — a real consumer importing mdoc shouldn't get unsolicited
# stdout output — so this just shows pass/fail per test, plus a few
# deliberate t.Logf calls (e.g. the CBOR/COSE hex dumps in mdoc_test.go)
go test -v .

# just the happy-path issuance → disclosure → verification walkthrough
go test -v -run TestFullIssuanceFlow_ProducesValidMDoc .
```

`cmd/demo/main.go` is intentionally a separate package rather than living in the
`mdoc` package itself — it only calls exported functions (`Issuer.IACACert()`,
`Holder.PublicKey()`, etc.), the same way any real external consumer of this
package would.

The demo also takes care not to let the verifier and holder implicitly share
state that a real, separate wallet and verifier never would: the verifier's DCQL
query is `json.Marshal`'d and the holder only ever works with a fresh
`json.Unmarshal` of that JSON (`receivedQuery`), the same way a wallet would only
ever see the query as it arrived over the wire. In particular, the holder
recovers the vp_token response key via `receivedQuery.CredentialQueryId(docType)`
rather than reusing the verifier's own `verifierQueryId` Go variable — the two
values are computed independently and only match because the protocol works, not
because they're the same variable. `clientId`/`nonce`/`responseUri` are still
hardcoded on both sides, though (see "Known gaps" below) — there's no real
Authorization Request being parsed for those.

---

## Expected output

Output from `go run ./cmd/demo`:

```
========================================
  mDoc Issuer → Holder → Verifier Demo
  with two-level cert chain + deviceKeyInfo
========================================

IACA root CA generated (self-signed, offline in production)
  Subject: Test Age Verification IACA Root CA
DS cert generated (signed by IACA root)
  Subject: Test Age Verification DS - 001
  Issuer:  Test Age Verification IACA Root CA

Device key generated (x: <16 hex chars>...)

--- ISSUER: Building mDoc ---
  Claim: age_over_16 = true
  Claim: age_over_18 = true
  Claim: age_over_21 = false
  MSO signed by DS cert ✓  (1406 bytes)
  x5chain: DS cert + IACA cert
  deviceKeyInfo: embedded holder public key ✓

--- VERIFIER: Requesting attributes (DCQL over OpenID4VP) ---
  dcql_query: format=mso_mdoc, doctype_value=eu.europa.ec.av.1, claims=[eu.europa.ec.av.1.age_over_18]

--- HOLDER: Selective disclosure ---
  Withholding: age_over_16
  Revealing:   age_over_18
  Withholding: age_over_21

deviceAuth signed ✓  (74 bytes)
  (fresh per session — binds presentation to this verifier + session)

direct_post form built ✓  (2402 bytes, POSTed to response_uri as application/x-www-form-urlencoded)
  state echoed back correctly ✓  (anti-CSRF check passed)

--- VERIFIER: Verifying mDoc ---
  age_over_18 = true  digest: ✓
  Verification: PASSED ✓
  deviceAuth signature: valid ✓  (matches session transcript)

========================================
  RESULT
========================================
  DocType:          eu.europa.ec.av.1
  Valid:            true
  DeviceAuth Valid: true
  Disclosed attributes:
    age_over_18 = true

========================================
  CHAIN ATTACK TEST (attacker's own cert chain)
========================================

--- ISSUER: Building mDoc ---
  Claim: age_over_18 = true
  MSO signed by DS cert ✓  (1331 bytes)
  x5chain: DS cert + IACA cert
  deviceKeyInfo: embedded holder public key ✓

--- HOLDER: Selective disclosure ---
  Revealing:   age_over_18

--- VERIFIER: Verifying mDoc ---
  Attacker's mDoc valid: false
  Error: chain verification failed: x509: certificate signed by unknown authority ...
  (correctly rejected — attacker's root not trusted ✓)

========================================
  DEVICE-KEY MISMATCH TEST (cloned mdoc, wrong signer)
========================================

--- VERIFIER: Verifying mDoc ---
  age_over_18 = true  digest: ✓
  Verification: PASSED ✓
  Cloned mdoc deviceAuth valid: false
  Error: deviceAuth signature invalid: verification error
  (correctly rejected — deviceAuth signed by wrong key ✓)
```

Note what changed from earlier drafts of this demo: the per-item `salt`/`Digest[N]` hex
lines and the granular "Certificate chain: valid ✓" / "MSO signature: valid ✓" / "MSO
validityInfo: within window ✓" sub-steps are gone. Those used to come from `fmt.Println`
calls **inside** `Issue`/`Verify` themselves — but a real consumer importing `mdoc` as a
dependency shouldn't get unsolicited console output on every call (this is the same
convention `sdjwtvc` follows: zero `fmt.Println`/`fmt.Printf` in its non-test source).
The library now returns values only; everything printed above is reconstructed here in
`cmd/demo/main.go` purely from `mdoc`'s exported API (`credential.IssuerSigned.IssuerAuth`,
`VerificationResult.Attributes`, etc.) — nothing the demo prints required new exports.

The demo skips the tamper-detection scenario — constructing a tampered item requires
the package's internal `tag24Wrap` helper, which isn't exported (deliberately: real
external callers never need to hand-craft an `IssuerSignedItem`). That scenario, plus
all of the above, are covered as proper tests instead — see `TestUntrustedRootIsRejected`,
`TestTamperedDigestIsRejected`, and `TestDeviceAuthWrongSignerIsRejected` in the test
table above. Since the library is silent, `go test -v .` no longer reproduces this
narrative output — it just shows `PASS`/`FAIL` per test plus the deliberate `t.Logf` hex
dumps of the presented mdoc, `issuerAuth`, and `deviceAuth` (`mdoc_test.go:28,32,36`),
with a final `PASS`/`ok` summary.

---

## Known gaps vs real mDoc

### OpenID4VP only — the W3C Digital Credentials API path is out of scope by design

The AV Blueprint's Annex A §A.6 states the W3C Digital Credentials API is the
*default* presentation method, with OpenID4VP only as a *fallback*. This package
deliberately models the OpenID4VP fallback path exclusively — everything here
(`DCQLQuery`, `NewVPTokenJSON`/`ParseVPTokenJSON`, `NewOpenID4VPSessionTranscript`)
is OpenID4VP-shaped. Concretely out of scope as a result:

- ISO 18013-5's native `DeviceRequest` CBOR object (§8.3.2.1.2.1) — the blueprint
  confirms this is used *exclusively* by the DC API path; OpenID4VP requests
  attributes via a DCQL query instead (JSON, see `DCQLQuery`), which is what this
  package implements.
- The DC API's `EncryptedResponse = ["dcapi", {enc, cipherText}]` wrapper, where
  `cipherText` is `DeviceResponse` encrypted with HPKE (RFC 9180). OpenID4VP's
  `response_mode=direct_post` sends `DeviceResponse` unencrypted (as base64url CBOR
  inside the vp_token JSON — see `NewVPTokenJSON`), so no HPKE layer is needed for
  the path this package actually implements.

### No session encryption / transport layer

Real ISO 18013-5 *proximity* presentations happen over BLE or NFC, with session keys
derived via ECDH from a QR-code-carried verifier ephemeral key, then AES-GCM/AES-CCM
encrypting the actual `DeviceRequest`/`DeviceResponse` exchange. None of that transport
layer is modeled here — and per the AV Blueprint's own Annex A §A.6, it doesn't need to
be: proximity presentation is explicitly out of scope for this profile.

`NewOpenID4VPSessionTranscript`, `NewDCQLQuery`, `NewVPTokenJSON`/`ParseVPTokenJSON`, and
`NewDirectPostForm`/`ParseDirectPostForm` together model the OpenID4VP-shaped request →
disclosure → response wire format end-to-end, down to the real
`application/x-www-form-urlencoded` HTTP body shape (see `cmd/demo/main.go`) — but none
of it is wired into an actual HTTP client/server yet (no real Authorization Request
parsing, no real HTTP POST over a socket). The demo and
`TestOpenID4VPSessionTranscriptIntegratesWithDeviceAuth` use hardcoded
`clientId`/`nonce`/`responseUri`/`state` values rather than ones parsed from a real
Authorization Request.

### Verifier sees total digest count

The full `issuerAuth` (all digests) travels with every presentation. The verifier can
call `len(mso.ValueDigests[namespace])` to learn how many total claims exist, even for
undisclosed ones. Values are hidden — count is not.

(Digest*order* is a separate concern and is handled: `Issue()` assigns digestIDs via a
cryptographically random shuffle, not a sorted/deterministic order — see the comment on
`shuffleIdentifiers` in `issuer.go` — so a disclosed claim's digestID reveals nothing
about undisclosed claims' relative position. Only the *count* remains visible.)

### No verifier-side certificate / relying-party authentication

Real deployments (e.g. Yivi's production trust model) also have a separate CA branch
for relying parties (`Yivi Relying Parties CA` alongside `Yivi Attestation Providers
CA`, both under one root), letting a verifier authenticate *itself* to the holder's
wallet before requesting data. This program only models the issuer-side chain; there
is no equivalent verifier-side cert or check.

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
- IANA COSE Algorithms registry — `-7` = ES256
- IANA COSE Key Types registry — `1`=kty, `-1`=crv, `-2`=x, `-3`=y
