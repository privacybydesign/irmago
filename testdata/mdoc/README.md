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
| Deterministic claim ordering | ✓ | claims sorted before digestID assignment — reproducible across runs |
| MSO construction | ✓ | version, digestAlgorithm, valueDigests, docType, validityInfo, deviceKeyInfo |
| `deviceKeyInfo` in MSO | ✓ | holder's public key embedded at issuance, COSEKey uses `keyasint` (real CBOR int keys per RFC 9053) |
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
| `DeviceSigned` wrapper struct | ✗ | deviceAuth exists as standalone bytes; not wired into a `DeviceSigned` field on `MDoc` |
| `DeviceRequest` / `DeviceResponse` | ✗ | verifier request/response container format not built |
| Session encryption (BLE/NFC) | ✗ | transport layer not built |

---

## Test suite

`main_test.go` exercises the pipeline end to end plus targeted regression/negative cases:

| Test | What it checks |
|---|---|
| `TestFullIssuanceFlow_ProducesValidMDoc` | Full issuer → holder → verifier round trip; also logs the real CBOR/COSE hex of the presented mdoc, `issuerAuth`, and `deviceAuth` for external inspection (e.g. via [cbor.me](https://cbor.me)) |
| `TestCOSEKeyUsesIntegerMapKeys` | Decodes the real MSO bytes generically and asserts `deviceKey`'s map keys are actual CBOR integers — regression test for the `keyasint` struct-tag fix |
| `TestClaimOrderingIsDeterministic` | Issues the same claims twice, confirms `digestID` assignment is identical both times |
| `TestUntrustedRootIsRejected` | Attacker's own valid IACA→DS chain, signed correctly, still rejected — root isn't in the verifier's trust pool |
| `TestTamperedDigestIsRejected` | Flipped claim value fails the digest check |
| `TestDeviceAuthWrongSignerIsRejected` | Cloned mdoc — deviceAuth signed by a different device's key — rejected |
| `TestDeviceAuthWrongSessionIsRejected` | Correct device key, but signed over a different session transcript (replay) — rejected |
| `TestUnknownDigestIDIsRejected` | A digestID absent from the MSO's `valueDigests` is rejected |
| `TestFreshCertsVerifyUnderCurrentTime` | Sanity check — freshly issued certs verify under the real current time (no off-by-one in validity math) |
| `TestExpiredDSCertIsRejected` | Verifier clock pinned ~400 days ahead (past the DS cert's 365-day window) — chain correctly rejected as expired |
| `TestExpiredMSOValidityIsRejected` | Verifier clock pinned ~100 days ahead (past the MSO's 90-day `validUntil`, but still within the DS cert's 365-day window) — rejected on the MSO's own validity, distinct from the cert check |
| `TestNotYetValidMSOIsRejected` | Verifier clock pinned between the (backdated) cert `NotBefore` and the MSO's `validFrom` — isolates the MSO validityInfo check specifically, distinct from cert validity |
| `TestNotYetValidCertIsRejected` | Verifier clock pinned before the certs' `NotBefore` — chain correctly rejected as not-yet-valid |

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

```bash
# first time only
go mod tidy

go run .\main.go        # Windows
go run ./main.go        # Linux/macOS

# test suite
go test -v .
```

---

## Expected output

```
IACA root CA generated (self-signed, offline in production)
  Subject: Test Age Verification IACA Root CA
DS cert generated (signed by IACA root)
  Subject: Test Age Verification DS - 001
  Issuer:  Test Age Verification IACA Root CA

--- ISSUER: Building mDoc ---
  Item 0: age_over_16 = true   (salt: <32 hex chars>)
  Item 1: age_over_18 = true   (salt: <32 hex chars>)
  Item 2: age_over_21 = false  (salt: <32 hex chars>)
  Digest[0..2]: <64 hex chars each>
  MSO signed by DS cert ✓
  x5chain: DS cert + IACA cert
  deviceKeyInfo: embedded holder public key ✓

--- HOLDER: Selective disclosure ---
  Withholding: age_over_16
  Revealing:   age_over_18
  Withholding: age_over_21

deviceAuth signed ✓  (fresh per session — binds presentation to this verifier + session)

--- VERIFIER: Verifying mDoc ---
  Certificate chain: valid ✓  (depth 2: DS → IACA root)
  MSO signature: valid ✓
  age_over_18 = true  digest: ✓
  Verification: PASSED ✓
  deviceAuth signature: valid ✓  (matches session transcript)

CHAIN ATTACK TEST:
  Attacker's mDoc valid: false
  Error: chain verification failed: x509: certificate signed by unknown authority

TAMPER TEST:
  Tampered valid: false
  Error: digest mismatch for age_over_18

DEVICE-KEY MISMATCH TEST:
  Cloned mdoc deviceAuth valid: false
  Error: deviceAuth signature invalid: verification error
```

---

## Known gaps vs real mDoc

### No `DeviceRequest` / `DeviceResponse` wrapper

The program builds and verifies an `MDoc` directly. Real ISO 18013-5 wraps this in a
`DeviceResponse` (top-level container, potentially multiple documents) on the
response side and a `DeviceRequest` (itemsRequest, requested docType/namespaces) on
the verifier's request side. Neither container exists here — everything is exercised
by calling the issuer/holder/verifier functions directly rather than through those
message formats.

### No session encryption / transport layer

Real presentations happen over BLE or NFC, with session keys derived via ECDH from a
QR-code-carried verifier ephemeral key, then AES-GCM/AES-CCM encrypting the actual
`DeviceRequest`/`DeviceResponse` exchange. None of that transport layer is modeled —
`SessionTranscript` here is a hardcoded stub, not derived from a real engagement.

### Verifier sees total digest count

The full `issuerAuth` (all digests) travels with every presentation. The verifier can
call `len(mso.ValueDigests[namespace])` to learn how many total claims exist, even for
undisclosed ones. Values are hidden — count is not.

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
