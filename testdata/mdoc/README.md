# mDoc Issuer → Holder → Verifier (Go)

A minimal, self-contained implementation of ISO 18013-5 mDoc selective disclosure,
built against the EU Age Verification Blueprint (Annex A, `eu.europa.ec.av.1`).

Written to learn how mDoc, CBOR, COSE_Sign1, Tag-24 wrapping, and selective disclosure
fit together — not production code.

---

## What it implements

| Component | Status | Notes |
|---|---|---|
| `IssuerSignedItem` (4-field envelope) | ✓ | digestID, random, elementIdentifier, elementValue |
| CBOR encoding (fxamacker/cbor) | ✓ | shortest-form deterministic encoding |
| Tag-24 wrapping | ✓ | freezes bytes before hashing |
| SHA-256 valueDigests | ✓ | per-item, `hash(Tag24(CBOR(item)))` |
| MSO construction | ✓ | version, digestAlgorithm, valueDigests, docType, validityInfo |
| COSE_Sign1 issuerAuth | ✓ | ES256 (ECDSA P-256 + SHA-256), x5chain in header 33 |
| Self-signed DS certificate | ✓ | test only — no IACA → DS chain |
| Selective disclosure | ✓ | holder filters which items to reveal, issuerAuth reused unchanged |
| Digest verification | ✓ | recomputes hash, matches against MSO valueDigests |
| Tamper detection | ✓ | demonstrates digest mismatch on value tampering |
| `deviceKeyInfo` in MSO | ✗ | not implemented — device key not embedded at issuance |
| `deviceSigned` / `deviceAuth` | ✗ | not implemented — no proof of device possession |
| IACA → DS certificate chain | ✗ | self-signed cert used instead |
| `DeviceRequest` | ✗ | verifier request format not built |
| `DeviceResponse` wrapper | ✗ | top-level container not built |
| Session encryption (BLE/NFC) | ✗ | transport layer not built |

---

## Crypto suite

Matches EU AV Blueprint Annex A §A.7 — mandatory, no alternatives:

```
Key type:   P-256 (secp256r1)
Algorithm:  ES256 (ECDSA + P-256 + SHA-256), COSE alg id = -7
Hash:       SHA-256
Encoding:   CBOR (RFC 8949), deterministic shortest-form
Signing:    COSE_Sign1 (RFC 9052)
```

---

## Data model

Namespace and docType per EU AV Blueprint Annex A §4.1.1 and §4.1.2:

```
docType:   eu.europa.ec.av.1
namespace: eu.europa.ec.av.1
allowed attributes: age_over_18 (mandatory), age_over_NN (optional)
no other attributes permitted
```

---

## Structure

### `main.go`

All code lives in one file, divided into four sections:

```
Data structures     IssuerSignedItem, MSO, IssuerSigned, MDoc, Tag24Item, etc.
Tag-24 helpers      tag24Wrap(), hashTag24Item(), mustMarshal()
Issuer              NewIssuer(), Issue()
Holder              SelectiveDisclose()
Verifier            NewVerifier(), Verify()
main()              wires everything together + runs a tamper test
```

### `go.mod`

```
module mdoc_test
go 1.21
requires: github.com/fxamacker/cbor/v2, github.com/veraison/go-cose
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/fxamacker/cbor/v2` | CBOR encoding/decoding, Tag-24 wrapping |
| `github.com/veraison/go-cose` | COSE_Sign1 signing and verification |
| `crypto/ecdsa`, `crypto/elliptic` | P-256 key generation (Go stdlib) |
| `crypto/rand` | OS CSPRNG via `/dev/urandom` or `BCryptGenRandom` |
| `crypto/sha256` | SHA-256 digest computation |
| `crypto/x509` | Self-signed DS certificate construction |

---

## Running

```bash
# first time only — downloads dependencies, generates go.sum
go mod tidy

# run
go run .\main.go        # Windows
go run ./main.go        # Linux/macOS
```

---

## Expected output

```
========================================
  mDoc Issuer → Holder → Verifier Test
========================================

Issuer key pair and cert generated

--- ISSUER: Building mDoc ---
  Item 0: age_over_18 = true   (salt: <32 random hex chars>)
  Item 1: age_over_16 = true   (salt: <32 random hex chars>)
  Item 2: age_over_21 = false  (salt: <32 random hex chars>)
  Digest[0]: <64 hex chars>
  Digest[1]: <64 hex chars>
  Digest[2]: <64 hex chars>
  MSO signed: 710 bytes

--- HOLDER: Selective disclosure ---
  Revealing:   age_over_18
  Withholding: age_over_16
  Withholding: age_over_21

--- VERIFIER: Verifying mDoc ---
  Issuer cert: trusted ✓
  MSO signature: valid ✓
  age_over_18 = true  digest: ✓
  Verification: PASSED ✓

========================================
  RESULT
========================================
  DocType:  eu.europa.ec.av.1
  Valid:    true
  Disclosed attributes:
    age_over_18 = true

========================================
  TAMPER TEST (flip age_over_18 to false)
========================================
  Tampered valid: false
  Error: digest mismatch for age_over_18
  (tamper correctly rejected ✓)
```

---

## What is NOT checked (known gaps vs real mDoc)

### 1. No IACA → DS certificate chain validation

The verifier only checks if the cert matches its trusted list directly
(shallow equality, no chain walk). A real verifier would:

```
dsCert chains to intermediateCert chains to IACARootCert
```

Our self-signed test cert acts as both root and DS simultaneously —
so anyone with a self-signed cert would pass verification.

### 2. No deviceAuth (replay attack possible)

Without `deviceSigned` / `deviceAuth`, a valid `presented` mDoc can be
replayed verbatim to any verifier. A real implementation would:

```
1. Embed holder's public key in MSO.deviceKeyInfo at issuance
2. Holder signs DeviceAuthentication (containing fresh SessionTranscript)
   using their device private key at each presentation
3. Verifier checks deviceAuth against deviceKeyInfo in the trusted MSO
```

### 3. Verifier sees total digest count

The verifier receives the full `issuerAuth` (containing all digests), so
it can call `len(mso.ValueDigests[namespace])` and learn how many total
claims exist — even for undisclosed ones. Only the *values* are hidden,
not the *count*.

---

## Key concepts covered

| Concept | Where in code |
|---|---|
| CBOR major types and length encoding | implicit in `cbor.Marshal()` calls |
| Tag-24 `D8 18` wrap (freeze bytes) | `tag24Wrap()` |
| Deterministic encoding requirement | enforced by fxamacker/cbor |
| Salt (`random`) purpose | `rand.Read(salt)` in `Issue()` |
| `digestID` as index into valueDigests | `IssuerSignedItem.DigestID` field |
| COSE_Sign1 `[protected, unprotected, payload, signature]` | `cose.NewSign1Message()` |
| protected headers `{1: -7}` = `{alg: ES256}` | `msg.Headers.Protected.SetAlgorithm()` |
| unprotected header 33 = x5chain (DS cert) | `msg.Headers.Unprotected[int64(33)]` |
| Sig_structure (what ECDSA actually signs) | handled internally by go-cose |
| Selective disclosure = filter NameSpaces, reuse issuerAuth | `SelectiveDisclose()` |
| Tamper detection via digest mismatch | `Verify()` + tamper test in `main()` |

---

## References

- ISO 18013-5 — mDoc/mDL standard
- RFC 8949 — CBOR
- RFC 9052 — COSE (CBOR Object Signing and Encryption)
- EU Age Verification Blueprint Annex A — `eu.europa.ec.av.1` profile
- IANA COSE Algorithms registry — algorithm numbers (`-7` = ES256)
- IANA COSE Key Types registry — key parameter labels (`1`=kty, `-1`=crv, `-2`=x, `-3`=y)
