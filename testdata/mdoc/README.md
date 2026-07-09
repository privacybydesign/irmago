# mDoc Issuer → Holder → Verifier (Go)

A minimal, self-contained implementation of ISO 18013-5 mDoc selective disclosure,
built against the EU Age Verification Blueprint (Annex A, `eu.europa.ec.av.1`).

Not production code — written to understand how mDoc, CBOR, COSE_Sign1, Tag-24,
certificate chains, and selective disclosure fit together.

---

## What it implements

| Component | Status | Notes |
|---|---|---|
| `IssuerSignedItem` (4-field envelope) | ✓ | digestID, random, elementIdentifier, elementValue |
| CBOR encoding | ✓ | shortest-form deterministic, fxamacker/cbor |
| Tag-24 wrapping | ✓ | freezes bytes before hashing |
| SHA-256 valueDigests | ✓ | `hash(Tag24(CBOR(item)))` per item |
| MSO construction | ✓ | version, digestAlgorithm, valueDigests, docType, validityInfo |
| COSE_Sign1 issuerAuth | ✓ | ES256, x5chain (header 33) carries DS + IACA cert |
| Two-level certificate chain | ✓ | IACA root CA → DS cert, real x509 chain walk |
| Chain attack rejection | ✓ | untrusted root rejected before signature check |
| Selective disclosure | ✓ | holder filters items, issuerAuth reused unchanged |
| Digest verification | ✓ | constant-time comparison via `crypto/subtle` |
| Tamper detection | ✓ | digest mismatch on value tampering |
| `deviceKeyInfo` in MSO | ✗ | device key not embedded at issuance |
| `deviceSigned` / `deviceAuth` | ✗ | no proof of device possession |
| `DeviceRequest` / `DeviceResponse` | ✗ | verifier request format not built |
| Session encryption (BLE/NFC) | ✗ | transport layer not built |

---

## Certificate chain

```
IACA root CA  (self-signed, IsCA=true, offline in production)
      ↓ signs
DS cert       (IsCA=false, signs every MSO)
      ↓ signs
MSO           (inside COSE_Sign1 issuerAuth)
```

x5chain header 33 carries `[DS cert, IACA cert]`.
The verifier pre-installs only the IACA root cert — DS cert arrives with each mDoc.

### Deployment phases

| Phase | Trust anchor | Status |
|---|---|---|
| 1 — testing | self-signed IACA root (this code) | current |
| 2 — pilot | Yivi's own IACA root, manually configured on verifiers | next |
| 3 — production | EU AV Blueprint root CA, registered AP trust list | future |

---

## Crypto suite

Matches EU AV Blueprint Annex A §A.7:

```
Key type:   P-256 (secp256r1)
Algorithm:  ES256 (ECDSA + P-256 + SHA-256), COSE alg id = -7
Hash:       SHA-256
Encoding:   CBOR (RFC 8949), deterministic shortest-form
Signing:    COSE_Sign1 (RFC 9052)
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
  Item 0: age_over_18 = true   (salt: <32 hex chars>)
  Item 1: age_over_16 = true   (salt: <32 hex chars>)
  Item 2: age_over_21 = false  (salt: <32 hex chars>)
  Digest[0..2]: <64 hex chars each>
  MSO signed by DS cert ✓
  x5chain: DS cert + IACA cert

--- HOLDER: Selective disclosure ---
  Revealing:   age_over_18
  Withholding: age_over_16
  Withholding: age_over_21

--- VERIFIER: Verifying mDoc ---
  Certificate chain: valid ✓  (depth 2: DS → IACA root)
  MSO signature: valid ✓
  age_over_18 = true  digest: ✓
  Verification: PASSED ✓

CHAIN ATTACK TEST:
  Attacker's mDoc valid: false
  Error: chain verification failed: x509: certificate signed by unknown authority

TAMPER TEST:
  Tampered valid: false
  Error: digest mismatch for age_over_18
```

---

## Known gaps vs real mDoc

### deviceAuth not implemented (replay attack possible)

Without `deviceSigned`/`deviceAuth`, a valid presented mDoc can be replayed to any
verifier. A real implementation embeds the holder's public key in `MSO.deviceKeyInfo`
at issuance, then requires a fresh `deviceAuth` signature (over `DeviceAuthentication`
containing a per-session `SessionTranscript`) at every presentation.

Note: EU AV Blueprint Annex A §A.3 lists "Device bound Proof of Age attestations" as
out of scope for the current spec version — but `deviceKeyInfo` is still present in
the reference example and will likely be mandated in future versions.

### Verifier sees total digest count

The full `issuerAuth` (all digests) travels with every presentation. The verifier can
call `len(mso.ValueDigests[namespace])` to learn how many total claims exist, even for
undisclosed ones. Values are hidden — count is not.

---

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/fxamacker/cbor/v2` | CBOR encoding/decoding, Tag-24 wrapping |
| `github.com/veraison/go-cose` | COSE_Sign1 signing and verification |
| `crypto/ecdsa`, `crypto/elliptic` | P-256 key generation |
| `crypto/rand` | OS CSPRNG (`/dev/urandom` / `BCryptGenRandom`) |
| `crypto/sha256` | SHA-256 digest computation |
| `crypto/subtle` | Constant-time digest comparison |
| `crypto/x509` | Certificate generation and chain validation |

---

## References

- ISO 18013-5 — mDoc/mDL standard
- RFC 8949 — CBOR
- RFC 9052 — COSE
- EU Age Verification Blueprint Annex A — `eu.europa.ec.av.1` profile
- IANA COSE Algorithms registry — `-7` = ES256
- IANA COSE Key Types registry — `1`=kty, `-1`=crv, `-2`=x, `-3`=y