# Design: WSCA-backed holder key binding for SD-JWT VC (OpenID4VCI + OpenID4VP)

Status: **Implemented (irmago + adapter); live E2E blocked by env** · Scope:
bind irmago's SD-JWT VC holder keys to an external WSCA (Wallet Secure
Cryptographic Application) · Repos: `irmago` + `wallet-provider` (SECDSA)

> **Implementation status**
> - **irmago (done, unit-tested):** `HolderSigner` abstraction + software impl;
>   `signerKeyBinder` implementing `sdjwtvc.KeyBinder` (presentation KB-JWT via an
>   external signer); `proofs.BuildWithES256Signer` (issuance PoP via an external
>   signer); both seams made injectable —
>   `eudi_sdjwt_dcql.NewSdJwtVcDcqlHandler` takes an optional `KeyBinder`, and
>   `openid4vci.NewClient` takes `WithHolderKeyBinder`; `wallet.Config`
>   exposes `HolderSigner` + `IssuanceKeyBinderFactory`. Unit tests prove a
>   KB-JWT and an OpenID4VCI proof signed through an external signer verify
>   against the holder public key. Whole module builds; existing tests pass.
> - **wallet-provider (done, compiles):** `secdsa/irmawsca` — `Signer`
>   (implements `wallet.HolderSigner`) and `IssuanceBinder` (implements
>   `openid4vci.HolderKeyBinder`) over `walletmobile`; compile-time interface
>   checks pass; `go.mod` wired with a local `replace` to irmago.
> - **Live E2E (partially exercised, then blocked):** against a live WSCA
>   (SoftHSM + Postgres) the SECDSA activation `challenge`+`submit` succeeded —
>   real HSM crypto through the `walletmobile` client — before `finalize`
>   returned HTTP 500 `account lookup failed`. Full green E2E could not be
>   completed because the local Docker daemon repeatedly crashed (~1–2 min
>   uptime), killing the required Postgres, and no native Postgres was available.
>   The E2E test (`irmawsca_e2e_test.go`, gated on `WSCA_E2E_URL`) is committed
>   and compiles; rerun it against a stable WSCA to finish verification.

## 1. Goal

Make the SD-JWT VC **holder binding key** — the key whose public half goes into
the credential's `cnf` at issuance and that signs the KB-JWT at presentation —
live in and be operated by the **WSCA**, instead of being a software
`*ecdsa.PrivateKey` generated and stored (in the clear, per the separate
SQLCipher finding) inside irmago.

Concretely, for both protocol flows the private key must never exist in the
irmago process:

- **OpenID4VCI (issuance)** — the proof-of-possession JWT (`openid4vci-proof+jwt`)
  is signed by the WSCA.
- **OpenID4VP (presentation)** — the Key Binding JWT (`kb+jwt`) is signed by the
  WSCA.

This gives the EUDI "sole control" property: each holder-key signature requires
the user's PIN (knowledge factor) **and** the device possession key `U`
(possession factor), completed by the provider HSM — while the resulting
signature remains a **standard ES256/P-256 signature** that issuers and verifiers
validate with no SECDSA awareness.

## 2. Why this is a clean fit

The WSCA's `walletmobile` client (`secdsa/mobile/walletmobile`) is an embeddable
Go library exposing exactly the primitives holder binding needs:

| Need | WSCA client call | Notes |
|---|---|---|
| Create a holder key | `Wallet.GenerateKey(keyID, pin)` | P-256 keypair created inside the HSM; private half never leaves it |
| Get its public key | `Wallet.ListKeys()` / generate result | DER SPKI (PKIX) P-256 public key |
| Sign | `Wallet.Sign(keyID, message, pin)` | HSM signs `sha256(message)`, returns **DER (r,s)** ES256 signature |
| Activate (once) | `Wallet.Activate(pin)` | establishes the internal certificate; possession key `U` via `HardwareSigner` |

The decisive detail: `Sign` takes the **raw message** and the HSM hashes it with
SHA-256 server-side. A JWS signing input is exactly `base64url(header) + "." +
base64url(payload)`; feeding that as the message yields precisely an ES256
signature over the JWS — no client-side hashing, no SECDSA-specific encoding. The
signature verifies against the key's normal P-256 public key with
`ecdsa.VerifyASN1(pub, sha256(signingInput), derSig)`.

So the entire verifier/issuer side of irmago is unchanged. The only work is
replacing the *source* of holder keys and holder-key signatures.

## 3. The two seams in irmago

Both holder-key operations currently require a raw `*ecdsa.PrivateKey`:

### Presentation — KB-JWT
- `eudi/openid4vp/eudi_sdjwt_dcql/handler.go:404` — `sdjwtvc.CreateKbJwt(selected, h.keyBinder, nonce, clientId)`.
- `h.keyBinder` is a `sdjwtvc.KeyBinder` (`eudi/credentials/sdjwtvc/kbjwt.go:111`).
  `DefaultKeyBinder.CreateKeyBindingJwt` (`kbjwt.go:172`) pulls the private key
  from storage (`GetAndRemovePrivateKey`) and signs with `NewJwtCreator(privKey)`.
- **Problem**: the handler *constructs its own* binder at
  `handler.go:69-73` (`services.NewHolderBindingKeyService(...)` →
  `sdjwtvc.NewDefaultKeyBinder(...)`) — it is not injectable.

### Issuance — OID4VCI proof of possession
- `eudi/openid4vci/session.go:633` — `keyBindingService :=
  services.NewHolderBindingKeyService(s.storage.Db())`, then
  `CreateKeyPairsWithProofs(num, proofBuilder)` (session.go:664).
- `proofs.ProofBuilder.Build(key *ecdsa.PrivateKey)`
  (`eudi/credentials/proofs/proofbuilders.go:25,51`) builds AND signs the proof
  JWT internally with the private key.
- **Problem**: the service is hardcoded (not injectable), and the proof builder
  is intrinsically private-key-based.

## 4. Proposed abstraction

Introduce one low-level interface in irmago, in stdlib terms only, so irmago
gains **no dependency on the `secdsa` module**:

```go
// eudi/credentials/sdjwtvc  (or a new eudi/holderkeys package)

// HolderSigner is the source of SD-JWT VC holder binding keys and holder-key
// signatures. Implementations may keep private keys in software or delegate to
// an external secure device (WSCA/WSCD). It never exposes private key material.
type HolderSigner interface {
    // GenerateKeys creates num holder keys and returns, for each, a stable
    // opaque reference plus its P-256 public key.
    GenerateKeys(num uint) (refs []string, pubs []*ecdsa.PublicKey, err error)

    // SignES256 signs the JWS signing input (ASCII "header.payload") with the
    // referenced key and returns the raw 64-byte r||s JWS signature.
    SignES256(ref string, signingInput []byte) (sig []byte, err error)

    // Reference resolves the reference for a previously generated public key
    // (used at presentation time, where the credential carries the pubkey).
    Reference(pub jwk.Key) (ref string, err error)

    // Remove deletes the referenced keys.
    Remove(refs []string) error
}
```

Two adapters, both already-existing irmago interfaces, are then built on top of
`HolderSigner` so nothing downstream changes:

- **`signerKeyBinder`** implements `sdjwtvc.KeyBinder` (presentation). `CreateKeyPairs`
  → `HolderSigner.GenerateKeys`; `CreateKeyBindingJwt` builds the `kb+jwt`
  header+payload, calls `SignES256`, and assembles the compact JWS. No private
  key touched.
- **Issuance proof path**: add a signer-based proof builder that mirrors
  `JwtProofBuilder` but obtains the signature from `HolderSigner.SignES256`
  instead of a private key. The `cnf`/`jwk`/`kid` header logic is copied
  verbatim from `proofbuilders.go`.

### Signature encoding note

`walletmobile.Sign` returns **DER (r,s)**; JWS needs **raw r||s** (each integer
left-padded to 32 bytes for P-256). The adapter converts DER→raw once. (irmago
already depends on nothing exotic here — `crypto/ecdsa` + `math/big`, or
`ecdsa.VerifyASN1` on the verify side.)

## 5. Required irmago changes (small, additive)

1. **Make the presentation binder injectable.** Add an optional
   `sdjwtvc.KeyBinder` parameter (or functional option) to
   `eudi_sdjwt_dcql.NewSdJwtVcDcqlHandler`; default to the current software
   binder when nil. (~5 lines.)
2. **Make the issuance holder-key backend injectable.** Give
   `openid4vci.NewClient` an optional holder-key backend; the session uses it
   instead of `services.NewHolderBindingKeyService(...)` when set. Add a
   signer-based proof builder. (~40 lines + the proof builder.)
3. **Define `HolderSigner`** and the `signerKeyBinder` adapter + signer proof
   builder. (New file(s), no behavior change to existing callers.)
4. **`wallet.Config`** (the POC): add a `HolderSigner` field; when set, wire
   it into both the OpenID4VP handler and the OpenID4VCI client. When nil, the
   wallet behaves exactly as today (software keys).

No changes to SD-JWT verification, DCQL, storage schema for the *software* path.

### Storage of the key reference

For the software path, keys stay in `holder_binding_keys` as today. For the WSCA
path the "private key" is a WSCA `key_id`; the wallet must map a credential's
`cnf` public key (JWK thumbprint) → `key_id`. Two options:

- **A (POC):** the WSCA `HolderSigner` keeps its own small persistent map
  (thumbprint → key_id) — no change to irmago's storage models.
- **B (later):** extend `models.HolderBindingKey` to store an external key
  reference instead of PKCS#8 bytes, reusing the existing thumbprint/DID lookup
  in `HolderBindingKeyStore`.

The POC uses A to avoid touching shared storage models.

## 6. The WSCA adapter (lives in `wallet-provider`, not irmago)

Layering: **`wallet-provider` depends on `irmago`**, never the reverse. A new
package there — e.g. `secdsa/irmawsca` — implements irmago's `HolderSigner`:

```go
type WscaHolderSigner struct {
    w   *walletmobile.Wallet // NewWalletWithHardwareSigner(baseURL, dir, insecure, hw)
    pin func() (string, error) // knowledge factor, prompted per operation
    // thumbprint -> key_id map (persisted)
}

func (s *WscaHolderSigner) GenerateKeys(num uint) ([]string, []*ecdsa.PublicKey, error) {
    // for each: keyID := random; s.w.GenerateKey(keyID, pin); parse DER SPKI pub;
    // record thumbprint(pub) -> keyID; return
}
func (s *WscaHolderSigner) SignES256(ref string, signingInput []byte) ([]byte, error) {
    // res := s.w.Sign(ref, signingInput, pin)   // HSM hashes sha256 internally
    // parse "signature_hex=<DER>"; DER -> raw r||s (32+32); return
}
func (s *WscaHolderSigner) Reference(pub jwk.Key) (string, error) { /* thumbprint lookup */ }
```

- **Possession key `U`**: `NewWalletWithHardwareSigner(..., hw walletmobile.HardwareSigner)`.
  On device this is the Secure Enclave / StrongBox; for a desktop POC the
  software stand-in from `wallet_client_hw/enclave.go` fulfils the same
  interface.
- **Activation**: performed once (`Wallet.Activate(pin)`) before any
  issuance/presentation; the adapter surfaces `IsActivated()` so the app can
  drive first-run activation.

## 7. PIN / sole-control flow

Every holder-key signature needs the PIN. This changes the wallet flow: the
`HolderSigner` must be able to obtain the PIN at issuance and presentation time.
Plumbing:

- The POC `wallet` gains a PIN provider callback carried by the WSCA
  `HolderSigner`.
- In irmamobile the existing PIN-entry UI feeds the same callback; the possession
  key comes from the native `HardwareSigner` already built for the WSCA
  (`walletmobile.HardwareSigner` — `PublicKeyDER`/`SignP256`/attestation).
- Failed-PIN lockout, rate limiting, and app/key attestation are enforced by the
  WSCA server, unchanged.

## 8. End-to-end flow (WSCA-backed)

Issuance:
1. (once) `Activate(pin)` → internal certificate.
2. OID4VCI session needs N proofs → `HolderSigner.GenerateKeys(N)` → WSCA
   `GenerateKey` ×N → public keys.
3. For each, build `openid4vci-proof+jwt` (jwk/kid header) → `SignES256` → WSCA
   `Sign`. Send proofs; issuer binds `cnf` to the WSCA public keys.
4. Credentials stored; `cnf` now references HSM-resident keys.

Presentation:
1. Verifier request → DCQL selects a credential; its `cnf` pubkey → `Reference`
   → WSCA `key_id`.
2. Build `kb+jwt` (sd_hash, nonce, aud) → `SignES256` → WSCA `Sign`.
3. Assemble `<sd-jwt>~<disclosures>~<kb-jwt>`; verifier validates the KB-JWT
   against the `cnf` key as usual.

## 9. Module wiring

- `irmago` — no new module dependency. Defines `HolderSigner`, adapters,
  injection points.
- `wallet-provider` — add `require github.com/privacybydesign/irmago vX` and
  implement `HolderSigner` in `secdsa/irmawsca`. For local POC development, a
  `replace github.com/privacybydesign/irmago => ../irmago` in
  `wallet-provider/go.mod`.
- A demo/E2E driver (in `wallet-provider`, importing both) wires:
  WSCA server URL + software enclave + PIN → `WscaHolderSigner` →
  `wallet.New(Config{HolderSigner: ...})` → run `Receive` then `Present`.

## 10. Testing / running E2E

Prerequisites to actually run: a WSCA server (`go run ./wsca`, needs
SoftHSM/PKCS#11), an OID4VCI issuer + OID4VP verifier (the in-repo irmago
harness or EUDI reference services), a possession signer (software enclave
stand-in), and a test PIN.

- **Unit**: DER→raw conversion; `signerKeyBinder` produces a JWS that verifies
  against the returned public key (using a software `HolderSigner`).
- **Integration (gated)**: with a running WSCA, assert `GenerateKeys` +
  `SignES256` yields a signature verifiable via `ecdsa.VerifyASN1`, and that a
  KB-JWT built through `signerKeyBinder` passes irmago's SD-JWT verifier.
- **E2E (gated)**: issue a credential whose `cnf` is a WSCA key, then present it;
  the verifier accepts the WSCA-signed KB-JWT.

## 11. Phased plan

1. **irmago**: `HolderSigner` + `signerKeyBinder` + signer proof builder +
   software `HolderSigner`; make both seams injectable; `wallet.Config`
   option. Unit-tested, no behavior change by default.
2. **wallet-provider**: `secdsa/irmawsca.WscaHolderSigner` over `walletmobile`;
   gated integration test.
3. **Demo driver**: full issue→present cycle against a running WSCA.
4. **Hardening (later)**: storage option B (external key ref in
   `HolderBindingKey`), attestation surfacing, PIN-lockout UX, batch
   optimization.

## 12. Known constraints

- Curve is P-256 only (WSCA `ECBitSize = 256`); matches irmago's ES256 holder
  keys.
- Every holder-key signature is a network round-trip to the WSCA and requires the
  PIN — batch issuance (N proofs) means N signs; consider a single
  PIN-authorized batch instruction later.
- The `cnf.kid` (did:jwk) KB-JWT verification gap in `sdjwtvc/verify.go` still
  applies; use `cnf.jwk` holder binding.
- Depends on the WSCA being reachable at issuance/presentation time (online
  holder binding).
