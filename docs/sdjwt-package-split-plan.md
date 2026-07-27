# Plan: split `eudi/credentials/sdjwtvc` into `eudi/sdjwt` + `eudi/credentials/sdjwtvc`

## Goal

Today one package, `eudi/credentials/sdjwtvc` (~5.5k non-test lines), implements two
specifications at once:

- **draft-ietf-oauth-selective-disclosure-jwt** (SD-JWT) — salted disclosures, `_sd`/`_sd_alg`,
  the `~`-separated compact serialization, the KB-JWT and `cnf`.
- **draft-ietf-oauth-sd-jwt-vc** (SD-JWT VC) — `vct`, `vct#integrity`, the `dc+sd-jwt` media
  type, issuer identification via `x5c`/`iss`, `status`, and type metadata.

A third spec, **draft-ietf-oauth-status-list** (Token Status List), already lives in its own
package `eudi/credentials/statuslist`, but SD-JWT VC reaches into it from its core data types.

After the split:

| Package | Spec | Depends on |
| --- | --- | --- |
| `eudi/sdjwt` | SD-JWT | `internal/crypto/hashing`, `eudi/didjwk`, `eudi/didkey`, `eudi/jwt` |
| `eudi/credentials/sdjwtvc` | SD-JWT VC | `eudi/sdjwt`, `eudi/credentials/statuslist`, `eudi/jwt`, `eudi/scheme`, `eudi/utils` |
| `eudi/credentials/sdjwtvc/typemetadata` | SD-JWT VC Type Metadata | unchanged |
| `eudi/credentials/statuslist` | Token Status List | unchanged |

Hard invariant: **`eudi/sdjwt` must not import `sdjwtvc`, `statuslist`, `scheme`, or
`typemetadata`.** A `go list -deps` assertion in CI is the cheapest way to keep it true
(see step 8).

### On the Token Status List boundary

Per decision, the `statuslist` integration is **not** restructured. The split alone buys the
clearer distinction that was asked for: after step 4, `eudi/sdjwt` contains zero references to
`statuslist`, and every status-list touchpoint is confined to three named places in the VC
package — `IssuerSignedJwtPayload.Status`, `SdJwtVcVerificationContext.StatusChecker`, and
`sdJwtVcProcessor.runStatusListCheck`. Step 7 documents that contract. Two follow-ups are
recorded as out-of-scope in "Deferred" below.

---

## Current file inventory and destination

Non-test files in `eudi/credentials/sdjwtvc/`:

| File | Lines | Content | Destination |
| --- | --- | --- | --- |
| `sdjwtvc.go` | 481 | Disclosure encode/decode/hash/salt, compact-format constructors, claim-key constants, `IssuerSignedJwtPayload`, `vct#integrity` lookup | **split** — bulk to `sdjwt`, `vct`/`status` parts stay |
| `kbjwt.go` | 302 | `KeyBindingJwt`, `KeyBinder`, `KeyBindingStorage`, `cnf` resolution, `did:jwk`/`did:web` holder-key resolution | `sdjwt` |
| `presentation.go` | 364 | `CreatePresentation`, `PostDisclosureView`, disclosure selection/dependency graph | `sdjwt` |
| `path_pointer.go` | 80 | Claims path pointer resolution (OpenID4VCI App. C) | `sdjwt` |
| `verifier_helpers.go` | 59 | `splitSdJwtVcKb`, `splitSdJwtVc` — `~` tokenizer | `sdjwt` |
| `crypto.go` | 73 | `JwtCreator`, ECDSA key loading | `sdjwt` |
| `issuer.go` | 420 | Claim-tree builder (`Claim`/`SdClaim`/`Object`/`Array`), `SdJwtBuilder` | **split** — tree to `sdjwt`, builder policy stays |
| `verify.go` | 976 | Verification pipeline, `SdJwtVcVerificationContext`, `x5c` + scheme integration, `ProcessedSdJwtPayload`, disclosure verification | **split** — disclosure verification to `sdjwt`, pipeline stays |
| `messages.go` | 11 | `IssuerMetadata` | stays |
| `test_data.go` | 21 | Hardcoded SD-JWT VC fixtures, unexported | stays (see step 6) |
| `test_utils.go` | 554 | Exported test helpers in a **non-`_test`** file | **split** into two test-only packages (step 6) |

`typemetadata/` (~650 non-test lines) already has no dependency on the parent package and is
untouched.

---

## Target package contents

### `eudi/sdjwt`

| New file | From | Notable symbols |
| --- | --- | --- |
| `doc.go` | new | package doc naming the draft and revision it targets |
| `disclosure.go` | `sdjwtvc.go` | `DisclosureContent`, `DisclosureContents`, `EncodedDisclosure`, `HashedDisclosure`, `NewDisclosureContent`, `NewArrayItemDisclosureContent`, `MultipleNewDisclosureContents`, `Encode/DecodeDisclosure(s)`, `HashDisclosure(s)`, `HashEncodedDisclosure(s)`, `generateSalt` |
| `serialization.go` | `sdjwtvc.go` + `verifier_helpers.go` | `SdJwt`, `SdJwtKb`, `IssuerSignedJwt`, `Create`, `AddKeyBindingJwt`, `Split`, `SplitKb`, `DecodeJwtPayload` |
| `claims.go` | `sdjwtvc.go` | core claim keys (`Key_Sd`, `Key_SdAlg`, `Key_Confirmationkey`, `Key_Ellipsis`, `Key_Subject`, `Key_Issuer`, `Key_ExpiryTime`, `Key_IssuedAt`, `Key_NotBefore`, `Key_Typ`, `Key_X5c`, `Key_Kid`), `KbJwtTyp`, `RegisteredClaims`, `RegisteredClaimNames` |
| `builder.go` | `issuer.go` | `ClaimElement`, `SerializedClaim`, `SdClaimElement`, `EmbeddedClaimElement`, `ClaimType`, `LeafClaimDataType`, `Null`, `Claim`, `SdClaim`, `Item`, `SdItem`, `Object`, `SdObject`, `Array`, `SdArray`, `HolderKeyClaim`, `JsonToClaimTree`, `Builder` |
| `kbjwt.go` | `kbjwt.go` | `KeyBindingJwt`, `KeyBindingJwtPayload`, `KeyBinder`, `DefaultKeyBinder`, `KeyBindingStorage`, `InMemoryKeyBindingStorage`, `CreateKbJwt`, `CnfField`, `ExtractHashingAlgorithmAndHolderPubKey`, `resolveHolderKey`, `resolveKeyFromDid` |
| `presentation.go` | `presentation.go` | `CreatePresentation`, `PostDisclosureView`, `indexedDisclosure` and its helpers |
| `processed.go` | `verify.go` + `path_pointer.go` | `ProcessedPayload` (was `ProcessedSdJwtPayload`), `MarshalJSON`, `Sort`, `GetClaimValue` |
| `verify_disclosures.go` | `verify.go` | `VerifyAndProcessDisclosures`, `processEmbeddedDisclosures`, `processSdClaim`, `ParseSdField`, `ParseConfirmField`, `ExtractClaimsAndDisclosureDigestsFromToken` |
| `crypto.go` | `crypto.go` | `JwtCreator`, `DefaultEcdsaJwtCreator`, `NewJwtCreator`, `DecodeEcdsaPrivateKey`, `ReadEcdsaPrivateKey`, `JwtVerifier`, `JwxJwtVerifier`, `CreateUrlEncodedHash` |

### `eudi/credentials/sdjwtvc` (what remains)

| File | Notable symbols |
| --- | --- |
| `doc.go` | package doc naming the SD-JWT VC draft, and an explicit note that Token Status List handling is delegated to `credentials/statuslist` and confined to `payload.go` + `verify.go` |
| `sdjwtvc.go` | `SdJwtVc`, `SdJwtVcKb` (defined-types over `sdjwt.SdJwt`/`sdjwt.SdJwtKb`), `SdJwtVcTyp`, `SdJwtVcTyp_Legacy`, `Key_VerifiableCredentialType`, `Key_VerifiableCredentialTypeIntegrity`, `Key_Status`, `Key_Federation`, `StandardClaims`, `LookupVctIntegrityClaim` |
| `payload.go` | `IssuerSignedJwtPayload` (embeds `sdjwt.RegisteredClaims`, adds `VerifiableCredentialType` and `Status *statuslist.StatusClaim`), `IssuerSignedJwtPayload_ToJson`, `SdJwtVc_IssuerRepresentation` |
| `issuer.go` | `SdJwtVcBuilder` — wraps `sdjwt.Builder`, enforces `vct` present, enforces `iss` is `https://`, sets `typ: dc+sd-jwt` and the `x5c` header |
| `verify.go` | `SdJwtVcVerificationContext`, `sdJwtVcProcessor`, `VerifiedSdJwtVc`, `HolderVerificationProcessor`, `VerifierVerificationProcessor`, `keyBindingProcessor`, `runStatusListCheck`, `parseStatusClaim`, `decodeJwtAndVerifyFromX5cHeader`, `verifyTimeFields`, `CheckKeyBindingConfirmationUniqueness`, `ClockSkewInSeconds` |
| `messages.go` | `IssuerMetadata` |

---

## Rename map

Names that change because they carried "VC" while describing SD-JWT core. Counts are
call-site occurrences outside the package (32 consumer files total).

| Current | New | Ext. refs |
| --- | --- | --- |
| `sdjwtvc.SdJwtVc` (core string type) | `sdjwt.SdJwt` — `sdjwtvc.SdJwtVc` kept as a defined type | 27 |
| `sdjwtvc.SdJwtVcKb` | `sdjwt.SdJwtKb` — `sdjwtvc.SdJwtVcKb` kept as a defined type | 22 |
| `sdjwtvc.ProcessedSdJwtPayload` | `sdjwt.ProcessedPayload` | 20 |
| `sdjwtvc.KeyBinder` / `KeyBindingStorage` / `KeyBindingJwt(Payload)` | `sdjwt.*`, unchanged names | 31 |
| `sdjwtvc.CnfField` | `sdjwt.CnfField` | 10 |
| `sdjwtvc.Claim` / `SdClaim` / `ClaimElement` / `LeafClaimDataType` / `HolderKeyClaim` | `sdjwt.*`, unchanged names | 28 |
| `sdjwtvc.NewSdJwtBuilder` | `sdjwtvc.NewSdJwtVcBuilder` (VC policy) wrapping `sdjwt.NewBuilder` | 3 |
| `sdjwtvc.CreateSdJwtVc` / `CreateSdJwtVcWithDisclosureContents` | `sdjwt.Create` / `sdjwt.CreateWithDisclosureContents` | 0 |
| `sdjwtvc.AddKeyBindingJwtToSdJwtVc` | `sdjwt.AddKeyBindingJwt` | 2 |
| `sdjwtvc.CreatePresentation` / `PostDisclosureView` / `CreateKbJwt` / `ExtractHashingAlgorithmAndHolderPubKey` / `CreateUrlEncodedHash` / `NewJwxJwtVerifier` / `DecodeEcdsaPrivateKey` / `NewJwtCreator` | `sdjwt.*`, unchanged names | 19 |
| `sdjwtvc.Key_Sd` / `Key_SdAlg` / `Key_Confirmationkey` / `Key_Ellipsis` / `Key_Subject` / `Key_Issuer` / `Key_ExpiryTime` / `Key_IssuedAt` / `Key_NotBefore` / `Key_Typ` / `Key_X5c` / `Key_Kid` / `KbJwtTyp` | `sdjwt.*`, unchanged names | 14 |
| `sdjwtvc.NewEcdsaJwtCreatorWithIssuerTestkey` | `sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey` | 2 |
| — (new) | `sdjwt.RegisteredClaims` — `sub`/`iss`/`exp`/`iat`/`nbf`/`_sd`/`_sd_alg`/`cnf` | 0 |

Unchanged and staying in `sdjwtvc`: `VerifiedSdJwtVc` (46), `SdJwtVcVerificationContext` (7),
`NewHolderVerificationProcessor` / `HolderVerificationProcessor` (14),
`CreateDefaultVerificationContext` (4), `StandardClaims` (4), `Key_VerifiableCredentialType` (3),
`IssuerSignedJwtPayload` (3), `CheckKeyBindingConfirmationUniqueness` (2), `LookupVctIntegrityClaim` (1).

### `SdJwtVc` as a defined type, not an alias

```go
// eudi/credentials/sdjwtvc
type SdJwtVc sdjwt.SdJwt      // NOT `= sdjwt.SdJwt`
type SdJwtVcKb sdjwt.SdJwtKb
```

A defined type (rather than `=`) makes the compiler flag every place a raw SD-JWT is used
where an SD-JWT VC is expected, which is the point of the exercise. The cost is explicit
conversions at the boundary — roughly 40 sites, all inside `sdjwtvc`. If that friction turns
out to be pure noise during step 4, downgrade to an alias; decide once, in one commit,
rather than per call site.

---

## Boundary decisions worth recording

Six places genuinely straddle the two specs. Resolutions:

1. **`IssuerSignedJwtPayload`** currently mixes registered JWT claims, SD-JWT claims
   (`_sd`, `_sd_alg`, `cnf`) and VC claims (`vct`, `status`). Resolution: `sdjwt.RegisteredClaims`
   holds the first two groups; `sdjwtvc.IssuerSignedJwtPayload` embeds it and adds `vct` +
   `status`. This is the one change that makes the statuslist dependency structurally
   VC-only.

2. **`SdJwtBuilder.Build`** requires `vct`, requires `iss` to be `https://`, and hardcodes
   `typ: dc+sd-jwt` — all three are SD-JWT VC rules, not SD-JWT rules. Resolution: `sdjwt.Builder`
   accepts a caller-supplied `typ` and set of header fields and enforces only the SD-JWT
   rules (`_sd_alg` supported, default `sha-256`). `sdjwtvc.SdJwtVcBuilder` layers the VC
   policy on top.

3. **`ExtractHashingAlgorithmAndHolderPubKey`** reads `_sd_alg` and `cnf` from an
   `SdJwtVc`. Both claims are SD-JWT core → moves to `sdjwt`, retyped to `sdjwt.SdJwt`.
   It pulls `eudi/didjwk`, `eudi/didkey` and `eudi/jwt` into `sdjwt`; acceptable, since
   `cnf.kid` with `did:jwk` is described by the SD-JWT spec itself.

4. **`decodeJwtAndVerifyFromX5cHeader`** ties JWT verification to `dc+sd-jwt`/`vc+sd-jwt`
   media types and the Yivi `scheme.AttestationProviderRequestor`. Entirely VC/Yivi →
   stays in `sdjwtvc`. Only the generic `sdjwt.JwtVerifier` interface moves.

5. **`verifyTimeFields`** validates `exp`/`iat`/`nbf` with a clock skew — generic JWT, not
   SD-JWT-specific. Resolution: keep it in `sdjwtvc` for now, since it reads the
   VC payload struct and moving it would mean threading a clock into `sdjwt` for no
   present benefit. Noted in `doc.go` as deliberate.

6. **`ClockSkewInSeconds = 180`** (sdjwtvc) duplicates `ClockSkewSeconds = 180`
   (statuslist). Leave both; they are independently specified windows that happen to
   coincide. Add a comment on each pointing at the other so a future reader does not
   "deduplicate" them into a shared constant.

---

## Execution steps

Each step should compile and pass `go test ./...` on its own, so the series can be reviewed
and bisected commit by commit.

**1. Prepare — no behaviour change.** `git mv` nothing yet. Inside the existing package,
regroup code into the target file names (`disclosure.go`, `serialization.go`, `claims.go`,
`builder.go`, `processed.go`, `verify_disclosures.go`, `payload.go`) so that step 3 is a
pure file move. Verify: `go build ./... && go test ./eudi/...`, and `git diff --stat` should
show only moves between files in one directory.

**2. Introduce `sdjwt.RegisteredClaims`.** Split `IssuerSignedJwtPayload` into the embedded
core struct plus the VC fields, still inside `sdjwtvc`. Fix the ~15 field accesses
(`payload.Sd`, `payload.SdAlg`, `payload.Confirm`, `payload.Issuer`, `payload.Subject`,
`payload.Expiry`, `payload.IssuedAt`, `payload.NotBefore`) — Go's embedded-field promotion
means most read/write sites need no change; composite literals in `verify.go` and
`test_utils.go` do. Verify: tests pass unchanged.

**3. Split the builder.** Extract `sdjwt.Builder` from `SdJwtBuilder`; make
`SdJwtVcBuilder` a wrapper that enforces `vct`, the `https://` `iss` rule, and the `typ`
header. Still one package. Verify: `issuer_test.go` passes; add a case asserting
`sdjwt.Builder` produces a valid SD-JWT with no `vct` at all.

**4. Create `eudi/sdjwt` and move.** `git mv` the files from the table above; rewrite
`package sdjwtvc` → `package sdjwt`; apply the rename map. Add the `SdJwtVc`/`SdJwtVcKb`
defined types and the conversions at the boundary. This is the large commit; keep it
mechanical — no logic edits. Verify: `go build ./...`, then
`go list -deps ./eudi/sdjwt | grep -E 'sdjwtvc|statuslist|eudi/scheme'` must print nothing.

**5. Update the 32 consumer files.** In dependency order:
`irma/irmaclient/*` (7 files, the heaviest — `sdjwtvc_storage.go`, `keybinding_storage.go`,
`irmaclient.go`, `helpers.go`), `eudi/openid4vci/*` (6), `eudi/openid4vp/{eudi,irma}_sdjwt_dcql/*` (4),
`eudi/services/*` (3), `eudi/holderkeys/*` (2), `irma/server/*` (3), `client/client.go`,
`irma/messages.go`, `internal/sessiontest/*` (2). Mostly import-path and qualifier edits;
`gofmt -r` handles the bulk, but review each `SdJwtVc`↔`SdJwt` conversion by hand — those
are where a genuine type confusion would hide.

**6. Split the test helpers.** `test_utils.go` (554 lines) and `test_data.go` are production
files holding fixtures; `crypto.go` additionally imports `irmago/testdata` from
non-test code. Move to two new test-only packages, `eudi/sdjwt/sdjwttest` and
`eudi/credentials/sdjwtvc/sdjwtvctest`, and drop the `testdata` import from `crypto.go` by
having `NewDefaultEcdsaJwtCreatorWithHolderPrivateKey` move to `sdjwttest`. Split the
`_test.go` files along the same line: `sdjwtvc_test.go`, `presentation_test.go`,
`path_pointer_test.go`, `verifier_helpers_test.go`, `processed_sd_jwt_payload_test.go` and
`test_data_generators_test.go` follow the code to `sdjwt`; `verify_test.go` (1453 lines) and
`issuer_test.go` need splitting by test case.

**7. Document the three boundaries.** Write `eudi/sdjwt/doc.go` and
`eudi/credentials/sdjwtvc/doc.go`. Each names its draft and revision, states what it
deliberately does *not* cover, and points at the neighbouring package. The VC doc states
that Token Status List support is delegated to `credentials/statuslist` and reachable only
via `IssuerSignedJwtPayload.Status`, `SdJwtVcVerificationContext.StatusChecker` and
`runStatusListCheck` — so a reader knows where the seam is without grepping.
`typemetadata/typemetadata.go` already has an exemplary package comment; match its style.

**8. Enforce the invariant.** Add a test in `eudi/sdjwt` that shells out to
`go list -deps` (or uses `golang.org/x/tools/go/packages`) and fails if the dependency
closure of `eudi/sdjwt` contains `sdjwtvc`, `statuslist`, `eudi/scheme`, or `typemetadata`.
Cheap, and it is the only thing that will stop the boundary eroding.

---

## Risks

- **Silent type confusion during step 5.** The defined-type approach means the compiler
  catches SD-JWT/SD-JWT VC mixups, but a lazy `SdJwtVc(x)` conversion silences the very
  check we introduced. Review conversions individually; grep for `SdJwtVc(` afterwards and
  justify each.
- **`verify_test.go` is 1453 lines** and covers both layers. Splitting it is where the
  effort actually is; budget for it rather than deferring, or the SD-JWT package ships
  without its own test coverage.
- **Merge conflicts.** Steps 4–6 touch nearly every EUDI file. Land the series quickly on
  a short-lived branch rather than accumulating.
- **`sdjwtvc` is on the public API surface of irmago** (`irma/messages.go`, `client/client.go`).
  Anything importing irmago externally will break on step 4. Check whether the
  irmamobile/wallet side pins a version before landing.

## Deferred (explicitly out of scope)

Both were considered and left out per the statuslist decision; record them as issues so
they are not silently forgotten:

- Replace `IssuerSignedJwtPayload.Status *statuslist.StatusClaim` with a VC-local status
  claim type, so `sdjwtvc` no longer depends on `statuslist` at the type level.
- Turn `SdJwtVcVerificationContext.StatusChecker` into a pluggable post-verification hook
  interface, so revocation policy is injected rather than compiled into the verifier.
