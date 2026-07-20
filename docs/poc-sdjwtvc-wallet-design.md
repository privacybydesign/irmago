# Design: Standalone SD-JWT VC Wallet Client (Proof of Concept)

Status: **Scaffolded (POC implemented)** · Scope: EUDI (European Digital
Identity) SD-JWT VC wallet · Target repo: `github.com/privacybydesign/irmago`

> **Implemented in this branch**
> - `wallet` — the `Wallet` facade (`New`/`Receive`/`Present`/`Credentials`/
>   `Logs`/`Reset`/`Close`), the `Policy` interface with `AutoApprovePolicy` and
>   `FuncPolicy`, and headless OpenID4VCI + OpenID4VP handlers (pre-authorized
>   **and** authorization-code grants; `direct_post` + `direct_post.jwt`).
> - `yivi/cli/walletcli` — the `yivi sdjwtvc-wallet` command
>   (`receive`/`present`/`list`/`logs`/`reset`), with PBKDF2 passphrase→key
>   derivation and a paste-the-callback UX for the auth-code flow.
> - Tests: unit tests for the plan→selection policy logic and the wallet
>   lifecycle (real SQLCipher), plus an opt-in end-to-end test
>   (`WALLET_POC_OFFER`/`WALLET_POC_PRESENT`).
> - Verified: `go build ./...`, `go vet`, and `go test ./wallet/...` pass;
>   the CLI runs a create→list→reset cycle against real storage.
> - **Finding**: the EUDI credential database is not actually encrypted at rest
>   (see §7) — surfaced, not fixed.

## 1. Summary

This document proposes a **standalone, headless proof-of-concept wallet client** for
SD-JWT VC credentials in the EUDI spectrum.

The important starting observation: **irmago already contains a complete, working
EUDI SD-JWT VC wallet implementation.** OpenID4VCI issuance, encrypted-at-rest
storage, OpenID4VP presentation, DCQL query handling, holder key binding, and
verifier trust validation are all implemented and are exercised end-to-end today
(including against a real Python PID issuer and the EUDI Kotlin / Veramo
verifiers in `internal/sessiontest`).

What does *not* exist yet is a way to run that stack **as a wallet on its own**.
The only production facade — the `client` package (`client.Client`) — is a
unified IRMA + EUDI wallet: it drags in `irmaclient`, the keyshare protocol, a
bbolt store, and a Flutter-oriented, UI-callback session model. To *demonstrate*
the EUDI SD-JWT VC lifecycle you currently need the full mobile app or the
integration-test harness.

The POC therefore is deliberately thin. It adds three things on top of the
existing `eudi/*` libraries:

1. A `Wallet` facade that wires **only** the EUDI pieces (no IRMA, no keyshare,
   no bbolt).
2. **Headless `Handler` implementations** (policy/auto-approve) that replace the
   Flutter UI callbacks.
3. A small **driver** (CLI + example + E2E test) that runs the happy path:
   *receive a credential over OpenID4VCI → store it encrypted → present it over
   OpenID4VP.*

Non-goal: reimplementing any protocol logic. Every cryptographic and protocol
operation is reused from `eudi/*` as-is.

## 2. Background: what already exists (reuse, do not rebuild)

All of the following are present, implemented, and tested. The POC consumes them
directly.

| Concern | Package / entry point | Notes |
|---|---|---|
| Trust configuration | `eudi.NewConfiguration(storage)` → `*eudi.Configuration` | Issuer + verifier trust lists, CRLs, staging anchors |
| Encrypted storage | `eudi/storage.NewStorage(aesKey, dbPath, storagePath)` | SQLCipher DB (`yivi-eudi.db`) + AES-GCM filesystem for logos/certs/CRLs |
| Credential persistence | `eudi/storage/db.CredentialStore`, `HolderBindingKeyStore` | `CredentialBatch` / `IssuedCredentialInstance` (single-use batch instances) |
| Credential/keys/logs services | `eudi/services` (`CredentialService`, `HolderBindingKeyService`, `EudiLogService`) | Verify-and-store, ECDSA P-256 key-pair + OID4VCI proof generation, session logs |
| Issuance (OpenID4VCI) | `eudi/openid4vci.NewClient(httpClient, conf, holderVerifier)` + `.NewSession(...)` | Pre-Authorized **and** Authorization Code (PKCE, PAR) flows; nonce; optional JWE credential request; VCT `#integrity` check |
| Presentation (OpenID4VP) | `eudi/openid4vp.NewClient(conf, dcqlHandlers, verifierValidator)` + `.NewSession(...)` | `direct_post` and `direct_post.jwt` (JWE) response modes |
| Query matching | `eudi/openid4vp/dcql` + `eudi/openid4vp/eudi_sdjwt_dcql.NewSdJwtVcDcqlHandler(...)` | The **non-IRMA** DCQL handler over EUDI storage — this is the one the POC uses |
| Verifier trust | `openid4vp.NewCompositeVerifierValidator(x509, did)` | X.509 (`x509_san_dns`, `x509_hash`) + `did:jwk`/`did:web` |
| SD-JWT VC crypto | `eudi/credentials/sdjwtvc` | Parse/verify, selective disclosure, KB-JWT, `HolderVerificationProcessor`, `KeyBinder` |
| Holder key proofs | `eudi/credentials/proofs.NewJwtProofBuilder(...)` | `openid4vci-proof+jwt`, binding via `jwk` / `did:key` / `did:jwk` |
| DID resolution | `eudi/did`, `eudi/didjwk`, `eudi/didkey`, `eudi/didweb` | Broad verify-side support |
| Type metadata | `eudi/credentials/sdjwtvc/typemetadata` | VCT resolution, `extends` chain, integrity |

A crucial wiring detail confirmed in the code: the OpenID4VCI session builds its
own `services.NewCredentialService(storage)` and
`services.NewHolderBindingKeyService(storage.Db())` internally
(`eudi/openid4vci/session.go`). Both clients reach storage through the shared
`eudi.Configuration`. **So the POC never touches the storage/service layer
directly for the happy path — it only provides `Configuration`, the two clients,
and handlers.**

### The one real gap: the handler model

Both protocol clients are driven by asynchronous handler interfaces designed for
a mobile UI:

- `openid4vci.Handler` — `RequestPreAuthorizedCodeFlowPermission`,
  `RequestAuthorizationCodeFlowPermission`, `RequestPermission`, `Success`,
  `Cancelled`, `Failure` (plus `PermissionHandler`/`AuthCodeHandler`/
  `TokenPermissionHandler` callbacks).
- `openid4vp.Handler` — `RequestVerificationPermission(plan, requestor,
  hashToQueryId, callback)`, `Success`, `Cancelled`, `Failure`.

In the app these fire a callback and *await* a user tap. For a POC we supply
**headless handlers** that resolve those callbacks immediately from a policy
(auto-approve, or "approve if requestor is trusted and disclosure ⊆ allow-list").
This exact pattern already exists as `MockSessionHandler` in
`eudi/openid4vci/test_helpers.go` and in the `openid4vp` tests — the POC
promotes that idea from test-only to a reusable component.

## 3. Goals & non-goals

**Goals**

- Demonstrate the full SD-JWT VC wallet lifecycle with a runnable artifact.
- Zero IRMA coupling: no `irmaclient`, keyshare, idemix, or bbolt.
- Reuse `eudi/*` verbatim; the POC is glue + a driver.
- Be scriptable/headless so it can run in CI and from a terminal.
- Encrypted-at-rest storage, same as production (SQLCipher). **Caveat**: the
  underlying storage layer currently does not apply the DB encryption key — see
  §7. The POC inherits this; it is called out, not fixed.

**Non-goals (for the POC)**

- No GUI.
- No new protocol features (deferred issuance, DPoP, mdoc, W3C VC, revocation).
- Not a hardware-backed key store (holder keys are software ECDSA P-256, as in
  the current services layer).
- Not a hardened trust posture — staging anchors / developer mode are acceptable
  for the demo.

## 4. Proposed architecture

New package: **`wallet`** (library) + a thin CLI under **`yivi/cli`** (or
`cmd/sdjwtvc-wallet`). Nothing else in the repo changes.

```
                       ┌─────────────────────────────────────────────┐
                       │  driver: yivi cli `sdjwtvc-wallet` / example │
                       │   receive · present · list · logs · reset    │
                       └───────────────────────┬─────────────────────┘
                                               │ calls
                       ┌───────────────────────▼─────────────────────┐
                       │            wallet.Wallet (NEW)          │
                       │  - Receive(offerURI)  → OpenID4VCI issuance  │
                       │  - Present(requestURI)→ OpenID4VP disclosure │
                       │  - Credentials() / Logs() / Reset()          │
                       │  - headless Handlers (policy-driven) (NEW)   │
                       └───────┬───────────────────────────┬─────────┘
                               │ reuse                      │ reuse
        ┌──────────────────────▼─────────┐   ┌─────────────▼──────────────────┐
        │ eudi/openid4vci.Client         │   │ eudi/openid4vp.Client          │
        │ (+ HolderVerificationProcessor)│   │ (+ eudi_sdjwt_dcql handler,    │
        │                                │   │    composite VerifierValidator)│
        └──────────────────────┬─────────┘   └─────────────┬──────────────────┘
                               │                            │
                       ┌───────▼────────────────────────────▼───────┐
                       │           eudi.Configuration                 │
                       │  eudi/storage.Storage (SQLCipher + FS)       │
                       │  services: Credential / HolderKey / Log      │
                       └──────────────────────────────────────────────┘
```

### 4.1 The `Wallet` facade

A stripped-down analogue of `client.Client`, EUDI-only. Sketch:

```go
package wallet

type Wallet struct {
    conf        *eudi.Configuration
    storage     storage.Storage
    vci         *openid4vci.Client
    vp          *openid4vp.Client
    policy      Policy // decides auto-approval
}

type Config struct {
    DataDir       string    // holds yivi-eudi.db + filesystem containers
    AesKey        [32]byte  // encrypts DB + filesystem (as in client.New)
    DeveloperMode bool      // staging trust anchors, insecure http/did:web
    Policy        Policy
}

func New(cfg Config) (*Wallet, error)

// Receive runs an OpenID4VCI issuance session to completion and returns the
// credentials that were stored.
func (w *Wallet) Receive(ctx context.Context, offerURI, redirectURI string) ([]*clientmodels.Credential, error)

// Present runs an OpenID4VP disclosure session against a request/offer URI.
func (w *Wallet) Present(ctx context.Context, requestURI string) (*PresentationResult, error)

func (w *Wallet) Credentials() ([]*clientmodels.Credential, error)
func (w *Wallet) Logs(max int) ([]clientmodels.LogInfo, error)
func (w *Wallet) Reset() error
func (w *Wallet) Close() error
```

`New` reproduces the EUDI half of `client.New`:

```go
eudiStorage, _ := storage.NewStorage(cfg.AesKey, filepath.Join(cfg.DataDir, storage.DbFilename), cfg.DataDir)
conf, _        := eudi.NewConfiguration(eudiStorage)

vctFetcher     := typemetadata.NewDefaultVctFetcher(nil)
issuerFetcher  := typemetadata.NewDefaultIssuerFetcher(nil)
dcqlHandler    := eudi_sdjwt_dcql.NewSdJwtVcDcqlHandler(eudiStorage, vctFetcher, issuerFetcher)

x509           := openid4vp.NewRequestorCertificateStoreVerifierValidator(&conf.Verifiers, &openid4vp.DefaultQueryValidatorFactory{})
did            := openid4vp.NewDidVerifierValidator(cfg.DeveloperMode)
validator      := openid4vp.NewCompositeVerifierValidator(x509, did)
vp, _          := openid4vp.NewClient(conf, []dcql.DcqlCredentialQueryHandler{dcqlHandler}, validator)

verifyCtx      := sdjwtvc.SdJwtVcVerificationContext{
    X509VerificationContext: &conf.Issuers,
    Clock:                   eudi_jwt.NewSystemClock(),
    JwtVerifier:             sdjwtvc.NewJwxJwtVerifier(),
    VerifyVerifiableCredentialTypeInRequestorInfo: false, // matches OID4VCI ctx in client.go
}
vci, _         := openid4vci.NewClient(&http.Client{}, conf, sdjwtvc.NewHolderVerificationProcessor(verifyCtx))
```

Note the **single DCQL handler** (`eudi_sdjwt_dcql`) — the POC intentionally
omits the IRMA handler. `conf.Reload()` and (in developer mode)
`EnableStagingTrustAnchors()` / `UpdateCertificateRevocationLists()` are called
exactly as `client.New`/`SetPreferences` do.

### 4.2 Headless handlers (the actual new logic)

`Receive` and `Present` are synchronous wrappers around the async clients. Each
uses a private handler that turns the client's callbacks into a channel result,
consulting a `Policy` to decide approval:

```go
type Policy interface {
    // ApproveIssuance is called with the offered credentials + requestor.
    ApproveIssuance(offered []*clientmodels.Credential, requestor *clientmodels.TrustedParty) bool
    // TransactionCode supplies a pre-authorized-code tx_code if the issuer asks for one.
    TransactionCode() (string, bool)
    // ApproveDisclosure selects what to disclose from the plan (default: the
    // minimal satisfying owned option per DCQL query).
    ApproveDisclosure(plan *clientmodels.DisclosurePlan, requestor *clientmodels.TrustedParty) ([]dcql.DisclosureSelection, bool)
}
```

- `AutoApprovePolicy` — approves everything, picks the first fully-owned
  disclosure option (good enough for the demo, mirrors the test handlers).
- `AllowlistPolicy` — approves issuance only from trusted requestors and
  discloses only claims on an allow-list; useful to show consent semantics.

The issuance handler implements `openid4vci.Handler`; for the happy path it
answers `RequestPreAuthorizedCodeFlowPermission` (supplying a tx_code from the
policy) and `RequestPermission` (approve), then resolves on `Success`. The
disclosure handler implements `openid4vp.Handler`, answering
`RequestVerificationPermission` by turning the `DisclosurePlan` +
`hashToQueryId` map into `[]dcql.DisclosureSelection` — the same conversion the
app performs in `client/openid4vp_adapters.go`
(`disclosureChoicesToOpenID4VPSelections`), which the POC lifts into a small
shared helper.

### 4.3 Flow choice for the POC happy path

Use the **Pre-Authorized Code flow** as the primary demo path: it needs no
browser and no redirect server, so it runs cleanly headless and in CI. The
Authorization Code flow is supported by the underlying client but requires an
OAuth redirect; for the POC it is a documented "advanced" path where the CLI
prints the authorization URL and accepts the pasted callback URL (feeding
`AuthCodeHandler`). Holder binding uses `cnf.jwk` (see §7 for the `did:jwk`
KB-JWT limitation).

## 5. The driver (CLI)

A `yivi sdjwtvc-wallet` subcommand (or standalone `cmd/sdjwtvc-wallet`) exposing:

| Command | Action |
|---|---|
| `receive <credential-offer-uri>` | Run OpenID4VCI issuance; print stored credentials |
| `present <authorization-request-uri>` | Run OpenID4VP disclosure; print what was shared |
| `list` | List stored credentials (`Wallet.Credentials()`) |
| `logs [--max N]` | Print issuance/disclosure/removal logs |
| `reset` | Wipe the wallet data dir |

Global flags: `--data-dir`, `--developer` (staging anchors + insecure http/did:web),
`--auto-approve` / `--allowlist <claims>`. The AES key is derived from a
`--pin`/passphrase (PBKDF/HKDF) or generated and stored for the demo.

## 6. Testing strategy

The repo already has everything needed to test this without external services:

- **Unit**: handler policy logic, plan→selection conversion, `Wallet.New` wiring.
- **E2E (offline)**: reuse the in-repo local issuance server + mock authorization
  server (`eudi/openid4vci` test helpers) and the Veramo verifier harness
  (`internal/sessiontest/openid4vp_veramo_disclosure_test.go`). New test:
  *issue via pre-auth flow → assert credential in `Wallet.Credentials()` →
  present to the verifier → assert disclosed claim set.*
- **E2E (live, opt-in)**: point `receive`/`present` at the real Python PID issuer
  and EUDI Kotlin verifier already used in
  `internal/sessiontest/eudi_pid_python_issuer_test.go` (gated behind a build
  tag / env var, like the existing suite).

## 7. Known limitations to carry into the POC (from the existing code)

These are pre-existing gaps in `eudi/*`; the POC should document them, not fix
them:

- **Deferred credential responses** not supported (`openid4vci/session.go` errors
  on HTTP 202).
- **DPoP nonce**, **signed AS metadata**, and **Client Attestation** not
  implemented; `client_id` is a fixed value.
- **`request_uri_method=post`** not handled in OpenID4VP; several `client_id`
  prefixes (`redirect_uri:`, `openid_federation:`, `verifier_attestation:`,
  `origin:`) are rejected.
- **KB-JWT holder binding** verifies `cnf.jwk` only; `cnf.kid` (`did:jwk`) is
  supported for KB-JWT *creation* but not verifier-side verification
  (`sdjwtvc/verify.go`). The POC's holder binding should use `cnf.jwk`.
- **Revocation** is not implemented (`Revoked`/`RevocationSupported` are false).
- **Holder keys** are ECDSA P-256 only, software-stored PKCS#8 (no HSM/secure
  enclave).
- **Only SD-JWT VC** (`dc+sd-jwt`, legacy `vc+sd-jwt`) is fully processed; mdoc /
  W3C VC are declared in metadata models but not implemented.
- **VCT-vs-requestor-certificate authorization** is currently commented out in
  the verification path (`sdjwtvc/verify.go`).
- **The EUDI SQLCipher database is NOT actually encrypted at rest.**
  `eudi/storage/storage.go:46` builds the connector as
  `&sqlcipher.Connector{Path: dbPath}` and never sets the key field, so
  `PRAGMA key` is never applied (`db/sqlcipher/driver.go:63`). The `aesKey`
  passed to `NewStorage` reaches only the filesystem layer. The result:
  `yivi-eudi.db` is a plaintext SQLite file (verified: header `SQLite format 3`,
  and the `sqlite3` CLI reads every table — including `holder_binding_keys`,
  which stores PKCS#8 holder private keys, and `issued_credential_instances`,
  which stores raw SD-JWT VC tokens — with no key). This affects the production
  mobile wallet too, not just the POC. The one-line fix is
  `sqlcipher.NewConnector(dbPath, aesKey[:])`; note it makes existing (plaintext)
  databases fail to open, so it needs a migration path. Until fixed, the POC's
  at-rest encryption covers only the filesystem containers (logos/certs/CRLs),
  not the credential database.

## 8. Work breakdown (suggested)

1. `wallet` package skeleton: `Config`, `New`, `Close`, `Credentials`,
   `Logs`, `Reset` (pure wiring, ~1 day).
2. Headless handlers + `Policy` (`AutoApprove`, `Allowlist`) and the
   plan→selection helper lifted from `client/openid4vp_adapters.go` (~1–2 days).
3. `Receive` (pre-auth flow) + `Present` synchronous wrappers (~1 day).
4. CLI driver `sdjwtvc-wallet` (~1 day).
5. Offline E2E test against the in-repo issuer/verifier harness (~1–2 days).
6. Docs: README for the package + how to run the demo (~0.5 day).

Total: roughly one to two weeks for a polished POC, most of it glue and tests.

## 9. Alternative considered: build on `client.Client`

Instead of a new `wallet` package, the POC could construct a `client.Client`
and drive it via `NewSession` / `HandleUserInteraction` (as the integration tests
do). **Rejected as the primary approach** because `client.Client` mandates an
IRMA configuration, keyshare signer, and bbolt storage even when only EUDI
features are used — that is precisely the coupling a "standalone SD-JWT VC wallet
POC" should shed. The integration-test path remains valuable as a reference and
for the live E2E tests, but the clean-room `wallet` facade is the better
demonstration of the EUDI stack standing on its own.

## 10. Decisions

Locked in for the POC:

- **Form factor**: **library core (`wallet`) + CLI (`sdjwtvc-wallet`) + E2E
  test harness** — all three. The library is the reusable unit; the CLI is the
  interactive demo; the test harness proves the lifecycle offline in CI.
- **Issuance flows**: **both** Pre-Authorized Code (headless happy path) **and**
  Authorization Code (paste-the-callback UX in the CLI, `AuthCodeHandler`).
- **Key custody**: software ECDSA P-256 in SQLCipher (as the services layer does
  today). A secure-enclave seam is out of scope but noted in §7.

## 11. Open questions

- **Key custody hardening**: should we stub a secure-enclave interface later to
  show the intended production seam? (Out of scope for the POC.)
