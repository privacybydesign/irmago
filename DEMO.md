# Running the mDoc age-verification demo on a phone

Everything needed to reproduce, on someone else's machine, the flow this branch
demonstrates: a `eu.europa.ec.av.1` credential issued over OpenID4VCI to a real
device, then presented over OpenID4VP, with the wallet refusing anything it
cannot authenticate.

**This branch is not for merging.** It carries three local trust anchors so a
demo works against the local docker stack with no patch step, and every one of
them is marked `LOCAL DEVELOPMENT ONLY -- DO NOT COMMIT` for the branch it should
never reach. Merging it would ship a wallet that trusts three self-signed test
CAs. See "What makes this branch different" below.

## The one rule for reproducibility

**Build the `.aar` from this branch.** Wallet behaviour lives in the library
packages (`client/`, `eudi/`), so a `.aar` built from any other commit will
behave differently no matter how faithfully the steps below are followed. A stale
`.aar` is the single most likely reason two people see different results.

Nothing else needs to match: the offer and presentation links are data generated
per run, not code, so they differ every time and that is expected.

## Prerequisites

1. **The stack.** From the repository root:
   ```
   docker compose up -d
   ```
   Wait for `eudi_pid_issuer_py`, `eudi_openid4vp_jwt` and `tls_proxy` to report
   running. If every call later 502s, `docker compose restart tls_proxy` --
   nginx caches upstream container IPs.

2. **`adb` on your PATH**, with the device connected. `mint-session` runs the
   port forwarding itself -- `adb reverse` for the verifier port, plus the issuer
   port when `-issue` is passed -- so `localhost` on the phone reaches this
   machine. If `adb` cannot be found it prints the exact commands to run and
   carries on, so the links are still usable. Pass `-reverse=false` to leave your
   adb state alone.

   Both forwards matter. Only the issuer is behind TLS, so a missing 8443 makes a
   presentation-only run work and issuance fail in a way that reads like a
   container problem.

3. **The app**, built from this branch and installed, with **developer mode on**.
   Without it the wallet refuses plain HTTP and the local scheme data.

4. **The app unlocked** when a link arrives. A locked app queues the intent at
   the PIN screen, which looks like nothing happening.

## Run it

```
go run ./yivi/cli/eudicli/mint-session -issue
```

That prints three commands and what to expect from each: an `adb` deep link for
the offer with its one-time code, an `adb` deep link for the presentation, and a
`curl` that reads back what was disclosed. Follow them in order, approving on the
phone.

After the presentation is approved **the app disappears**. That is deliberate and
not a crash: on a same-device session irmamobile hands the user back to whatever
called it, and on Android it does that by moving its own task to the background
so the OS surfaces the previous app. Launched from `adb` there is nothing to
surface, so it reads as the app exiting. The relevant code is the same-device
branch of `session_screen.dart` in irmamobile's `yivi_core`, which dispatches
`AndroidSendToBackgroundEvent` and pops; iOS shows an `ArrowBack` screen there
instead, lacking a way to do it itself. `mint-session` says the same thing at the
point you will see it.

The verify step pipes into `vptoken-decode`, which reports per document what was
actually disclosed. Run before approving, it answers HTTP 400 with a state error
-- the verifier saying "no answer yet", not a failure.

Useful variations:

```
go run ./yivi/cli/eudicli/mint-session                      presentation only, reuse a held credential
go run ./yivi/cli/eudicli/mint-session -value false         ask for false, to see a refusal
go run ./yivi/cli/eudicli/mint-session -value any           no value constraint
go run ./yivi/cli/eudicli/mint-session -element age_over_21 ask for a different threshold
```

`-value` constrains the query only. What `-issue` mints is always exactly
`localstack.DefaultAVElements`, so change the credential by editing that map --
which is also how the offer and the query are made to disagree on purpose.

## What to expect

The credential holds five thresholds and the query asks for one, so the
permission screen shows a single attribute while the wallet holds five. That is
the point: `vptoken-decode` shows one disclosed element against five digests in
the MSO, which is selective disclosure visible in the bytes.

Two runs on two machines agree on the parts that carry meaning and differ on the
parts that are supposed to:

| Identical anywhere | Different every run |
|---|---|
| `docType`, the disclosed element and its value | the `random` salt, fresh per item |
| the number of digests in `valueDigests` | `digestID` -- the issuer shuffles claim order deliberately, so the same element lands on a different id each issuance |
| the document signer, `CN=Yivi Test PID Issuer`, committed in testdata | `nonce`, `state`, `transaction_id`, signatures |
| `SHA-256`, a detached `deviceAuth` payload, an empty `deviceSigned.nameSpaces` | the validity dates, on a different day |

A differing salt or digestID is correct behaviour, not a discrepancy. The shuffle
is what stops a verifier inferring which undisclosed thresholds a credential
holds from the id of one that was disclosed; `TestClaimOrderingIsRandomized`
fails if it ever stops happening.

## Without a phone

```
go run ./yivi/cli/eudicli/mdoc-e2e
```

The same protocols end to end against the same containers, with a real
`client.Client` wallet in-process instead of a device. Needs no `adb`, no
`.aar`, and none of this branch's trust anchors -- it installs the test CAs into
its own throwaway wallet storage. Use it to tell "the stack is broken" apart from
"the phone is misconfigured".

```
go run ./yivi/cli/eudicli/mdoc-violations
```

Drives the same stack through protocol violations and reports whether each was
refused. Note that with this branch's anchors applied, scenario 13 can no longer
create an untrusted verifier and is expected to report ACCEPTED.

## What makes this branch different

| Store | Authenticates | Where |
|---|---|---|
| Go x509 system pool | the TLS certificate of `tls_proxy` | `client/localdev_trust.go` |
| `c.Issuers` | the issuer's document signer inside the MSO | `Local_Demo_IssuerTrustAnchor`, `eudi/trustanchors.go` |
| `c.Verifiers` | the relying party's request-signing certificate | `Local_Demo_VerifierTrustAnchor`, `eudi/trustanchors.go` |

Three separate stores, deliberately: an issuer anchor must not be able to
authenticate a relying party, which `mdoc-violations` scenario 38 pins.

To strip them, delete `client/localdev_trust.go` -- nothing else calls into it --
and revert `eudi/eudiconfig.go` and `eudi/trustanchors.go`. Then
`grep -rn "DO NOT COMMIT" --include=*.go .` should find nothing. Do that before
running the full test suite: with the anchors applied,
`testEudiPidPythonIssuerUntrustedIssuerIsRejected` fails for reasons unrelated to
the code under test.
