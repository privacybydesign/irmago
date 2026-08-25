# Running the mDoc age-verification demo on a phone

Everything needed to reproduce, on someone else's machine, the flow this branch
demonstrates: a `eu.europa.ec.av.1` credential issued over OpenID4VCI to a real
device, then presented over OpenID4VP, with the wallet refusing anything it
cannot authenticate.

**A demo run needs a local trust patch that is deliberately not committed here.**
Nothing on a phone trusts the docker stack's self-signed certificates, so three
separate trust additions have to be applied to the working tree before the `.aar`
is built. They live outside the repository on purpose -- committing them would
ship a wallet trusting three self-signed test CAs. See "Applying the local trust
patch" below, and apply it before anything else in this file will work.

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
the offer, an `adb` deep link for the presentation, and a `curl` that reads back
what was disclosed. Follow them in order, approving on the phone.

The one-time code is printed alongside, **not carried in the offer link**. The
reference issuer returns it inside the offer it hands back, which is a convenience
of the fixture rather than the protocol -- OpenID4VCI's `tx_code` object has no
`value` member, and a code shipped inside the link it protects protects nothing --
so `localstack.CreateOffer` strips it before building the link. The wallet always
prompts for it either way: `openid4vci.TransactionCode` carries only
`input_mode`, `length` and `description`, and never read a value. Pass `-email` to
have the code mailed instead of printed, which is how to demonstrate it arriving
on a channel the link did not travel on; with the default `-smtp` that is the
stack's mailhog, read at <http://localhost:8025>.

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
go run ./yivi/cli/eudicli/mint-session -show-query          print the DCQL query being sent
go run ./yivi/cli/eudicli/mint-session -issue -email        mail the one-time code
go run ./yivi/cli/eudicli/mint-session -issue -mint age_over_42=true
```

`-value` constrains the query; `-mint` decides the credential. Keeping them
separate is what allows the offer and the query to disagree on purpose, which is
what testing a refusal requires -- a single flag driving both would make every run
agree with itself. `-issue` without `-mint` mints exactly
`localstack.DefaultAVElements`.

Two boundaries are worth knowing before changing either. The issuer does **not**
validate what it is asked to mint: `-mint age_over_42=true` is accepted even
though 42 is absent from its advertised claim set. Presenting one is a different
matter -- the relying party certificate's authorized set decides what may be
requested, so an unadvertised element can be issued and then never asked for. See
`testdata/eudi/verifier/README.md` for widening that set.

Re-issuing the same claims twice is now refused while the stored credential is
still presentable, and accepted once it is spent or expired, so `-issue` is not a
way to obtain a second identical credential -- it is the renewal path.

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
`.aar`, and no part of the local trust patch -- it installs the test CAs into
its own throwaway wallet storage. Use it to tell "the stack is broken" apart from
"the phone is misconfigured".

```
go run ./yivi/cli/eudicli/mdoc-violations
```

Drives the same stack through protocol violations and reports whether each was
refused. Note that with the local trust patch applied, scenario 13 can no longer
create an untrusted verifier and is expected to report ACCEPTED.

## Applying the local trust patch

The three trust additions are **not in this repository** and must be applied to
the working tree before building the `.aar`:

```
git apply --exclude=DEMO.md <path-to>/localdev-trust-4743a671.patch
```

`--exclude=DEMO.md` matters: the patch carries its own copy of this file, and
without the exclusion `git apply` aborts on the collision and applies *nothing* --
including the three hunks you wanted.

| # | Store | Authenticates | Added to | Error when missing |
|---|---|---|---|---|
| 1 | Go x509 system pool | the TLS certificate of `tls_proxy` on :8443 | `client/localdev_trust.go` (new file) | `tls: failed to verify certificate` while fetching issuer metadata |
| 2 | `c.Issuers` | the issuer's document signer inside the MSO | `Local_Demo_IssuerTrustAnchor`, `eudi/trustanchors.go` | `mdoc verification failed: chain verification failed` -- credential fetched, then refused |
| 3 | `c.Verifiers` | the relying party's request-signing certificate | `Local_Demo_VerifierTrustAnchor`, `eudi/trustanchors.go` | fails at presentation, naming the relying party |

They fail one at a time in that order, so fixing one reveals the next -- a single
"certificate signed by unknown authority" tells you nothing on its own. Read which
stage the error names.

Three separate stores, deliberately: an issuer anchor must not be able to
authenticate a relying party, which `mdoc-violations` scenario 38 pins.

**Stores 2 and 3 need developer mode on**, store 1 does not. Store 1 installs from
`init()`, so it applies unconditionally; the other two live inside
`addStagingTrustAnchors()`, which `Configuration.Reload` calls only when
`Preferences.DeveloperMode` is set. With developer mode off you therefore get a
credential that downloads over TLS and is then refused with error 2 -- which reads
like a missing patch and is not.

To strip the patch again:

```
rm client/localdev_trust.go
git checkout -- eudi/eudiconfig.go eudi/trustanchors.go
grep -rn "DO NOT COMMIT" --include=*.go .     # must find nothing
```

Do that before running the full test suite or merging: with the anchors applied,
`testEudiPidPythonIssuerUntrustedIssuerIsRejected` fails for reasons unrelated to
the code under test, and `mdoc-violations` scenario 13 can no longer build an
untrusted verifier, so it reports ACCEPTED.
