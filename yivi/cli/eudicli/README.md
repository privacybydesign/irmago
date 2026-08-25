# eudicli — EUDI command line tools

Six `package main` programs for working with the EUDI credential code by hand.
They live here rather than beside the packages they exercise because Go does not
allow a `func main()` to sit in the same package as library code.

| Tool | What it does | Needs |
|---|---|---|
| [`mdoc-decode`](#mdoc-decode--cosecbor-inspector) | decodes a hex-encoded COSE_Sign1 or CBOR blob and prints its structure | nothing |
| [`mdoc-demo`](#mdoc-demo--selective-disclosure-in-process) | walks one credential through issue → disclose → verify in-process, printing what each side sees | nothing |
| [`mdoc-e2e`](#mdoc-e2e--the-real-protocols-against-the-reference-containers) | the same story over real OpenID4VCI and OpenID4VP against the EUDI reference containers | `docker compose up -d` |
| [`mdoc-violations`](#mdoc-violations--protocol-violations-end-to-end) | runs protocol violations through the same real stack and reports whether each was refused | `docker compose up -d` |
| [`mint-session`](#mint-session--drive-a-real-phone) | starts an issuance and/or presentation and prints the `adb` commands to drive a phone through them | `docker compose up -d`, `adb reverse` |
| [`vptoken-decode`](#vptoken-decode--read-back-what-was-disclosed) | decodes a verifier's `vp_token` and reports what each document actually disclosed | nothing |

Each program's own package comment is the detailed reference; this file is the
map. Run any of them from the repository root.

---

## mdoc-demo — selective disclosure, in process

```bash
go run ./yivi/cli/eudicli/mdoc-demo
```

Issues an age-verification credential with two claims, presents one, and verifies
it as a party that trusts only the issuer's root — printing the MSO's digests next
to the disclosed items at each step, so it is visible *why* withholding a claim is
safe for the verifier and private for the holder. No containers, no wallet storage,
no network: everything runs against `eudi/credentials/mdoc` directly.

## mdoc-e2e — the real protocols, against the reference containers

```bash
docker compose up -d
go run ./yivi/cli/eudicli/mdoc-e2e
```

The counterpart to `mdoc-demo`: same story, but issued over OpenID4VCI by the EUDI
reference issuer and presented over OpenID4VP to the EUDI reference verifier, with
a real `client.Client` wallet in between. Nothing is mocked, so what fails here
fails on a phone too.

The walkthrough goes to stdout and the wallet's own log to stderr, so they can be
read apart (`2> e2e.log`) or together (`2>&1 | tee e2e.log`). Neither is the
wallet's *activity* log — the entries the app shows the user; step 7 prints those
as JSON, and `-logs <path>` writes them somewhere they outlive the run.

---

## mdoc-violations — protocol violations, end to end

```bash
docker compose up -d
go run ./yivi/cli/eudicli/mdoc-violations
go run ./yivi/cli/eudicli/mdoc-violations -only 22,33,34   # a subset
```

Where `mdoc-e2e` shows the happy path, this drives the same stack — real issuer
container, real `client.Client` on fresh storage, real verifier container —
through a battery of things a conformant party would never send, and reports for
each whether it was refused. A scenario passes only when the real wallet or the
real container rejects the session; no verification function is called directly.

Requests that have to differ from what the reference verifier sends are made by
taking the container's own signed request JWT, changing exactly one field, and
re-signing with the verifier private key from `testdata/eudi/verifier`. The
modified request is served from a throwaway local HTTP server standing in for
`request_uri`. Scenario 1 is the control for that rig: an unmodified re-signed
request must still succeed, or every later rejection would be an artifact of the
minting rather than a property of the wallet.

Two results are expected not to be refused, and the summary says so rather than
hiding them. One depends on a trust anchor not being compiled in (see the note it
prints); the other is the `aud` claim, which is reported but deliberately
unchecked — the reasoning is in the CHANGELOG entry for the request-object
claims.

---

## mint-session — drive a real phone

```bash
go run ./yivi/cli/eudicli/mint-session                 presentation only
go run ./yivi/cli/eudicli/mint-session -issue          issuance too
go run ./yivi/cli/eudicli/mint-session -value false    ask for false
go run ./yivi/cli/eudicli/mint-session -element age_over_21
go run ./yivi/cli/eudicli/mint-session -show-query     print the DCQL being sent
go run ./yivi/cli/eudicli/mint-session -issue -email   mail the one-time code
go run ./yivi/cli/eudicli/mint-session -issue -mint age_over_42=true
```

Where `mdoc-e2e` drives a wallet it builds itself, this prints the three commands
needed to drive a real phone: the `adb` deep link for an offer, the one for a
presentation, and the `curl` that reads the answer back. It shares its
request-building with `mdoc-e2e` through `internal/localstack`, so the links a
device is handed cannot drift from the ones the automated demo uses.

Three flag pairs are easy to confuse, and the separation is deliberate:

| Flag | Decides | Note |
|---|---|---|
| `-mint` | what the credential *holds* | empty mints `localstack.DefaultAVElements` |
| `-element` / `-value` | what the query *asks* | so the two can be made to disagree, which is what testing a refusal needs |
| `-email` / `-mail-to` | where the one-time code goes | the code is never in the offer link |

`-email` is a bool: the default `-smtp localhost:1025` is the compose stack's
mailhog, which captures mail and delivers none, so every recipient behaves alike
and no address is needed. **Read it at http://localhost:8025** — it reaches no
inbox. `-mail-to` matters only once `-smtp` points at a relay that really
delivers, with credentials from `SMTP_USERNAME` / `SMTP_PASSWORD`.

`-show-query` prints the `dcql_query` as sent, from the same
`localstack.DcqlQuery` that builds it. There is otherwise no way to read it: the
request object is single use, so fetching it to decode the query leaves nothing
for the phone, and the verifier answers 400 until the wallet responds and keeps
no record across a restart.

Prerequisites beyond the stack: `adb reverse` for 8090, plus 8443 when issuing.
The app needs developer mode on and must be *unlocked* when a link arrives — a
locked app queues it at the PIN screen, which looks like nothing happening.

## vptoken-decode — read back what was disclosed

```bash
curl -s http://127.0.0.1:8090/ui/presentations/<tx> | go run ./yivi/cli/eudicli/vptoken-decode
```

Takes a verifier's whole response, a bare base64url `DeviceResponse`, or hex, by
argument or on stdin, and reports per credential and per document what was
disclosed and who signed it. Where `mdoc-decode` prints CBOR structure for any
blob, this one knows it is looking at a presentation: it resolves the Tag-24
`IssuerSignedItem` byte arrays and the x5chain certificate, which `mdoc-decode`
leaves raw. Prefer it for whole presentations; reach for `mdoc-decode` when all
you have is a fragment such as a bare `issuerAuth`.

Verifies nothing — no signature check, no digest recomputation, no chain walk.
It answers "what is in these bytes", which is not "are they genuine".

---

## mdoc-decode — COSE/CBOR inspector

Inspects any hex-encoded COSE_Sign1 or CBOR blob produced by
`eudi/credentials/mdoc` (`issuerAuth`, `deviceAuth`, a full presented mdoc, or any
raw CBOR bytes). Read-only — it does not verify signatures, certificate chains, or
digests; it only decodes and prints structure so you can eyeball what's actually
inside. The decoding itself lives in `internal/mdocdecode` so the demos can call
it too.

---

### Usage

From the repository root:

```bash
go run ./yivi/cli/eudicli/mdoc-decode <hex-string>
go run ./yivi/cli/eudicli/mdoc-decode -    # reads hex from stdin instead
```

Input can have spaces or newlines in it (e.g. pasted from a wrapped
terminal output) — they're stripped before decoding.

#### Examples

```bash
# decode a deviceAuth COSE_Sign1
go run ./yivi/cli/eudicli/mdoc-decode d28443a10126a0585c84...988b

# decode a full presented mdoc from a file
cat mdoc.hex | go run ./yivi/cli/eudicli/mdoc-decode -
```

To read back a `vp_token` an OpenID4VP verifier collected, use
[`vptoken-decode`](#vptoken-decode--read-back-what-was-disclosed) rather than this
tool: it accepts base64url directly, walks every credential and document in the
response, and resolves the Tag-24 items and x5chain. `mdoc-decode` is for a
fragment you already hold as hex.

Piping to `-` rather than passing hex as an argument keeps a multi-document
response clear of the Windows command-line length limit.

---

### What it does

**If the input is a well-formed COSE_Sign1** (a 4-element CBOR array:
`[protected, unprotected, payload, signature]`), it prints:

- **Protected header** — decoded, with known `alg` values (`ES256`/`ES384`/`ES512`) named instead of left as raw integers
- **Unprotected header** — decoded, with `x5chain` (header 33) broken into individual certs, each shown as byte length + a DER hex preview
- **Payload** — full hex, then recursively decoded (see below)
- **Signature** — full hex, split into `r`/`s` halves (computed from actual length, not hardcoded), with a note on whether the total length matches a standard ES256/384/512 size

**If it's not a COSE_Sign1**, it falls back to generic CBOR pretty-printing of whatever structure is there (maps, arrays, byte strings, etc.).

#### Automatic recursion

Any `[]byte` field encountered during decoding — payload, a nested claim, whatever — is checked to see if *it itself* contains embedded CBOR:

- **Tag-24 wrapped bytes** (`0xd8 0x18` prefix) are unwrapped automatically
- **Nested COSE_Sign1 structures** (a 4-element array starting with `0xd2`) are detected and recursively decoded with the same header/payload/signature breakdown

This is what lets one invocation walk all the way from a full mdoc → `issuerSigned.nameSpaces[...].EncodedItem` (Tag-24 wrapped claim) and → `issuerAuth`/`deviceAuth` (nested COSE_Sign1 → MSO/DeviceAuthentication payload) without needing separate commands per layer.

#### Readable timestamps

Known mdoc/MSO timestamp fields (`signed`, `validFrom`, `validUntil`) are printed
readably in either encoding they arrive in. ISO 18013-5 puts a tag-0 RFC 3339 string
there, which is what this package writes and what the reference issuers send:

```
validUntil: 2026-11-16T00:00:00Z  (tag-0 RFC3339)
```

A bare Unix epoch integer — an older encoding still found in the wild — is shown as
both the raw value and the date it means:

```
validUntil: 1791452553  (2027-07-10T08:42:33Z, legacy bare-epoch encoding)
```

---

### Limitations

- **Does not verify anything.** No signature checking, no cert chain walk, no digest recomputation. Use the actual `Verifier` (in `eudi/credentials/mdoc`) for that — this tool only tells you what bytes are present, not whether they're trustworthy.
- **Heuristic recursion, not exhaustive.** `looksLikeNestedCBOR` only recognizes Tag-24 and 4-element COSE_Sign1 arrays; other nested CBOR shapes fall through to a flat hex dump.
- **Best-effort formatting.** Unknown COSE header labels are printed as their raw integer key; unknown timestamp field names are left as plain integers.

---

### Why this exists

Handy for sanity-checking that the main program's output is actually
spec-shaped CBOR/COSE — e.g. confirming `deviceKeyInfo`'s map keys are real
CBOR integers (not text-string keys), or visually diffing `issuerAuth`
against `deviceAuth` to see which fields differ between the two signatures.