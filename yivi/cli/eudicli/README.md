# eudicli — EUDI command line tools

Three `package main` programs for working with the EUDI credential code by hand.
They live here rather than beside the packages they exercise because Go does not
allow a `func main()` to sit in the same package as library code.

| Tool | What it does | Needs |
|---|---|---|
| [`mdoc-decode`](#mdoc-decode--cosecbor-inspector) | decodes a hex-encoded COSE_Sign1 or CBOR blob and prints its structure | nothing |
| [`mdoc-demo`](#mdoc-demo--selective-disclosure-in-process) | walks one credential through issue → disclose → verify in-process, printing what each side sees | nothing |
| [`mdoc-e2e`](#mdoc-e2e--the-real-protocols-against-the-reference-containers) | the same story over real OpenID4VCI and OpenID4VP against the EUDI reference containers | `docker compose up -d` |

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
go run ./yivi/cli/eudicli/mdoc-decode.go <hex-string>
go run ./yivi/cli/eudicli/mdoc-decode.go -    # reads hex from stdin instead
```

Input can have spaces or newlines in it (e.g. pasted from a wrapped
terminal output) — they're stripped before decoding.

#### Examples

```bash
# decode a deviceAuth COSE_Sign1
go run ./yivi/cli/eudicli/mdoc-decode.go d28443a10126a0585c84...988b

# decode a full presented mdoc from a file
cat mdoc.hex | go run ./yivi/cli/eudicli/mdoc-decode.go -
```

To read back a `vp_token` an OpenID4VP verifier collected, the entry has to be
converted from base64url to hex first (PowerShell):

```powershell
$tx  = "<transaction_id>"
$r   = curl.exe -s "http://127.0.0.1:8090/ui/presentations/$tx" | ConvertFrom-Json
$b64 = $r.vp_token.age; if ($b64 -is [array]) { $b64 = $b64[0] }
$b64 = $b64.Replace('-','+').Replace('_','/')
$b64 = $b64.PadRight(4 * [math]::Ceiling($b64.Length / 4), '=')
$hex = -join ([Convert]::FromBase64String($b64) | % { $_.ToString('x2') })
$hex | go run ./yivi/cli/eudicli/mdoc-decode.go -
```

Piping to `-` rather than passing the hex as an argument keeps a multi-document
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

Known mdoc/MSO timestamp fields (`signed`, `validFrom`, `validUntil`) are shown as both the raw epoch integer and a human-readable UTC date, e.g.:

```
validUntil: 1791452553  (2027-07-10T08:42:33Z)
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