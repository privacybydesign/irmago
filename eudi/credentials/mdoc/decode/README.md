# decode — COSE/CBOR inspector

A standalone CLI for manually inspecting any hex-encoded COSE_Sign1 or CBOR
blob produced by the mdoc program (`issuerAuth`, `deviceAuth`, a full
presented mdoc, or any raw CBOR bytes). Read-only — it does not verify
signatures, certificate chains, or digests; it only decodes and prints
structure so you can eyeball what's actually inside.

Lives in its own directory because it's a separate `package main` — Go
doesn't allow two `func main()`s in the same package, so this can't share a
folder with the project's other runnable binary (`cmd/demo/main.go`).

---

## Usage

```bash
cd decode
go run decode.go <hex-string>
go run decode.go -              # reads hex from stdin instead
```

Input can have spaces or newlines in it (e.g. pasted from a wrapped
terminal output) — they're stripped before decoding.

### Examples

```bash
# decode a deviceAuth COSE_Sign1
go run decode.go d28443a10126a0585c84...988b

# decode a full presented mdoc from a file
cat mdoc.hex | go run decode.go -
```

---

## What it does

**If the input is a well-formed COSE_Sign1** (a 4-element CBOR array:
`[protected, unprotected, payload, signature]`), it prints:

- **Protected header** — decoded, with known `alg` values (`ES256`/`ES384`/`ES512`) named instead of left as raw integers
- **Unprotected header** — decoded, with `x5chain` (header 33) broken into individual certs, each shown as byte length + a DER hex preview
- **Payload** — full hex, then recursively decoded (see below)
- **Signature** — full hex, split into `r`/`s` halves (computed from actual length, not hardcoded), with a note on whether the total length matches a standard ES256/384/512 size

**If it's not a COSE_Sign1**, it falls back to generic CBOR pretty-printing of whatever structure is there (maps, arrays, byte strings, etc.).

### Automatic recursion

Any `[]byte` field encountered during decoding — payload, a nested claim, whatever — is checked to see if *it itself* contains embedded CBOR:

- **Tag-24 wrapped bytes** (`0xd8 0x18` prefix) are unwrapped automatically
- **Nested COSE_Sign1 structures** (a 4-element array starting with `0xd2`) are detected and recursively decoded with the same header/payload/signature breakdown

This is what lets one invocation walk all the way from a full mdoc → `issuerSigned.nameSpaces[...].EncodedItem` (Tag-24 wrapped claim) and → `issuerAuth`/`deviceAuth` (nested COSE_Sign1 → MSO/DeviceAuthentication payload) without needing separate commands per layer.

### Readable timestamps

Known mdoc/MSO timestamp fields (`signed`, `validFrom`, `validUntil`) are shown as both the raw epoch integer and a human-readable UTC date, e.g.:

```
validUntil: 1791452553  (2027-07-10T08:42:33Z)
```

---

## Limitations

- **Does not verify anything.** No signature checking, no cert chain walk, no digest recomputation. Use the actual `Verifier` (in the parent package) for that — this tool only tells you what bytes are present, not whether they're trustworthy.
- **Heuristic recursion, not exhaustive.** `looksLikeNestedCBOR` only recognizes Tag-24 and 4-element COSE_Sign1 arrays; other nested CBOR shapes fall through to a flat hex dump.
- **Best-effort formatting.** Unknown COSE header labels are printed as their raw integer key; unknown timestamp field names are left as plain integers.

---

## Why this exists

Handy for sanity-checking that the main program's output is actually
spec-shaped CBOR/COSE — e.g. confirming `deviceKeyInfo`'s map keys are real
CBOR integers (not text-string keys), or visually diffing `issuerAuth`
against `deviceAuth` to see which fields differ between the two signatures.