// Package vcdm implements the W3C Verifiable Credentials Data Model 2.0
// (https://www.w3.org/TR/vc-data-model-2.0/, REC 2025-05-15) as a wallet/holder
// must understand it: the base `@context`, the `type` discriminator, `issuer`,
// `credentialSubject`, the `validFrom`/`validUntil` validity period, and the
// typed extension points (`credentialStatus`, `credentialSchema`, `termsOfUse`,
// `evidence`, `refreshService`).
//
// This package is the shared, securing-agnostic data-model core. The *data
// model* (W3C VCDM) and the *securing mechanism* (SD-JWT / JOSE / Data
// Integrity) are orthogonal axes: each securing layer decodes its wire format
// down to a logical JSON document and then hands that document here for
// structural validation, independent of how it was secured. The SD-JWT-secured
// securing layer lives in eudi/credentials/vcdmsdjwt; JOSE-enveloped and
// Data-Integrity securings will be siblings reusing this same core.
//
// Following VCDM 2.0 §6.3 ("Type-Specific Credential Processing"), this package
// takes the sanctioned lightweight path for wallets that pin the base
// `@context` by order and hash: it validates the decoded document
// *structurally* without a full JSON-LD processor. JSON-LD expansion, RDF
// canonicalization, and Data-Integrity proof suites are deliberately out of
// scope here — they belong to the Data-Integrity securing layer (map milestone
// M3), not to the data model.
//
// Two boundaries worth knowing when reading this package:
//
//   - Validate reports *structural* conformance (VCDM §1.3 "conforming
//     document" + Appendix A "Validation"): the shapes that must hold
//     regardless of securing mechanism. Per §7.1, a securing layer MUST run
//     this check *after* its mechanism-specific proof verification, on the
//     decoded/disclosed logical document — never on the raw wire form.
//
//   - VerifyValidityPeriod is a separate, temporal check ("is this credential
//     valid *now*"), kept apart from Validate so that structural conformance
//     and point-in-time validity are independently testable and a caller can
//     choose its own clock and skew.
//
// A Document is held as a raw map[string]any rather than a fixed struct: VCDM
// is an open-world JSON-LD model where all but a handful of properties may be
// arrays and extensions carry unknown terms, so a lossless map preserves the
// document for storage and claim traversal while typed accessors enforce shape
// on read.
package vcdm
