// Package vcdmsdjwt implements the SD-JWT-secured W3C VCDM 2.0 credential
// (VC-JOSE-COSE §3.2, https://www.w3.org/TR/vc-jose-cose/): milestone M1 of the
// VCDM effort. It is a policy layer over two cores:
//
//   - eudi/sdjwt: the SD-JWT *securing* core (issuer-signed JWT, `_sd`/`_sd_alg`
//     disclosures, the `~` serialization, `cnf` + KB-JWT holder binding); and
//   - eudi/credentials/vcdm: the securing-agnostic VCDM 2.0 *data-model* core
//     (structural validation, validity period, data-model detection).
//
// It sits parallel to eudi/credentials/sdjwtvc, the IETF SD-JWT VC (`vct`)
// policy layer over the same eudi/sdjwt core. The two differ only in the data
// model carried in the payload: an SD-JWT-secured VCDM credential's payload is
// a W3C VCDM 2.0 document (`@context`/`type`/`issuer`/`credentialSubject`/…),
// whereas an SD-JWT VC's payload is a flat `vct`-typed claim set. These are
// distinct data models: an SD-JWT-secured VCDM credential is NOT an IETF
// SD-JWT VC, so they get distinct policy layers over the shared securing core.
//
// Media type (JWS `typ` header): only `vc+sd-jwt`. `dc+sd-jwt` is IETF SD-JWT
// VC and belongs to eudi/credentials/sdjwtvc. After verifying the signature,
// this layer also requires the decoded payload to be a VCDM document
// (vcdm.IsVCDM).
//
// Verification order follows VCDM 2.0 §7.1: the SD-JWT proof is verified first
// (issuer signature over the issuer-signed JWT, via the shared eudi/jwt key
// provider (X.509 `x5c` or DID `kid`/did:web/did:jwk), plus disclosure
// digest checks), and only then is the decoded/disclosed document validated
// structurally as VCDM. Structural validation never runs on the raw wire form.
//
// Issuer trust is hybrid X.509 + DID: reusing eudi/jwt's key provider means an
// `x5c` header resolves and validates an X.509 chain, and a `kid` header
// resolves a did:web / did:jwk issuer key. No VCDM-specific trust code.
//
// Holder binding reuses the shared `cnf` handling in eudi/sdjwt, which resolves
// both the `cnf.jwk` and `cnf.kid` (did:jwk / did:key) forms. The holder proof
// at presentation is not a KB-JWT but a Verifiable Presentation signed with
// that key, enveloping the SD-JWT (presentation.go; docs/adr/0011).
package vcdmsdjwt
