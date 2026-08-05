// Package vcdmsdjwt implements the SD-JWT-secured W3C VCDM 2.0 credential
// (VC-JOSE-COSE §3.2, https://www.w3.org/TR/vc-jose-cose/): milestone M1 of the
// VCDM effort. It is a policy layer over two cores:
//
//   - eudi/sdjwt — the SD-JWT *securing* core (issuer-signed JWT, `_sd`/`_sd_alg`
//     disclosures, the `~` serialization, `cnf` + KB-JWT holder binding); and
//   - eudi/credentials/vcdm — the securing-agnostic VCDM 2.0 *data-model* core
//     (structural validation, validity period, data-model detection).
//
// It sits parallel to eudi/credentials/sdjwtvc, the IETF SD-JWT VC (`vct`)
// policy layer over the same eudi/sdjwt core. The two differ only in the data
// model carried in the payload: an SD-JWT-secured VCDM credential's payload is
// a W3C VCDM 2.0 document (`@context`/`type`/`issuer`/`credentialSubject`/…),
// whereas an SD-JWT VC's payload is a flat `vct`-typed claim set. These are
// distinct data models — an SD-JWT-secured VCDM credential is NOT an IETF
// SD-JWT VC — so they get distinct policy layers over the shared securing core.
//
// Media types (JWS `typ` header): per the effort's format-id convention,
// `vc+sd-jwt` always denotes an SD-JWT-secured VCDM credential, while
// `dc+sd-jwt` is content-dispatched (a `dc+sd-jwt` payload is VCDM only when it
// looks like VCDM). This layer accepts both `typ` values at the securing level
// and then gates on the decoded payload actually being a VCDM document (the
// cornerstone dispatch, vcdm.IsVCDM); a `dc+sd-jwt` carrying an IETF SD-JWT VC
// is rejected here and belongs to eudi/credentials/sdjwtvc.
//
// Verification order follows VCDM 2.0 §7.1: the SD-JWT proof is verified first
// (issuer signature over the issuer-signed JWT, via the shared eudi/jwt key
// provider — X.509 `x5c` or DID `kid`/did:web/did:jwk — plus disclosure
// digest checks), and only then is the decoded/disclosed document validated
// structurally as VCDM. Structural validation never runs on the raw wire form.
//
// Issuer trust is hybrid X.509 + DID: reusing eudi/jwt's key provider means an
// `x5c` header resolves and validates an X.509 chain, and a `kid` header
// resolves a did:web / did:jwk issuer key — no VCDM-specific trust code.
//
// Holder binding reuses the shared `cnf` + KB-JWT machinery in eudi/sdjwt,
// which resolves both the `cnf.jwk` and `cnf.kid` (did:jwk / did:key) forms;
// this layer therefore does not reintroduce the jwk-only limitation.
//
// Deliberately out of scope for M1 (tracked separately on the map):
//
//   - Selective *presentation* / disclosure (KB-JWT over OpenID4VP). Only
//     holder-side *receipt* verification is implemented here; the
//     keyBindingProcessor seam mirrors sdjwtvc so a verifier-side processor can
//     be added later without restructuring.
//   - Revocation / status. W3C BitstringStatusList does not interoperate with
//     the IETF Token Status List and needs its own sibling package; this layer
//     has no status hook yet.
//   - OpenID4VCI client / storage integration (dispatch into this verifier,
//     persistence, claim-path surfacing).
package vcdmsdjwt
