// Package sdjwt implements the core SD-JWT format from
// draft-ietf-oauth-selective-disclosure-jwt: salted disclosures, the
// `_sd`/`_sd_alg` digest mechanism, the `~`-separated compact
// serialization, the claim-tree Builder, and the Key Binding JWT (KB-JWT)
// with its `cnf` confirmation-key mechanism. Section references scattered
// through this package's comments (e.g. "SD-JWT spec Section 4.1.1") anchor
// to that draft.
//
// This package deliberately does not cover:
//
//   - SD-JWT VC (draft-ietf-oauth-sd-jwt-vc): `vct`, `vct#integrity`, the
//     `dc+sd-jwt` media type, issuer identification via `x5c`/`iss`, the
//     `status` claim, and SD-JWT VC Type Metadata. See
//     eudi/credentials/sdjwtvc, which wraps this package's Builder and
//     SdJwt/SdJwtKb types to add that policy layer: SdJwtVcBuilder wraps
//     Builder, and sdjwtvc.SdJwtVc/SdJwtVcKb are defined types over this
//     package's SdJwt/SdJwtKb — not aliases — so the compiler flags any
//     place a raw SD-JWT is used where an SD-JWT VC is expected.
//
//   - IETF OAuth Token Status List (draft-ietf-oauth-status-list): that
//     lives in eudi/credentials/statuslist. This package has no reference
//     to it at all, at the type level or otherwise; a go list -deps
//     invariant test (see invariant_test.go) enforces that.
//
// Hard invariant: this package must not import eudi/credentials/sdjwtvc,
// eudi/credentials/statuslist, eudi/scheme, or eudi/credentials/sdjwtvc/
// typemetadata. It also avoids eudi/jwt and eudi/utils, even though both
// would be convenient (a system clock, a generic optional-field lookup):
// both transitively import eudi/scheme through unrelated X.509-
// certificate-extension code living in those same packages, so kbjwt.go
// carries tiny private replacements instead (systemClock,
// extractOptionalWith) rather than pulling that dependency in.
package sdjwt
