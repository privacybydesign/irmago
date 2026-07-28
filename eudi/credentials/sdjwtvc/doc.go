// Package sdjwtvc implements the SD-JWT VC (SD-JWT-based Verifiable
// Credential) format from draft-ietf-oauth-sd-jwt-vc, layered on top of
// eudi/sdjwt's SD-JWT core: `vct`, `vct#integrity`, the `dc+sd-jwt` (and
// legacy `vc+sd-jwt`) media types, issuer identification via the `x5c`
// certificate chain and `iss`, the `status` claim, and the
// SdJwtVcBuilder/verification-processor policy that enforces them.
//
// SdJwtVc and SdJwtVcKb are defined types over sdjwt.SdJwt and
// sdjwt.SdJwtKb — not aliases — so converting between "a raw SD-JWT" and
// "an SD-JWT VC" is always an explicit, visible conversion rather than
// something the compiler lets slip by silently.
//
// This package deliberately does not cover:
//
//   - SD-JWT core mechanics (disclosures, `_sd`/`_sd_alg`, KB-JWT, the
//     claim-tree Builder): see eudi/sdjwt.
//
//   - IETF OAuth Token Status List (draft-ietf-oauth-status-list):
//     delegated entirely to eudi/credentials/statuslist. That integration
//     is not restructured by the sdjwt/sdjwtvc split — the split alone
//     already buys the clearer boundary that was asked for, since
//     eudi/sdjwt itself now has zero reference to statuslist. Every
//     status-list touchpoint in this package is confined to three named
//     places, so a reader can find the seam without grepping:
//
//   - IssuerSignedJwtPayload.Status — the `status.status_list`
//     reference carried on a verified credential.
//
//   - SdJwtVcVerificationContext.StatusChecker — the pluggable,
//     nil-by-default hook that turns the reference into a fetch.
//     Nil disables the check entirely (back-compat default).
//
//   - sdJwtVcProcessor.runStatusListCheck — where the check actually
//     runs, at the end of ProcessAndVerifySdJwtVc.
//
// Two follow-ups were considered and deliberately deferred rather than
// done as part of the split: replacing IssuerSignedJwtPayload.Status's direct
// *statuslist.StatusClaim with a VC-local status claim type, and turning
// StatusChecker into a fully pluggable post-verification hook interface
// rather than a struct field.
//
// Two smaller boundary decisions worth knowing about when reading this
// package:
//
//   - verifyTimeFields (exp/iat/nbf with clock skew) stays here rather
//     than moving to eudi/sdjwt: it is generic JWT validation, not
//     SD-JWT-specific, but it reads this package's IssuerSignedJwtPayload
//     and moving it would mean threading a clock into eudi/sdjwt for no
//     present benefit.
//
//   - ClockSkewInSeconds (180) duplicates statuslist.ClockSkewSeconds.
//     Both are independently specified windows that happen to coincide;
//     this is deliberate, not an oversight — do not deduplicate them into
//     a shared constant.
package sdjwtvc
