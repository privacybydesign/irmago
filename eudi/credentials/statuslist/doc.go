// Package statuslist implements client-side support for the IETF OAuth
// Token Status List specification, draft-ietf-oauth-status-list-15
// (https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/15/).
//
// The package fetches Status List Tokens advertised by SD-JWT VCs via the
// `status.status_list` claim, verifies their signatures (x5c or kid+did
// resolution), decodes the zlib-compressed bit array, and returns the
// status value at a given index. Callers use the single Checker.Check
// verb to obtain a typed Status value for a given Reference; partial
// fetch/decode/verify is intentionally not exposed.
//
// Status List Token verification reuses the same x5c-or-kid+DID
// dispatcher as SD-JWT VC verification via eudi_jwt.JwtKeyProvider,
// configured with the `statuslist+jwt` typ value mandated by the spec.
//
// v1 supports JWT Status List Tokens only (`application/statuslist+jwt`);
// CWT (`application/statuslist+cwt`) is intentionally out of scope.
package statuslist
