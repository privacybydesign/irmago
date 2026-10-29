// Package bitstringstatus implements holder-side checking of W3C Bitstring
// Status List v1.0 (https://www.w3.org/TR/vc-bitstring-status-list/), the
// status mechanism used by the JSON-LD / VCDM 2.0 world.
//
// It is a deliberate sibling of eudi/credentials/statuslist (the IETF OAuth
// Token Status List): the two specs do not interoperate. Bitstring Status List
// GZIP-compresses its bitstring (Token Status List uses zlib), packs bits
// MSB-first (Token Status List packs LSB-first), Multibase-encodes the result
// (base64url, "u" prefix), and wraps it in a full Verifiable Credential rather
// than a bare JWT. This package copies statuslist's Checker/Cache pattern but
// shares no wire-format code with it. Per research (#673) the pragmatic scope
// is a JWT-secured BitstringStatusListCredential, since irmago has no JSON-LD /
// Data-Integrity verification.
package bitstringstatus

import "errors"

// Sentinel errors. Callers should discriminate with errors.Is.
var (
	// ErrEntry covers a malformed BitstringStatusListEntry on a credential's
	// credentialStatus property (missing/!parseable statusPurpose,
	// statusListIndex, statusListCredential or statusSize).
	ErrEntry = errors.New("bitstring status: malformed credentialStatus entry")

	// ErrDecode covers a credentialSubject.encodedList that is not valid
	// Multibase base64url + GZIP, or a bitstring length violation.
	ErrDecode = errors.New("bitstring status: encodedList could not be decoded")

	// ErrIndexBounds is returned when a statusListIndex falls outside the
	// expanded bitstring.
	ErrIndexBounds = errors.New("bitstring status: statusListIndex out of bounds")

	// ErrFetch wraps transport errors, non-2xx responses, and content-type /
	// body-size violations while dereferencing a statusListCredential.
	ErrFetch = errors.New("bitstring status: statusListCredential fetch failed")

	// ErrUnauthorized covers integrity failures on a fetched
	// BitstringStatusListCredential: bad proof, wrong type, or a statusPurpose
	// that does not match the entry.
	ErrUnauthorized = errors.New("bitstring status: statusListCredential is invalid")
)
