package services

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
)

// Content identity of a stored credential: the hash a batch is stored under and
// deduplicated by. Two credentials are the same credential when they have the
// same type, the same issuer and the same attribute values.
//
// credentialHash is the one place the digest
// is computed; hashForSdJwtVc and hashGeneric are the two per-format ways of
// choosing what goes into it.

// hashGeneric hashes the claims directly, with no standard-claim stripping —
// used for formats (mso_mdoc) whose ResolvedClaims is already a bare
// namespace->element->value map with nothing resembling sdjwtvc.StandardClaims
// mixed in, unlike hashForSdJwtVc.
func hashGeneric(credType, issuerIdentifier string, resolvedClaimsBytes []byte) (string, error) {
	return credentialHash(credType, issuerIdentifier, resolvedClaimsBytes), nil
}

// hashForSdJwtVc computes the deterministic hash used for batch deduplication.
// Standard claims (iat, exp, nbf, iss, sub, vct, cnf, status, etc.) are stripped
// before hashing so that two issuances of the same credential with identical claims
// produce the same hash. The credential type and the issuer identifier are mixed in
// by credentialHash, so the same claims from a different issuer are a different
// credential. Note: this hash is intentionally different from
// irmaclient.CreateHashForSdJwtVc, which is used for IRMA-issued SD-JWTs.
//
// Stability: json.Marshal sorts map keys at every nesting level, so object key
// order in the input does not affect the hash. Array element order IS significant
// — ["A","B"] and ["B","A"] produce different hashes, which is the correct
// behaviour since array ordering is meaningful in SD-JWT claims.
func hashForSdJwtVc(credType, issuerIdentifier string, processedSdJwtPayloadBytes []byte) (string, error) {
	// Unmarshal into a map so we can strip standard claims before hashing.
	var payload map[string]any
	if err := json.Unmarshal(processedSdJwtPayloadBytes, &payload); err != nil {
		return "", fmt.Errorf("hashForSdJwtVc: failed to unmarshal payload: %w", err)
	}

	for key := range sdjwtvc.StandardClaims {
		delete(payload, key)
	}

	cleanedBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("hashForSdJwtVc: failed to marshal cleaned payload: %w", err)
	}

	return credentialHash(credType, issuerIdentifier, cleanedBytes), nil
}

// credentialHash is the one place a credential's deduplication hash is computed,
// for every format.
//
// The issuer is part of the identity on purpose. Two different issuers minting the
// same credential type with the same claims are two different credentials —
// "over 18, according to the Dutch state" and "over 18, according to a shop's own
// loyalty scheme" are not interchangeable, and a wallet that hashed them alike
// could hold only one of them, silently refusing or replacing the other. Because
// the hash is a unique index, that was not a display quirk: the storage layer
// could not represent both.
//
// Renewal still works, which is the property that constrains this: the issuer of
// a credential does not change when it is re-issued, so a renewal produces the
// same hash and is still recognised as the same credential.
//
// Length-prefixed rather than concatenated. Plain concatenation cannot tell field
// boundaries apart, so a type ending in the issuer's first characters would hash
// identically to a shorter type and a longer issuer — ("a.b", "cd") and ("a.bc",
// "d") were the same bytes. Nothing observed that, but a hash that decides
// credential identity should not have a preimage ambiguity in it at all.
func credentialHash(credType, issuerIdentifier string, claims []byte) string {
	digest := sha256.New()
	for _, field := range [][]byte{[]byte(credType), []byte(issuerIdentifier), claims} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		digest.Write(length[:])
		digest.Write(field)
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}
