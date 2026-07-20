package mdoc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// TAG-24 HELPERS + CRYPTO UTILITIES
// ============================================================

// tag24Wrap CBOR-encodes v, then wraps the result in a Tag-24 (embedded CBOR) container
// Tag 24 is IANA-registered to mean "this byte string contains a CBOR-encoded data item"
// This "freezes" the bytes so they can be hashed consistently
func tag24Wrap(v any) ([]byte, error) {
	innerBytes, err := cbor.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("tag24 inner encode: %w", err)
	}
	return tag24WrapBytes(innerBytes)
}

// tag24WrapWithMode is like tag24Wrap but uses a custom EncMode for the
// inner encode. Needed for values containing time.Time fields (e.g. MSO)
// that must use avTimeEncMode's RFC3339 tag-0 encoding rather than the
// default bare-epoch-integer encoding — plain tag24Wrap would silently
// undo that fix by re-encoding with cbor.Marshal's default mode instead.
func tag24WrapWithMode(v any, mode cbor.EncMode) ([]byte, error) {
	innerBytes, err := mode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("tag24 inner encode: %w", err)
	}
	return tag24WrapBytes(innerBytes)
}

// tag24WrapBytes wraps already-CBOR-encoded bytes in a Tag-24 container.
func tag24WrapBytes(innerBytes []byte) ([]byte, error) {
	tagged := cbor.RawTag{
		Number:  24, // IANA registered tag: embedded CBOR
		Content: cbor.RawMessage(mustMarshal(innerBytes)),
	}
	return cbor.Marshal(tagged)
}

// tag24Unwrap decodes Tag-24 wrapped CBOR bytes into T — the inverse of
// tag24Wrap/tag24WrapWithMode. Tag 24 means "this byte string contains a
// CBOR-encoded data item", so unwrapping takes two steps: decode the tag
// to get the embedded byte string, then decode THAT into T.
func tag24Unwrap[T any](data []byte) (T, error) {
	var zero T
	var rawTag cbor.RawTag
	if err := cbor.Unmarshal(data, &rawTag); err != nil {
		return zero, fmt.Errorf("unwrap tag24: %w", err)
	}
	var innerBytes []byte
	if err := cbor.Unmarshal(rawTag.Content, &innerBytes); err != nil {
		return zero, fmt.Errorf("unwrap tag24 inner bytes: %w", err)
	}
	var result T
	if err := cbor.Unmarshal(innerBytes, &result); err != nil {
		return zero, fmt.Errorf("decode tag24 content: %w", err)
	}
	return result, nil
}

// hashTag24Item computes SHA-256(Tag24(CBOR(item)))
// This is the exact digest formula specified by ISO 18013-5
// The resulting hash is what goes into MSO.ValueDigests
func hashTag24Item(item IssuerSignedItem) ([]byte, error) {
	wrapped, err := tag24Wrap(item)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(wrapped)
	return hash[:], nil
}

// mustMarshal CBOR-encodes v and panics on error
// Used only for values that are guaranteed to be encodable (e.g. raw []byte)
func mustMarshal(v any) []byte {
	b, err := cbor.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// COSEKey is the CBOR-encoded public key format per RFC 9053 (COSE Key).
//
// FIX: struct tags now use ",keyasint" so fxamacker/cbor encodes these as
// actual CBOR integer map keys (major type 0/1), not text-string keys like
// "1" / "-1". Without keyasint, the previous version silently produced a
// non-conformant COSE_Key — it round-tripped fine against *this* codebase
// (since decoding used the same wrong mapping) but would fail against any
// spec-compliant verifier, and worse, the bad encoding gets baked into the
// signed MSO digest, so it can't be patched after issuance.
//
//	1  = kty  (key type:  2 = EC2)
//	-1 = crv  (curve:    1 = P-256)
//	-2 = x    (x coordinate, 32 bytes for P-256)
//	-3 = y    (y coordinate, 32 bytes for P-256)
type COSEKey struct {
	Kty int64  `cbor:"1,keyasint"`
	Crv int64  `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// coseKeyFromECDSA converts an ECDSA public key into our COSEKey type.
// Factored out so both the issuer (embedding) and verifier (deviceAuth
// check) build the exact same structure from the exact same logic.
func coseKeyFromECDSA(pub *ecdsa.PublicKey) (COSEKey, error) {
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return COSEKey{}, fmt.Errorf("convert pub key: %w", err)
	}
	pubBytes := ecdhPub.Bytes() // 65 bytes: 04 || X(32) || Y(32)
	return COSEKey{
		Kty: 2, // EC2
		Crv: 1, // P-256
		X:   pubBytes[1:33],
		Y:   pubBytes[33:],
	}, nil
}

// ecdsaPublicKeyFromCOSE reconstructs a *ecdsa.PublicKey from a COSEKey.
// Used by the verifier to check deviceAuth against the deviceKey embedded
// in the (already-verified) MSO.
func ecdsaPublicKeyFromCOSE(k COSEKey) (*ecdsa.PublicKey, error) {
	if k.Kty != 2 {
		return nil, fmt.Errorf("unsupported kty: %d (want EC2/2)", k.Kty)
	}
	if k.Crv != 1 {
		return nil, fmt.Errorf("unsupported crv: %d (want P-256/1)", k.Crv)
	}
	return ECDSAPublicKeyFromCoordinates(new(big.Int).SetBytes(k.X), new(big.Int).SetBytes(k.Y))
}

// ECDSAPublicKeyFromCoordinates builds a *ecdsa.PublicKey from raw P-256
// x/y coordinates, validating the point actually lies on the curve.
// Shared by ecdsaPublicKeyFromCOSE (crypto.go, this package) and
// openid4vci's proof-of-possession JWK reconstruction — both rebuild a
// public key from an untrusted wire encoding and need the same check.
// Exported specifically so the openid4vci subpackage can reuse it without
// duplicating the on-curve validation logic.
//
// elliptic.Curve.IsOnCurve is deprecated ("low-level unsafe API"); the Go
// team's own recommendation in that deprecation notice is to validate via
// crypto/ecdh's NewPublicKey instead, which performs the on-curve check
// internally as part of parsing the uncompressed point encoding
// (0x04 || X || Y). ecdsa.Verify itself still needs a *ecdsa.PublicKey,
// not a *ecdh.PublicKey, so this only uses ecdh for the validation step
// and returns the ecdsa type the rest of this package works with.
func ECDSAPublicKeyFromCoordinates(x, y *big.Int) (*ecdsa.PublicKey, error) {
	curve := elliptic.P256()
	byteLen := (curve.Params().BitSize + 7) / 8 // 32 for P-256
	uncompressed := make([]byte, 1+2*byteLen)
	uncompressed[0] = 4
	x.FillBytes(uncompressed[1 : 1+byteLen])
	y.FillBytes(uncompressed[1+byteLen:])

	if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("invalid P-256 point: %w", err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// avTimeEncMode encodes time.Time as CBOR tag 0 (RFC3339 date-time string),
// matching the exact encoding shown in the AV Blueprint spec's own worked
// example (Annex A §A.11): `"signed": 0("2025-06-20T08:45:29Z")`. The
// default cbor.Marshal instead produces a bare Unix epoch integer with no
// tag, which is internally self-consistent for this program's own
// issuer/verifier round trip but is not what a spec-conformant verifier
// receiving a real AV Blueprint credential would expect to parse.
var avTimeEncMode, _ = cbor.EncOptions{
	Time:    cbor.TimeRFC3339,
	TimeTag: cbor.EncTagRequired,
}.EncMode()
