package mdoc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// TAG-24 HELPERS + CRYPTO UTILITIES
// ============================================================

// mdocDecMode is the decoder for every CBOR structure this package reads from
// outside the process. Nothing here should reach cbor.Unmarshal directly.
//
// ISO/IEC 18013-5 8.1 departs from fxamacker's defaults in one way that matters:
// "maps (major type 5) shall not have multiple entries with the same key". The
// library default is DupMapKeyQuiet, which silently keeps whichever entry came
// last. That is not merely untidy — every structure here is either covered by a
// signature or used to check one, so two parties can decode the same bytes to
// different documents while both believe they parsed correctly. An MSO carrying
// two docType entries, or two digests under one digestID, is exactly the shape
// of a parser-differential attack. Rejecting is the only reading that makes the
// decode deterministic.
//
// The clause's companion rule about definite lengths is deliberately not
// enforced; see indefLengthMode.
var mdocDecMode = mustDecMode(cbor.DecOptions{
	DupMapKey:   cbor.DupMapKeyEnforcedAPF,
	IndefLength: indefLengthMode,
})

// indefLengthMode is the one setting in mdocDecMode left lenient.
//
// 8.1's "indefinite-length items shall be made into definite-length items" is
// written as a rule for producers; whether a reader should also refuse an
// indefinite-length item it can decode perfectly well is a strictness judgement
// rather than a requirement the clause places on verification. Flipping this to
// cbor.IndefLengthForbidden completes 8.1 on the receiving side and is the
// intended end state.
//
// It is held back for one reason: it is the only change in this decoder that
// could reject a credential some non-Go issuer emits today, and the staging
// issuer is under active investigation for an unrelated certificate defect. A
// new decode failure appearing there now would be attributed to the wrong
// cause. Flip it once staging is settled — the constant exists so that is a
// one-line change with a test run behind it.
const indefLengthMode = cbor.IndefLengthAllowed

// mustDecMode panics on options this package itself wrote, which can only be
// wrong at build time.
func mustDecMode(opts cbor.DecOptions) cbor.DecMode {
	mode, err := opts.DecMode()
	if err != nil {
		panic(fmt.Sprintf("mdoc: invalid CBOR decoder options: %v", err))
	}
	return mode
}

// Unmarshal decodes CBOR under the rules ISO/IEC 18013-5 8.1 places on mdoc
// structures rather than fxamacker's defaults.
//
// It is exported for the callers that decode an mdoc envelope themselves before
// handing it here — the OpenID4VCI credential parser reading a Document,
// DeviceResponse or IssuerSigned off the wire, and the DCQL handler reading a
// stored credential back. Those decodes cover the outermost map, which the
// in-package decodes never see, so using cbor.Unmarshal there would leave the
// envelope on the library defaults while everything inside it was strict.
func Unmarshal(data []byte, v any) error {
	return mdocDecMode.Unmarshal(data, v)
}

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
// that must use tdateEncMode's RFC3339 tag-0 encoding rather than the
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
	if err := mdocDecMode.Unmarshal(data, &rawTag); err != nil {
		return zero, fmt.Errorf("unwrap tag24: %w", err)
	}
	var innerBytes []byte
	if err := mdocDecMode.Unmarshal(rawTag.Content, &innerBytes); err != nil {
		return zero, fmt.Errorf("unwrap tag24 inner bytes: %w", err)
	}
	var result T
	if err := mdocDecMode.Unmarshal(innerBytes, &result); err != nil {
		return zero, fmt.Errorf("decode tag24 content: %w", err)
	}
	return result, nil
}

// hashTag24Item computes SHA-256(Tag24(CBOR(item)))
// This is the exact digest formula specified by ISO 18013-5
// The resulting hash is what goes into MSO.ValueDigests
//
// SHA-256 is hardcoded because this is the issuer side, and 9.1.2.5 lets an
// issuer pick any one of the three. The verifier must handle all three, which is
// what digestFuncFor is for.
func hashTag24Item(item IssuerSignedItem) ([]byte, error) {
	wrapped, err := tag24Wrap(item)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(wrapped)
	return hash[:], nil
}

// digestFuncFor resolves the MSO's declared digestAlgorithm to the function that
// computes it, per ISO/IEC 18013-5 9.1.2.5: "The issuing authority infrastructure
// shall use one of the following digest algorithms: SHA-256, SHA-384 or SHA-512",
// identified by the exact strings in Table 21.
//
// The verifier used to assume SHA-256 and never read the field. A conformant
// SHA-384 credential then failed as "digest mismatch for age_over_18", which
// points at the element rather than at the algorithm and sends whoever reads it
// looking for a tampered value that does not exist.
//
// An identifier outside the table is refused rather than defaulted: the MSO is
// signed, so the algorithm it names is the issuer's statement of how these
// digests were computed, and guessing when that statement is unrecognised means
// verifying something other than what was attested.
func digestFuncFor(algorithm string) (func([]byte) []byte, error) {
	switch algorithm {
	case "SHA-256":
		return func(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }, nil
	case "SHA-384":
		return func(b []byte) []byte { sum := sha512.Sum384(b); return sum[:] }, nil
	case "SHA-512":
		return func(b []byte) []byte { sum := sha512.Sum512(b); return sum[:] }, nil
	default:
		return nil, fmt.Errorf(
			"MSO declares digestAlgorithm %q, which is not one of the three ISO/IEC 18013-5 Table 21 permits (SHA-256, SHA-384, SHA-512)",
			algorithm)
	}
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
// The struct tags carry ",keyasint" so fxamacker/cbor encodes the labels as
// actual CBOR integer map keys (major type 0/1) rather than text-string keys
// like "1" / "-1". Dropping it produces a non-conformant COSE_Key that still
// round-trips against this codebase — decoding would use the same wrong
// mapping — while failing against every spec-compliant verifier. Worse, the
// encoding is covered by the signed MSO digest, so an mdoc issued with the
// wrong one cannot be repaired after the fact.
//
//	1  = kty  (key type: 2 = EC2)
//	-1 = crv  (curve:    see coseCurves)
//	-2 = x    (x coordinate, the curve's field size in bytes)
//	-3 = y    (y coordinate, the curve's field size in bytes)
type COSEKey struct {
	Kty int64  `cbor:"1,keyasint"`
	Crv int64  `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// coseKeyFromECDSA converts an ECDSA public key into our COSEKey type.
// Factored out so both the issuer (embedding) and verifier (deviceAuth
// check) build the exact same structure from the exact same logic.
// coseCurves maps the COSE EC2 curve identifiers from the IANA COSE Elliptic
// Curves registry to their crypto/elliptic curve.
//
// These are three of the eleven curves ISO/IEC 18013-5 Table 22 lists for cipher
// suite 1, and the three the Go standard library provides. What is missing, and
// why:
//
//   - Ed25519 (6) and Ed448 (7) are OKP keys, not EC2, and an ed25519.PublicKey
//     is not an *ecdsa.PublicKey — supporting them means widening
//     VerificationResult.DeviceKey and the device-key binder to crypto.PublicKey,
//     which is a change of shape rather than a table entry.
//   - brainpoolP256r1/320r1/384r1/512r1 (256-259) are not in the Go standard
//     library at all. Table 22's "support for all curves is mandatory for an mdoc
//     reader" is unqualified, so strict conformance needs a third-party curve
//     implementation in the verification path — a decision about dependencies,
//     not an oversight.
//   - X25519 (4) and X448 (5) are ECDH-only in Table 22, so they cannot appear
//     as a device authentication key.
//
// An unlisted curve is refused by name rather than silently mishandled; see
// ecdsaPublicKeyFromCOSE.
var coseCurves = map[int64]elliptic.Curve{
	1: elliptic.P256(),
	2: elliptic.P384(),
	3: elliptic.P521(),
}

// coseCurveIDFor is coseCurves reversed.
func coseCurveIDFor(curve elliptic.Curve) (int64, bool) {
	for id, c := range coseCurves {
		if c == curve {
			return id, true
		}
	}
	return 0, false
}

// coseKeyFromECDSA converts an ECDSA public key into our COSEKey type.
// Factored out so both the issuer (embedding) and verifier (deviceAuth
// check) build the exact same structure from the exact same logic.
func coseKeyFromECDSA(pub *ecdsa.PublicKey) (COSEKey, error) {
	// The curve decides both the label and the coordinate width, so it has to be
	// resolved before the coordinates are sliced rather than assumed afterwards.
	// This slicing used to assume P-256's 65-byte uncompressed encoding: handed a
	// P-384 key it produced a COSEKey labelled crv=1 whose X was the first 32 of
	// 48 X-bytes and whose Y was the remaining 64 — a silently corrupt key,
	// stamped with the wrong curve, embedded in an MSO and signed, indistinguish-
	// able from a genuine P-256 key until something tried to rebuild it.
	crv, ok := coseCurveIDFor(pub.Curve)
	if !ok {
		return COSEKey{}, fmt.Errorf(
			"key is on %s, which has no COSE EC2 curve identifier this package supports (P-256, P-384, P-521)",
			pub.Curve.Params().Name)
	}
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return COSEKey{}, fmt.Errorf("convert pub key: %w", err)
	}
	// 04 || X || Y, each coordinate the curve's field size.
	pubBytes := ecdhPub.Bytes()
	byteLen := coordinateLen(pub.Curve)
	return COSEKey{
		Kty: 2, // EC2
		Crv: crv,
		X:   pubBytes[1 : 1+byteLen],
		Y:   pubBytes[1+byteLen:],
	}, nil
}

// coordinateLen is the byte width of one coordinate on curve — 32 for P-256, 48
// for P-384, 66 for P-521 (521 bits rounds up to 66 bytes, not 65).
func coordinateLen(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

// ecdsaPublicKeyFromCOSE reconstructs a *ecdsa.PublicKey from a COSEKey.
// Used by the verifier to check deviceAuth against the deviceKey embedded
// in the (already-verified) MSO.
func ecdsaPublicKeyFromCOSE(k COSEKey) (*ecdsa.PublicKey, error) {
	if k.Kty != 2 {
		// kty 1 is OKP, which is how Ed25519 and Ed448 device keys arrive. Naming
		// that explicitly, because "unsupported kty: 1" reads like a malformed key
		// when it is in fact a well-formed key on a curve this package cannot yet
		// return as an *ecdsa.PublicKey.
		if k.Kty == 1 {
			return nil, fmt.Errorf(
				"device key has kty OKP (1), i.e. an Edwards curve: ISO/IEC 18013-5 permits it, but this package returns EC2 keys only")
		}
		return nil, fmt.Errorf("unsupported kty: %d (want EC2/2)", k.Kty)
	}
	curve, ok := coseCurves[k.Crv]
	if !ok {
		return nil, fmt.Errorf(
			"unsupported COSE curve identifier %d: this package supports P-256 (1), P-384 (2) and P-521 (3)", k.Crv)
	}
	return ecdsaPublicKeyFromCoordinates(curve, new(big.Int).SetBytes(k.X), new(big.Int).SetBytes(k.Y))
}

// ecdsaPublicKeyFromCoordinates builds a *ecdsa.PublicKey from raw P-256
// x/y coordinates, validating the point actually lies on the curve. It
// rebuilds a public key from an untrusted wire encoding, so that check is
// load-bearing. Called only by ecdsaPublicKeyFromCOSE, above.
//
// elliptic.Curve.IsOnCurve is deprecated ("low-level unsafe API"); the Go
// team's own recommendation in that deprecation notice is to validate via
// crypto/ecdh's NewPublicKey instead, which performs the on-curve check
// internally as part of parsing the uncompressed point encoding
// (0x04 || X || Y). ecdsa.Verify itself still needs a *ecdsa.PublicKey,
// not a *ecdh.PublicKey, so this only uses ecdh for the validation step
// and returns the ecdsa type the rest of this package works with.
func ecdsaPublicKeyFromCoordinates(curve elliptic.Curve, x, y *big.Int) (*ecdsa.PublicKey, error) {
	name := curve.Params().Name
	// FillBytes panics rather than erroring when the value does not fit the
	// destination buffer, so an over-wide coordinate has to be rejected before
	// it gets there. These coordinates come off the wire, and the callers'
	// contract is to fail the key rather than the process.
	if x.BitLen() > curve.Params().BitSize || y.BitLen() > curve.Params().BitSize {
		return nil, fmt.Errorf("coordinate wider than %s: x=%d bits, y=%d bits", name, x.BitLen(), y.BitLen())
	}
	byteLen := coordinateLen(curve)
	uncompressed := make([]byte, 1+2*byteLen)
	uncompressed[0] = 4
	x.FillBytes(uncompressed[1 : 1+byteLen])
	y.FillBytes(uncompressed[1+byteLen:])

	ecdhCurve, ok := ecdhCurveFor(curve)
	if !ok {
		return nil, fmt.Errorf("no crypto/ecdh curve for %s", name)
	}
	if _, err := ecdhCurve.NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("invalid %s point: %w", name, err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// ecdhCurveFor pairs a crypto/elliptic curve with its crypto/ecdh counterpart,
// which is the one that performs the on-curve check during point parsing.
func ecdhCurveFor(curve elliptic.Curve) (ecdh.Curve, bool) {
	switch curve {
	case elliptic.P256():
		return ecdh.P256(), true
	case elliptic.P384():
		return ecdh.P384(), true
	case elliptic.P521():
		return ecdh.P521(), true
	}
	return nil, false
}

// tdateEncMode encodes time.Time as CBOR tag 0, an RFC 3339 date-time string.
//
// This is general ISO/IEC 18013-5 rather than a profile rule, which is why it is
// no longer named for the AV Blueprint: ValidityInfo's fields are typed `tdate`
// in the 9.1.2.4 CDDL, and 7.2.1 requires that "a tdate data item shall contain
// a date-time string as specified in RFC 3339". The AV Blueprint's worked
// example (Annex A §A.11) shows the same thing —
// `"signed": 0("2025-06-20T08:45:29Z")` — because it inherits the rule, not
// because it imposes one.
//
// The default cbor.Marshal instead produces a bare Unix epoch integer with no
// tag, which is internally self-consistent for this program's own
// issuer/verifier round trip but is not what any conformant verifier would
// expect to parse.
var tdateEncMode, _ = cbor.EncOptions{
	Time:    cbor.TimeRFC3339,
	TimeTag: cbor.EncTagRequired,
}.EncMode()
