package statuslist

import (
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"

	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

// statusListCborDecMode is the decoder for every CBOR structure this file
// reads from outside the process (a CWT Status List Token's payload). It
// forbids a CBOR map from carrying the same key twice — the library default
// silently keeps the last one — for the same reason mdoc.mdocDecMode does:
// a Status List Token is a signed, security-relevant structure, and two
// parties decoding the same bytes to different claim sets is exactly the
// shape of a parser-differential attack.
var statusListCborDecMode = func() cbor.DecMode {
	mode, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("statuslist: invalid CBOR decoder options: %v", err))
	}
	return mode
}()

// cwtSignatureAlgorithms are the COSE algorithms this package accepts for a
// CWT Status List Token's signature. Duplicated from
// mdoc.mdocSignatureAlgorithms (the same ISO/IEC 18013-5 9.1.2.4 / 9.1.3.6
// allow-list) rather than shared: mdoc imports this package for the shared
// Reference/StatusClaim types, so this package cannot import mdoc back
// without a cycle.
var cwtSignatureAlgorithms = []cose.Algorithm{
	cose.AlgorithmES256,
	cose.AlgorithmES384,
	cose.AlgorithmES512,
	cose.AlgorithmEdDSA,
}

// coseVerifierFor builds a verifier for the algorithm the message's own
// protected header declares (covered by the signature, so it cannot be
// substituted), restricted to cwtSignatureAlgorithms.
func coseVerifierFor(msg *cose.Sign1Message, key any) (cose.Verifier, error) {
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return nil, fmt.Errorf("no usable alg in protected header: %w", err)
	}
	supported := slices.Contains(cwtSignatureAlgorithms, alg)
	if !supported {
		return nil, fmt.Errorf("signed with %v, which is not one of the algorithms this package accepts (ES256, ES384, ES512, EdDSA)", alg)
	}
	verifier, err := cose.NewVerifier(alg, key)
	if err != nil {
		return nil, fmt.Errorf("declares %v, which does not match its %T signing key: %w", alg, key, err)
	}
	return verifier, nil
}

// decodeCoseSign1 decodes either COSE_Sign1 serialization — tag-18
// (COSE_Sign1_Tagged) or the bare four-element array — into the same
// message type. Duplicated from mdoc.decodeCoseSign1 for the same reason as
// cwtSignatureAlgorithms: this package cannot import mdoc.
func decodeCoseSign1(data []byte) (*cose.Sign1Message, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty COSE_Sign1")
	}
	if data[0] == 0xd2 { // tag 18: COSE_Sign1_Tagged
		var tagged cose.Sign1Message
		if err := tagged.UnmarshalCBOR(data); err != nil {
			return nil, err
		}
		return &tagged, nil
	}
	var untagged cose.UntaggedSign1Message
	if err := untagged.UnmarshalCBOR(data); err != nil {
		return nil, err
	}
	msg := cose.Sign1Message(untagged)
	return &msg, nil
}

// looksLikeCWT reports whether raw is (very likely) a CBOR-encoded
// COSE_Sign1 rather than a JWT. A JWT is ASCII — base64url characters and
// '.' separators, all below 0x80 — so any leading byte at or above 0x80 can
// only be a CBOR major-type/tag byte: 0xd2 (tag 18, COSE_Sign1_Tagged) or
// 0x84 (a 4-element array, the untagged COSE_Sign1 decodeCoseSign1 also
// accepts). Used to dispatch verification by encoding without threading the
// HTTP response's Content-Type through the cache, which stores only raw
// bytes (see Cache) — so a cache-read has no Content-Type to consult.
func looksLikeCWT(raw []byte) bool {
	return len(raw) > 0 && raw[0] >= 0x80
}

// certFromX5ChainLeaf extracts the leaf certificate from a COSE_Sign1's
// x5chain (unprotected header 33, RFC 9360) — only the leaf, mirroring the
// JWT path's eudi_jwt.X509KeyProvider convention for x5c: trust comes from
// ctx.X509Context's own configured intermediates, not from whatever chain
// the token happened to carry alongside itself.
func certFromX5ChainLeaf(msg *cose.Sign1Message) (*x509.Certificate, error) {
	raw, ok := msg.Headers.Unprotected[cose.HeaderLabelX5Chain]
	if !ok {
		return nil, fmt.Errorf("no x5chain in unprotected header")
	}

	var der []byte
	switch v := raw.(type) {
	case []byte:
		der = v
	case []any:
		if len(v) == 0 {
			return nil, fmt.Errorf("x5chain is empty")
		}
		b, ok := v[0].([]byte)
		if !ok {
			return nil, fmt.Errorf("x5chain[0] has wrong type: %T", v[0])
		}
		der = b
	default:
		return nil, fmt.Errorf("x5chain has wrong type: %T", raw)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse x5chain[0]: %w", err)
	}
	return cert, nil
}

// cwtStatusListClaim mirrors the CBOR `status_list` map value
// (draft-ietf-oauth-status-list-15 §4.3): text-string keys "bits"/"lst",
// used identically whether the enclosing Status List Token is JWT- or
// CWT-encoded. Kept separate from statusListClaim (the JSON/JWT shape)
// because Lst differs in Go type: a CBOR byte string decodes straight into
// []byte, where the JSON encoding's `lst` is a base64url string that needs
// an extra decode step (see statusListClaim / decodeBits).
type cwtStatusListClaim struct {
	Bits int    `cbor:"bits"`
	Lst  []byte `cbor:"lst"`
}

// cwtStatusListPayload mirrors the CWT Claims Set of a Status List Token
// (draft-ietf-oauth-status-list-15 §5.2). Claim keys are the integers the
// spec registers: 2 (sub) and 6 (iat) as generally defined by RFC 8392, 4
// (exp) likewise, 65533 (status_list) and 65534 (ttl) newly registered by
// this spec. Only the fields v1 acts on are captured; unknown claims are
// tolerated.
type cwtStatusListPayload struct {
	Subject    string             `cbor:"2,keyasint"`
	IssuedAt   int64              `cbor:"6,keyasint"`
	Expiry     int64              `cbor:"4,keyasint,omitempty"`
	TTLSeconds int64              `cbor:"65534,keyasint,omitempty"`
	StatusList cwtStatusListClaim `cbor:"65533,keyasint"`
}

// verifiedStatusListCWT holds a CWT Status List Token whose signature, type
// header, sub, and time bounds have been validated. StatusList.Lst is still
// zlib-compressed; statusAt consumes it.
type verifiedStatusListCWT struct {
	payload cwtStatusListPayload
	raw     []byte // original signed CWT bytes — kept for caching
}

var _ verifiedStatusListToken = (*verifiedStatusListCWT)(nil)

func (v *verifiedStatusListCWT) ttlSignal() (time.Duration, bool) {
	if v.payload.TTLSeconds > 0 {
		return time.Duration(v.payload.TTLSeconds) * time.Second, true
	}
	if v.payload.Expiry > 0 {
		if remaining := time.Until(time.Unix(v.payload.Expiry, 0)); remaining > 0 {
			return remaining, true
		}
	}
	return 0, false
}

func (v *verifiedStatusListCWT) statusAt(ref Reference, maxBytes int64) (Status, error) {
	bits, err := decodeBitsRaw(v.payload.StatusList.Lst, maxBytes)
	if err != nil {
		return StatusUnknown, err
	}
	return statusAtIndex(bits, v.payload.StatusList.Bits, ref.Index)
}

// verifyStatusList parses, signature-verifies, and time-checks a Status List
// Token of either encoding, dispatching on the fetched bytes (see
// looksLikeCWT). This is the single entry point Checker uses; the two
// concrete verify functions (this file's verifyStatusListTokenCWT and
// verifier.go's verifyStatusListToken) stay independently testable under
// their existing names.
func verifyStatusList(raw []byte, ctx VerificationContext, expectedURI string, now time.Time) (verifiedStatusListToken, error) {
	if looksLikeCWT(raw) {
		return verifyStatusListTokenCWT(raw, ctx, expectedURI, now)
	}
	return verifyStatusListToken(raw, ctx, expectedURI, now)
}

// verifyStatusListTokenCWT parses, signature-verifies, and time-checks a CWT
// Status List Token (draft-ietf-oauth-status-list-15 §5.2), the encoding
// COSE/CBOR-based Referenced Tokens — including an ISO mdoc's MSO, §6.3.2 —
// use.
//
// Unlike the JWT path (verifyStatusListToken), this only resolves the
// signing key via x5chain — mirroring how this codebase's own mdoc issuance
// signs (x5chain-only, no kid). The JWT path's kid+did:web/did:jwk
// resolution has no established equivalent in ecosystems that use CWT/COSE,
// so it is out of scope here rather than half-implemented.
func verifyStatusListTokenCWT(raw []byte, ctx VerificationContext, expectedURI string, now time.Time) (*verifiedStatusListCWT, error) {
	msg, err := decodeCoseSign1(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: decode cose: %v", ErrUnauthorized, err)
	}

	// The protected header's "type" (label 16, RFC 9596) MUST equal
	// application/statuslist+cwt (§5.2) — the CWT analogue of the JWT
	// path's 'typ' check, and covered by the signature the same way.
	typVal, ok := msg.Headers.Protected[cose.HeaderLabelType]
	if !ok {
		return nil, fmt.Errorf("%w: missing protected header 16 (type)", ErrUnauthorized)
	}
	typ, ok := typVal.(string)
	if !ok || typ != StatusListTokenCWTContentType {
		return nil, fmt.Errorf("%w: protected header 16 (type) is %v, want %q", ErrUnauthorized, typVal, StatusListTokenCWTContentType)
	}

	if ctx.X509Context == nil {
		return nil, fmt.Errorf("%w: no X509VerificationContext configured", ErrUnauthorized)
	}
	cert, err := certFromX5ChainLeaf(msg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	if err := eudi_jwt.VerifyCertificate(ctx.X509Context, cert, nil); err != nil {
		return nil, fmt.Errorf("%w: certificate validation: %v", ErrUnauthorized, err)
	}

	verifier, err := coseVerifierFor(msg, cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("%w: signature invalid: %v", ErrUnauthorized, err)
	}

	var payload cwtStatusListPayload
	if err := statusListCborDecMode.Unmarshal(msg.Payload, &payload); err != nil {
		return nil, fmt.Errorf("%w: invalid payload: %v", ErrUnauthorized, err)
	}

	// sub MUST equal the URI the token was fetched from — the same
	// anti-substitution binding the JWT path enforces (§5.2, validation
	// step §8.3).
	if payload.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub claim", ErrUnauthorized)
	}
	if payload.Subject != expectedURI {
		return nil, fmt.Errorf("%w: sub %q does not match status list uri %q", ErrUnauthorized, payload.Subject, expectedURI)
	}

	// iat is REQUIRED (§5.2). Unlike the JWT path, nothing here validates
	// time claims for us (jwx does that internally for JWTs), so iat/exp
	// are checked by hand against the same clock and skew window.
	if payload.IssuedAt == 0 {
		return nil, fmt.Errorf("%w: missing iat claim", ErrUnauthorized)
	}
	clock := ctx.Clock
	if clock == nil {
		clock = staticClock{t: now}
	}
	nowT := clock.Now()
	if payload.IssuedAt > nowT.Add(ClockSkewSeconds*time.Second).Unix() {
		return nil, fmt.Errorf("%w: iat %d is after current time (+skew)", ErrUnauthorized, payload.IssuedAt)
	}
	if payload.Expiry > 0 && payload.Expiry < nowT.Add(-ClockSkewSeconds*time.Second).Unix() {
		return nil, fmt.Errorf("%w: token expired at %d", ErrUnauthorized, payload.Expiry)
	}

	if !validBitSize(payload.StatusList.Bits) {
		return nil, fmt.Errorf("%w: invalid status_list.bits: %d", ErrUnauthorized, payload.StatusList.Bits)
	}
	if len(payload.StatusList.Lst) == 0 {
		return nil, fmt.Errorf("%w: empty status_list.lst", ErrUnauthorized)
	}

	return &verifiedStatusListCWT{payload: payload, raw: raw}, nil
}
