package statuslist

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

// ClockSkewSeconds matches sdjwtvc.ClockSkewInSeconds. Kept local to
// avoid an import cycle between statuslist and sdjwtvc.
const ClockSkewSeconds = 180

// statusListClaim mirrors the inner `status_list` object of a Status
// List Token payload (draft-ietf-oauth-status-list-15 §6).
type statusListClaim struct {
	Bits int    `json:"bits"`
	Lst  string `json:"lst"`
	// AggregationURI is intentionally not parsed — v1 ignores aggregation.
}

// statusListPayload mirrors the verified Status List Token payload
// (draft-ietf-oauth-status-list-15 §6). Only fields v1 acts on are
// captured; unknown fields are tolerated.
type statusListPayload struct {
	Issuer     string          `json:"iss"`
	Subject    string          `json:"sub"`
	IssuedAt   int64           `json:"iat"`
	Expiry     int64           `json:"exp,omitempty"`
	NotBefore  int64           `json:"nbf,omitempty"`
	TTLSeconds int64           `json:"ttl,omitempty"`
	StatusList statusListClaim `json:"status_list"`
}

// verifiedStatusList holds a Status List Token whose signature, typ,
// iss, and time bounds have been validated. The lst field is still
// base64url-encoded and zlib-compressed; the decoder consumes it.
type verifiedStatusList struct {
	payload  statusListPayload
	rawJwt   []byte // original signed JWT bytes — kept for caching
	verifyAt time.Time
}

// ttlFromPayload returns the JWT-side TTL signal: the `ttl` claim if
// present, otherwise the remaining `exp - now`, otherwise the package
// default (post-clamp).
func (v *verifiedStatusList) ttlFromPayload() time.Duration {
	if v.payload.TTLSeconds > 0 {
		return time.Duration(v.payload.TTLSeconds) * time.Second
	}
	if v.payload.Expiry > 0 {
		remaining := time.Until(time.Unix(v.payload.Expiry, 0))
		if remaining > 0 {
			return remaining
		}
	}
	return TTLDefault
}

// verifyStatusListToken parses, signature-verifies, and time-checks a
// Status List Token. expectedIss MUST equal the iss claim — this is
// the iss(StatusListToken) == iss(credential) binding required by the
// trust model (see docs/plans/sd-jwt-status-lists.md, Q6).
func verifyStatusListToken(rawJwt []byte, ctx VerificationContext, expectedIss string, now time.Time) (*verifiedStatusList, error) {
	keyProvider := eudi_jwt.NewJwtKeyProvider([]string{StatusListTokenTyp}, ctx.AllowInsecureDidWeb)

	clock := ctx.Clock
	if clock == nil {
		clock = staticClock{t: now}
	}

	token, err := jwt.Parse(rawJwt,
		jwt.WithKeyProvider(keyProvider),
		jwt.WithClock(clock),
		jwt.WithAcceptableSkew(ClockSkewSeconds*time.Second),
		jwt.WithVerify(true),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: parse/verify: %v", ErrUnauthorized, err)
	}

	// If the dispatcher chose x5c, validate the chain against the
	// configured trust anchors. The kid path delegates to did:web/
	// did:jwk resolution, which carries its own trust assumptions
	// (HTTPS for did:web, key-binding-by-construction for did:jwk).
	if x509KeyProvider, ok := keyProvider.InnerKeyProvider.(*eudi_jwt.X509KeyProvider); ok {
		cert := x509KeyProvider.GetCert()
		if ctx.X509Context == nil {
			return nil, fmt.Errorf("%w: x5c chain present but no X509VerificationContext configured", ErrUnauthorized)
		}
		if err := eudi_jwt.VerifyCertificate(ctx.X509Context, cert, nil); err != nil {
			return nil, fmt.Errorf("%w: certificate validation: %v", ErrUnauthorized, err)
		}
	}

	iss, ok := token.Issuer()
	if !ok || iss == "" {
		return nil, fmt.Errorf("%w: missing iss claim", ErrUnauthorized)
	}
	if iss != expectedIss {
		return nil, fmt.Errorf("%w: iss mismatch: got %q, expected %q", ErrUnauthorized, iss, expectedIss)
	}

	var payload statusListPayload
	if err := payloadFromToken(token, &payload); err != nil {
		return nil, fmt.Errorf("%w: invalid payload: %v", ErrUnauthorized, err)
	}

	// Token has a status_list claim; bits must be set to one of the
	// spec-defined values before the decoder is willing to consume it.
	if !validBitSize(payload.StatusList.Bits) {
		return nil, fmt.Errorf("%w: invalid status_list.bits: %d", ErrUnauthorized, payload.StatusList.Bits)
	}
	if payload.StatusList.Lst == "" {
		return nil, fmt.Errorf("%w: empty status_list.lst", ErrUnauthorized)
	}

	return &verifiedStatusList{payload: payload, rawJwt: rawJwt, verifyAt: now}, nil
}

// validBitSize matches RFC §6.1 — `bits` must be 1, 2, 4, or 8.
func validBitSize(b int) bool {
	return b == 1 || b == 2 || b == 4 || b == 8
}

// staticClock is the default clock used when VerificationContext.Clock
// is nil. It is **only** used inside verifyStatusListToken; the
// Checker calls verify with a concrete "now" so cache decisions are
// monotonic with verification.
type staticClock struct{ t time.Time }

func (s staticClock) Now() time.Time { return s.t }
