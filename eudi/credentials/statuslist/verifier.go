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
	TTLSeconds int64           `json:"ttl,omitempty"`
	StatusList statusListClaim `json:"status_list"`
}

// verifiedStatusList holds a Status List Token whose signature, typ,
// iss, and time bounds have been validated. The lst field is still
// base64url-encoded and zlib-compressed; the decoder consumes it.
type verifiedStatusList struct {
	payload statusListPayload
	rawJwt  []byte // original signed JWT bytes — kept for caching
}

// payloadTTLSignal reports the caching lifetime advertised by the
// Status List Token itself — the `ttl` claim if present, otherwise the
// remaining `exp - now` — together with whether the token advertised
// one at all. draft-ietf-oauth-status-list-15 §8.2 requires the `ttl`
// and `exp` claims to take priority over HTTP caching headers, so the
// caller must distinguish "token said nothing" (fall back to the HTTP
// header) from "token advertised a lifetime".
func (v *verifiedStatusList) payloadTTLSignal() (time.Duration, bool) {
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

// verifyStatusListToken parses, signature-verifies, and time-checks a
// Status List Token.
//
// expectedURI MUST equal the sub claim — the spec's anti-substitution
// binding (§5.1, validation step §8.3): the fetched token's subject
// must be the very URI the credential pointed at. The spec leaves
// issuer alignment to the trust model (§11.3), so a delegated Status
// Issuer signing with its own key is accepted as long as the signature
// is trusted and sub matches.
func verifyStatusListToken(rawJwt []byte, ctx VerificationContext, expectedURI string, now time.Time) (*verifiedStatusList, error) {
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

	payload, err := payloadFromToken(token)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload: %v", ErrUnauthorized, err)
	}

	// sub MUST equal the URI the token was fetched from (§5.1,
	// validation step §8.3). This binds the fetched Status List Token
	// to the reference carried in the credential — without it a valid
	// token for a *different* list could be substituted.
	if payload.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub claim", ErrUnauthorized)
	}
	if payload.Subject != expectedURI {
		return nil, fmt.Errorf("%w: sub %q does not match status list uri %q", ErrUnauthorized, payload.Subject, expectedURI)
	}

	// iat is REQUIRED (§5.1). jwx validates it when present but does
	// not enforce presence, so reject a token that omits it.
	if payload.IssuedAt == 0 {
		return nil, fmt.Errorf("%w: missing iat claim", ErrUnauthorized)
	}

	// Token has a status_list claim; bits must be set to one of the
	// spec-defined values before the decoder is willing to consume it.
	if !validBitSize(payload.StatusList.Bits) {
		return nil, fmt.Errorf("%w: invalid status_list.bits: %d", ErrUnauthorized, payload.StatusList.Bits)
	}
	if payload.StatusList.Lst == "" {
		return nil, fmt.Errorf("%w: empty status_list.lst", ErrUnauthorized)
	}

	return &verifiedStatusList{payload: payload, rawJwt: rawJwt}, nil
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
