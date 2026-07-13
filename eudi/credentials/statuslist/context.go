package statuslist

import (
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

// VerificationContext is the narrow configuration bag the Checker
// needs. It is intentionally a subset of sdjwtvc.SdJwtVcVerificationContext
// (no VCT-in-requestor-info policy, no expected-nonce, no
// JwtVerifier indirection) so callers don't accidentally couple to
// SD-JWT VC semantics.
//
// Callers building this from an SdJwtVcVerificationContext copy the
// X509Context, Clock, and allow-insecure flag verbatim.
type VerificationContext struct {
	// X509Context is consulted when the Status List Token's JWS
	// protected header carries x5c. Nil is rejected at verify time
	// if x5c is the chosen path.
	X509Context eudi_jwt.X509VerificationContext

	// Clock supplies the "now" for iat/exp/nbf checks. nil falls
	// back to time.Now().
	Clock jwt.Clock

	// AllowInsecureDidWeb mirrors the SD-JWT VC verifier's flag for
	// permitting did:web resolution over plain HTTP (dev/test only).
	AllowInsecureDidWeb bool

	// RequireStatusListIssuerMatch, when true, additionally requires the Status
	// List Token's `iss` to equal the issuer of the credential being
	// checked (the expectedIss passed to Check/Refresh). This is
	// STRICTER than the spec, which binds the token to the credential
	// via `sub` == `uri` plus a trusted signature and leaves issuer
	// alignment to the trust model (draft-ietf-oauth-status-list-15
	// §11.3). Default false: a delegated Status Issuer (e.g. a separate
	// status-list service signing with its own key) is accepted as
	// long as the signature is trusted and `sub` matches.
	RequireStatusListIssuerMatch bool

	// HTTPClient is used by the fetcher for the status list URI GET.
	// nil falls back to http.DefaultClient. It is NOT threaded into
	// signature-verification key resolution; did:web lookups during verify
	// use the didweb resolver's own (timeout-bounded) default client instead.
	HTTPClient *http.Client

	// MaxBodyBytes caps the HTTP response body and the
	// post-decompression bit-array size. <= 0 falls back to
	// MaxBodyDefault (5 MB).
	MaxBodyBytes int64

	// FetchTimeout bounds each HTTP request. <= 0 falls back to
	// FetchTimeoutDefault (10 s).
	FetchTimeout time.Duration
}

// payloadFromToken extracts the Status List Token's claims from a
// signature-verified jwt.Token into our statusListPayload struct.
// Returns an error if the mandatory status_list claim is missing or
// shaped wrong.
func payloadFromToken(token jwt.Token, out *statusListPayload) error {
	if iss, ok := token.Issuer(); ok {
		out.Issuer = iss
	}
	if sub, ok := token.Subject(); ok {
		out.Subject = sub
	}
	if iat, ok := token.IssuedAt(); ok && !iat.IsZero() {
		out.IssuedAt = iat.Unix()
	}
	if exp, ok := token.Expiration(); ok && !exp.IsZero() {
		out.Expiry = exp.Unix()
	}

	if token.Has("ttl") {
		var ttl float64
		if err := token.Get("ttl", &ttl); err != nil {
			return fmt.Errorf("ttl claim is not a number: %v", err)
		}
		out.TTLSeconds = int64(ttl)
	}

	if !token.Has("status_list") {
		return fmt.Errorf("missing status_list claim")
	}
	var slRaw map[string]any
	if err := token.Get("status_list", &slRaw); err != nil {
		return fmt.Errorf("status_list claim malformed: %v", err)
	}
	bitsRaw, ok := slRaw["bits"]
	if !ok {
		return fmt.Errorf("status_list.bits missing")
	}
	switch b := bitsRaw.(type) {
	case float64:
		out.StatusList.Bits = int(b)
	case int:
		out.StatusList.Bits = b
	case int64:
		out.StatusList.Bits = int(b)
	default:
		return fmt.Errorf("status_list.bits is not a number: %T", bitsRaw)
	}
	lstRaw, ok := slRaw["lst"]
	if !ok {
		return fmt.Errorf("status_list.lst missing")
	}
	lstStr, ok := lstRaw.(string)
	if !ok {
		return fmt.Errorf("status_list.lst is not a string: %T", lstRaw)
	}
	out.StatusList.Lst = lstStr
	return nil
}
