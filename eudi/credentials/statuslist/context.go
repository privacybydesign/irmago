package statuslist

import (
	"encoding/json"
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

	// HTTPClient is used by the fetcher for the status list URI GET.
	// nil falls back to http.DefaultClient (bounded by the fetcher's own
	// context.WithTimeout). It is NOT threaded into signature-verification
	// key resolution; did:web lookups during verify use their own
	// timeout-bounded client (didweb.NewHTTPClient) instead.
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
// signature-verified jwt.Token into our statusListPayload struct via a
// JSON round-trip — the struct's json tags mirror the spec's claim
// names (iat/exp marshal as Unix seconds, status_list as a nested
// object). Returns an error if the mandatory status_list claim is
// missing or a claim is shaped wrong for its struct field.
func payloadFromToken(token jwt.Token) (statusListPayload, error) {
	var out statusListPayload
	if !token.Has("status_list") {
		return out, fmt.Errorf("missing status_list claim")
	}
	raw, err := json.Marshal(token)
	if err != nil {
		return out, fmt.Errorf("serialize token claims: %v", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("decode token claims: %v", err)
	}
	return out, nil
}
