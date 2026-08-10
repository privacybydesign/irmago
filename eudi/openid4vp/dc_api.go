package openid4vp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// Protocol identifiers for OpenID4VP over the W3C Digital Credentials API,
// as defined in OpenID4VP 1.0 Appendix A.1. The request-type suffix tells the
// wallet up front whether the request is signed, so no parameter sniffing is
// needed to decide how to authenticate the verifier.
const (
	DcApiProtocolUnsigned = "openid4vp-v1-unsigned"
	DcApiProtocolSigned   = "openid4vp-v1-signed"

	// DcApiProtocolMultiSigned is recognized so we can report it as unsupported
	// instead of failing on a JWS that does not parse as compact serialization.
	DcApiProtocolMultiSigned = "openid4vp-v1-multisigned"
)

// DcApiRequest is a request the platform delivered through the Digital
// Credentials API: the exchange protocol the verifier asked for, the origin of
// the caller as authenticated by the platform, and the raw `data` member of the
// API call.
//
// The transport of the request and the origin to the wallet is platform-specific
// and out of scope of OpenID4VP (Appendix A.2), so the app layer is responsible
// for filling this in from the OS credential-provider callback.
type DcApiRequest struct {
	Protocol string          `json:"protocol"`
	Origin   string          `json:"origin"`
	Data     json.RawMessage `json:"data"`
}

// dcApiSignedRequestData is the `data` member of a signed DC API request using
// JWS Compact Serialization (Appendix A.3.2.1).
type dcApiSignedRequestData struct {
	Request string `json:"request"`
}

// isDcApiResponseMode reports whether the response for this response mode is
// returned through the Digital Credentials API instead of being transmitted to
// a response_uri by the wallet.
func isDcApiResponseMode(mode ResponseMode) bool {
	return mode == ResponseMode_DcApi || mode == ResponseMode_DcApiJwt
}

// OriginAudience returns the audience to bind the response to for a DC API
// session: the origin prefixed with `origin:` (Appendix A.4). This is the
// audience even for signed requests, so the client identifier is never used as
// the audience over the DC API.
func OriginAudience(origin string) string {
	return string(ClientIdentifierPrefix_Origin) + origin
}

// parseDcApiRequest turns a platform-delivered DC API request into a validated
// authorization request plus the requestor to show to the user.
func (client *Client) parseDcApiRequest(request *DcApiRequest) (*AuthorizationRequest, *clientmodels.TrustedParty, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("digital credentials api request is nil")
	}
	if request.Origin == "" {
		return nil, nil, fmt.Errorf("digital credentials api request is missing the caller origin")
	}
	if len(request.Data) == 0 {
		return nil, nil, fmt.Errorf("digital credentials api request is missing its data member")
	}

	var authRequest *AuthorizationRequest
	var requestor *clientmodels.TrustedParty

	switch request.Protocol {
	case DcApiProtocolUnsigned:
		parsed, err := parseUnsignedDcApiRequest(request.Data)
		if err != nil {
			return nil, nil, err
		}
		authRequest = parsed
		requestor = unsignedDcApiRequestor(request.Origin)

	case DcApiProtocolSigned:
		var data dcApiSignedRequestData
		if err := json.Unmarshal(request.Data, &data); err != nil {
			return nil, nil, fmt.Errorf("failed to parse signed digital credentials api request: %v", err)
		}
		if data.Request == "" {
			return nil, nil, fmt.Errorf("signed digital credentials api request is missing its request member")
		}

		verified, verifiedRequestor, err := client.verifySignedAuthorizationRequest(data.Request)
		if err != nil {
			return nil, nil, err
		}
		if err := validateExpectedOrigins(verified.ExpectedOrigins, request.Origin); err != nil {
			return nil, nil, err
		}
		authRequest = verified
		requestor = verifiedRequestor

	case DcApiProtocolMultiSigned:
		return nil, nil, fmt.Errorf(
			"multi-signed digital credentials api requests (%s) are not supported",
			DcApiProtocolMultiSigned,
		)

	default:
		return nil, nil, fmt.Errorf("unsupported digital credentials api protocol %q", request.Protocol)
	}

	if err := validateDcApiRequest(authRequest); err != nil {
		return nil, nil, err
	}

	// response_uri and redirect_uri are not among the parameters supported over
	// the DC API, so they must be ignored. Dropping them keeps any code further
	// down from transmitting the response anywhere but back through the platform.
	authRequest.ResponseUri = ""
	authRequest.RedirectUri = ""

	return authRequest, requestor, nil
}

// parseUnsignedDcApiRequest parses the request parameters that a verifier sent
// as members of the `data` member (Appendix A.3.1).
func parseUnsignedDcApiRequest(data []byte) (*AuthorizationRequest, error) {
	var authRequest AuthorizationRequest
	if err := json.Unmarshal(data, &authRequest); err != nil {
		return nil, fmt.Errorf("failed to parse unsigned digital credentials api request: %v", err)
	}

	// The wallet MUST ignore client_id in an unsigned request, and MUST ignore
	// expected_origins because that parameter is not for use in unsigned
	// requests (Appendix A.2). Dropping them here keeps the rest of the client
	// from reading a value the verifier never authenticated.
	authRequest.ClientId = ""
	authRequest.ExpectedOrigins = nil

	return &authRequest, nil
}

// validateDcApiRequest checks the request parameters that OpenID4VP over the DC
// API constrains (Appendix A.2).
func validateDcApiRequest(request *AuthorizationRequest) error {
	if ResponseType(request.ResponseType) != ResponseType_VpToken {
		return fmt.Errorf("digital credentials api requires response_type %q, but got %q", ResponseType_VpToken, request.ResponseType)
	}
	if !isDcApiResponseMode(request.ResponseMode) {
		return fmt.Errorf(
			"digital credentials api requires response_mode %q or %q, but got %q",
			ResponseMode_DcApi, ResponseMode_DcApiJwt, request.ResponseMode,
		)
	}
	if err := validateNonce(request.Nonce); err != nil {
		return fmt.Errorf("invalid digital credentials api request: %v", err)
	}
	if request.Scope != "" {
		return fmt.Errorf("scope is not supported over the digital credentials api, use dcql_query")
	}
	if len(request.DcqlQuery.Credentials) == 0 {
		return fmt.Errorf("digital credentials api request is missing a non-empty dcql_query")
	}
	return nil
}

// validateExpectedOrigins compares the origin reported by the platform against
// the origins the verifier signed for, to detect replay of the request by a
// malicious verifier (Appendix A.2).
func validateExpectedOrigins(expectedOrigins []string, origin string) error {
	if len(expectedOrigins) == 0 {
		return fmt.Errorf("signed digital credentials api request is missing a non-empty expected_origins")
	}
	for _, expected := range expectedOrigins {
		if sameOrigin(expected, origin) {
			return nil
		}
	}
	return fmt.Errorf("caller origin %q is not among the expected_origins of the request", origin)
}

// sameOrigin reports whether two origin strings denote the same web origin,
// comparing scheme, host and port. Origins that do not parse as a URL (such as
// the app-platform origins Android reports for native callers) are compared
// verbatim.
func sameOrigin(a, b string) bool {
	if a == b {
		return true
	}
	parsedA, errA := url.Parse(a)
	parsedB, errB := url.Parse(b)
	if errA != nil || errB != nil || parsedA.Host == "" || parsedB.Host == "" {
		return false
	}
	return strings.EqualFold(parsedA.Scheme, parsedB.Scheme) &&
		strings.EqualFold(originHostPort(parsedA), originHostPort(parsedB))
}

// originHostPort returns the host of an origin with the scheme's default port
// removed when it was written out explicitly, so that https://example.com and
// https://example.com:443 compare equal as RFC 6454 requires.
func originHostPort(u *url.URL) string {
	defaultPort := map[string]string{"http": "80", "https": "443"}[strings.ToLower(u.Scheme)]
	if defaultPort != "" && u.Port() == defaultPort {
		return u.Hostname()
	}
	return u.Host
}

// unsignedDcApiRequestor builds the requestor to show for an unsigned request.
// There is no trust framework backing an unsigned request, so the verifier is
// never presented as verified: all the wallet knows is the origin the platform
// authenticated.
//
// client_metadata is deliberately not consulted for the display name. Nothing
// authenticates it in an unsigned request, for the same reason client_id and
// expected_origins are dropped, so letting client_name name the verifier would
// hide the one fact the platform did authenticate behind a value the caller
// chose for itself.
//
// The display name is the origin itself, not just its host: the wallet does not
// require the origin to be https, so dropping the scheme and the port would show
// http://example.com, https://example.com and https://example.com:8443 under one
// name, while the response is bound to exactly one of them. A default port
// written out explicitly is normalised away, matching sameOrigin.
func unsignedDcApiRequestor(origin string) *clientmodels.TrustedParty {
	displayName := origin
	if u, err := url.Parse(origin); err == nil && u.Scheme != "" && u.Hostname() != "" {
		displayName = u.Scheme + "://" + originHostPort(u)
	}
	return &clientmodels.TrustedParty{
		// The origin the platform authenticated is both what the party is called
		// and what it is known by: at low the app renders the identifier next to
		// the name, and here it is the one thing the caller did not choose itself.
		Id: displayName,
		// client_name is a single string and an origin is not localized, so there
		// is nothing for the current locale to resolve here.
		Name: displayName,
		// Nothing vouches for the caller of an unsigned request: it presented no
		// certificate and named no identifier a recognized list could key on, so
		// the origin the platform authenticated is all the wallet has. That is
		// the bottom rung, not the absence of a verdict.
		TrustLevel: clientmodels.TrustLevel_Low,
	}
}
