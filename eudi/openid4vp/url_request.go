package openid4vp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// parseUnsignedUrlRequest reads the Authorization Request parameters a verifier
// sent directly in the query string.
//
// Only the parameters OpenID4VP defines for the request itself are read. The JWT
// claims of a request object (aud, iat, exp, nbf) have no query-string
// counterpart, so an unsigned request carries no validity window of its own:
// its freshness is whatever the nonce and the single-use link give it.
// expected_origins is likewise absent by design -- it exists for signed requests
// over the Digital Credentials API, and reading it here would let an
// unauthenticated caller state which origins to trust.
func parseUnsignedUrlRequest(query url.Values) (*AuthorizationRequest, error) {
	request := &AuthorizationRequest{
		ClientId:         query.Get("client_id"),
		Nonce:            query.Get("nonce"),
		State:            query.Get("state"),
		Scope:            query.Get("scope"),
		ResponseType:     query.Get("response_type"),
		ResponseMode:     ResponseMode(query.Get("response_mode")),
		ResponseUri:      query.Get("response_uri"),
		RedirectUri:      query.Get("redirect_uri"),
		RequestUriMethod: RequestUriMethod(query.Get("request_uri_method")),
	}

	// dcql_query and client_metadata are JSON objects, so in a query string they
	// arrive as the serialized object rather than as flattened parameters.
	if raw := query.Get("dcql_query"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &request.DcqlQuery); err != nil {
			return nil, fmt.Errorf("failed to parse the dcql_query parameter: %v", err)
		}
	}
	if raw := query.Get("client_metadata"); raw != "" {
		var metadata ClientMetadata
		if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
			return nil, fmt.Errorf("failed to parse the client_metadata parameter: %v", err)
		}
		request.ClientMetadata = &metadata
	}

	return request, nil
}

// validateUnsignedUrlRequest checks what OpenID4VP Section 5.10 constrains for a
// request that arrives without a signed request object, and fills in the
// response location the client identifier already states when the verifier chose
// to omit it.
//
// Every client identifier prefix this wallet accepts for a signed request names
// something a signature is checked against -- a certificate for x509_san_dns:
// and x509_hash:, a DID document for decentralized_identifier: -- so none of
// them mean anything on a request nobody signed. `redirect_uri:` is the one
// prefix defined for an unsigned request, and it authenticates the verifier in
// the only way an unsigned request can: the client identifier *is* the URL the
// response is sent to, so a request naming someone else's response URL sends the
// disclosure to that someone else rather than to whoever forged the link.
//
// That is a good deal weaker than a certificate, which is why the requestor
// built from it is never presented as verified.
func validateUnsignedUrlRequest(request *AuthorizationRequest) error {
	if request.ClientId == "" {
		return fmt.Errorf("request carries no request object and no client_id")
	}
	if !strings.HasPrefix(request.ClientId, string(ClientIdentifierPrefix_RedirectUri)) {
		return fmt.Errorf(
			"client_id %q can only be used with a signed request object: an unsigned request must use the %s client identifier prefix",
			request.ClientId, ClientIdentifierPrefix_RedirectUri)
	}

	location := unsignedResponseLocation(request.ClientId)
	if location == "" {
		return fmt.Errorf("client_id %q names no response location", request.ClientId)
	}
	if parsed, err := url.Parse(location); err != nil {
		return fmt.Errorf("client_id %q does not name a URL: %v", request.ClientId, err)
	} else if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("client_id %q does not name an absolute URL", request.ClientId)
	}

	// "The Verifier MAY omit the redirect_uri Authorization Request parameter"
	// when the client identifier already carries it. Filled in only for the
	// response modes that send the response somewhere, so no response location is
	// ever invented for a mode that does not use one.
	if request.ResponseUri == "" && request.RedirectUri == "" {
		if request.ResponseMode == ResponseMode_DirectPost || request.ResponseMode == ResponseMode_DirectPostJwt {
			request.ResponseUri = location
		}
		return nil
	}

	// Stated as well as named: the two have to agree, or the request says one
	// thing about who is asking and another about where the answer goes -- and it
	// is the client identifier the user is shown.
	stated := request.ResponseUri
	if stated == "" {
		stated = request.RedirectUri
	}
	if stated != location {
		return fmt.Errorf(
			"response location %q does not match the response location %q named by client_id",
			stated, location)
	}
	return nil
}

// unsignedResponseLocation returns the response location a `redirect_uri:`
// client identifier names.
func unsignedResponseLocation(clientId string) string {
	return strings.TrimPrefix(clientId, string(ClientIdentifierPrefix_RedirectUri))
}

// unsignedUrlRequestor builds the requestor to show for a request that arrived
// without a signed request object. Nothing in such a request is authenticated,
// so it is never presented as verified: all the wallet can tell the user is
// where the response would go.
//
// client_metadata is deliberately not consulted for the display name, for the
// same reason unsignedDcApiRequestor ignores it -- the caller chose that value
// for itself, and showing it would hide the one thing the request does bind
// behind a name nobody checked.
//
// The id is the client identifier, which is stable across sessions and so groups
// this verifier's disclosure history under one key. It carries the
// `redirect_uri:` prefix, so it can never collide with the key a certificate- or
// DID-authenticated verifier's logo is cached under; nothing authenticated a
// logo here, and none is ever stored.
//
// The name is the origin of the response location rather than the full URL: the
// path says which endpoint of a verifier collects the response, which is noise
// to the user, while the scheme and port are not -- a response bound to
// http://example.com goes somewhere else than one bound to https://example.com,
// so collapsing them to a bare host would show two different recipients under
// one name.
func unsignedUrlRequestor(request *AuthorizationRequest) *clientmodels.TrustedParty {
	location := unsignedResponseLocation(request.ClientId)
	displayName := location
	if parsed, err := url.Parse(location); err == nil && parsed.Scheme != "" && parsed.Hostname() != "" {
		displayName = parsed.Scheme + "://" + originHostPort(parsed)
	}
	return &clientmodels.TrustedParty{
		Id:       request.ClientId,
		Name:     displayName,
		Verified: false,
	}
}
