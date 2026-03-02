package openid4vci

import (
	"net/url"
	"strings"

	"github.com/privacybydesign/irmago/eudi/oauth2"
)

func BuildAuthorizationRequestValues(
	redirectUri string,
	clientId *string,
	scope []string,
	pkce *oauth2.CodeChallenge,
	issuerState *string,
	resource *string,
) url.Values {
	q := url.Values{}
	q.Add("response_type", "code")
	q.Add("redirect_uri", redirectUri)

	if clientId != nil {
		q.Add("client_id", *clientId)
	}
	if scope != nil {
		q.Add("scope", strings.Join(scope, " "))
	}
	if pkce != nil {
		q.Add("code_challenge", pkce.GetCodeChallenge())
		q.Add("code_challenge_method", pkce.GetCodeChallengeMethod())
	}
	if issuerState != nil {
		q.Add("issuer_state", *issuerState)
	}
	if resource != nil {
		q.Add("resource", *resource)
	}

	// The `state` parameter is handled in irmamobile, where it is used to correlate the authorization response to the session initiating the request, since we have a browser-based redirect.

	// TODO: check if redirect_uri is correctly encoded here, according to application/x-www-form-urlencoded
	return q
}
