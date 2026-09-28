package openid4vp

import "testing"

// TestRequireUnencryptedDirectPost covers the deployment policy that holds a
// URL-invoked session to plain direct_post.
//
// The policy exists because the EU Age Verification profile is narrower than
// OpenID4VP and ISO 18013-7, which both allow the encrypted variant and which
// this wallet implements. Off by default, so an ordinary 18013-7 verifier asking
// for direct_post.jwt is not refused for doing nothing wrong.
func TestRequireUnencryptedDirectPost(t *testing.T) {
	client := &Client{}

	if err := client.checkRedirectResponseModeAllowed(ResponseMode_DirectPostJwt); err != nil {
		t.Fatalf("direct_post.jwt must be allowed while the policy is off, got %v", err)
	}

	client.RequireUnencryptedDirectPost(true)

	if err := client.checkRedirectResponseModeAllowed(ResponseMode_DirectPost); err != nil {
		t.Fatalf("direct_post must stay allowed under the policy, got %v", err)
	}
	if err := client.checkRedirectResponseModeAllowed(ResponseMode_DirectPostJwt); err == nil {
		t.Fatal("direct_post.jwt must be refused under the policy")
	}

	// The DC API modes are deliberately untouched: the AV profile makes that path
	// primary and expects encrypted responses there. They are refused earlier for
	// a URL-invoked session anyway, by isDcApiResponseMode.
	for _, mode := range []ResponseMode{ResponseMode_DcApi, ResponseMode_DcApiJwt} {
		if err := client.checkRedirectResponseModeAllowed(mode); err != nil {
			t.Fatalf("the policy must not judge %s, got %v", mode, err)
		}
	}
}
