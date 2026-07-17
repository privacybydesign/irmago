package openid4vp

import (
	"crypto/x509"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/scheme"
)

const ClockSkew = 60 * time.Second

// VerifierValidator is an interface to be used to validate verifiers by parsing and verifying the
// authorization request and returning the requestor info for the verifier.
// The returned warnings are non-blocking findings about the verifier (such as
// a failed DNSSEC check) that the app can surface to the user.
type VerifierValidator interface {
	ParseAndVerifyAuthorizationRequest(requestJwt string) (*AuthorizationRequest, *x509.Certificate, *scheme.RelyingPartyRequestor, []clientmodels.SessionWarning, error)
}
