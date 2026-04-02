package openid4vp

import (
	"crypto/x509"
	"time"

	"github.com/privacybydesign/irmago/eudi/scheme"
)

const ClockSkew = 60 * time.Second

// VerifierValidator is an interface to be used to validate verifiers by parsing and verifying the
// authorization request and returning the requestor info for the verifier.
type VerifierValidator interface {
	ParseAndVerifyAuthorizationRequest(requestJwt string) (*AuthorizationRequest, *x509.Certificate, *scheme.RelyingPartyRequestor, error)
}
