package openid4vp

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/privacybydesign/irmago/eudi/scheme"
)

// CompositeVerifierValidator dispatches authorization request verification to the
// appropriate validator based on the client_id scheme in the JWT claims.
// This supports both X.509-based (x509_san_dns:) and DID-based (did:jwk, did:web)
// verifier authentication as defined in the OpenID4VP specification.
type CompositeVerifierValidator struct {
	x509Validator *RequestorCertificateStoreVerifierValidator
	didValidator  *DidVerifierValidator
}

// NewCompositeVerifierValidator creates a validator that supports both X.509 and DID-based verifiers.
func NewCompositeVerifierValidator(x509Validator *RequestorCertificateStoreVerifierValidator, didValidator *DidVerifierValidator) *CompositeVerifierValidator {
	return &CompositeVerifierValidator{
		x509Validator: x509Validator,
		didValidator:  didValidator,
	}
}

func (v *CompositeVerifierValidator) ParseAndVerifyAuthorizationRequest(requestJwt string) (
	*AuthorizationRequest,
	*x509.Certificate,
	*scheme.RelyingPartyRequestor,
	error,
) {
	// Pre-parse to inspect client_id without verifying signature
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(requestJwt, &AuthorizationRequest{})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to pre-parse auth request: %v", err)
	}

	claims := token.Claims.(*AuthorizationRequest)
	clientId := claims.ClientId

	switch {
	case strings.HasPrefix(clientId, "x509_san_dns:"):
		if v.x509Validator == nil {
			return nil, nil, nil, fmt.Errorf("X.509 verifier validator not configured")
		}
		return v.x509Validator.ParseAndVerifyAuthorizationRequest(requestJwt)

	case strings.HasPrefix(clientId, "decentralized_identifier:did:"):
		if v.didValidator == nil {
			return nil, nil, nil, fmt.Errorf("DID verifier validator not configured")
		}
		return v.didValidator.ParseAndVerifyAuthorizationRequest(requestJwt)

	default:
		return nil, nil, nil, fmt.Errorf("unsupported client_id scheme in %q", clientId)
	}
}
