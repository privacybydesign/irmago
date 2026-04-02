package openid4vp

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v5"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/utils"
)

// RequestorCertificateStoreVerifierValidator validates OpenID4VP authorization
// requests signed by verifiers that use X.509 certificates (x509_san_dns: client_id scheme).
type RequestorCertificateStoreVerifierValidator struct {
	verificationContext eudi_jwt.X509VerificationContext
	validatorFactory    QueryValidatorFactory
}

func NewRequestorCertificateStoreVerifierValidator(verificationContext eudi_jwt.X509VerificationContext, validatorFactory QueryValidatorFactory) *RequestorCertificateStoreVerifierValidator {
	return &RequestorCertificateStoreVerifierValidator{
		verificationContext: verificationContext,
		validatorFactory:    validatorFactory,
	}
}

func (v *RequestorCertificateStoreVerifierValidator) ParseAndVerifyAuthorizationRequest(requestJwt string) (
	*AuthorizationRequest,
	*x509.Certificate,
	*scheme.RelyingPartyRequestor,
	error,
) {
	var authRequest AuthorizationRequest
	token, err := jwt.ParseWithClaims(requestJwt, &authRequest, v.createAuthRequestVerifier())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse auth request jwt: %v", err)
	}

	endEntityCert, err := getEndEntityCertFromX5cHeader(token)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get end-entity certificate from x5c header: %v", err)
	}

	requestorInfo, err := utils.GetRequestorInfoFromCertificate[scheme.RelyingPartyRequestor](endEntityCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get requestor info from certificate: %v", err)
	}

	queryValidator := v.validatorFactory.CreateQueryValidator(&requestorInfo.RelyingParty)
	credQueries := dcqlQueryToCredentialQueryInfos(authRequest.DcqlQuery)
	if err := queryValidator.ValidateCredentialQueries(credQueries); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify queried credentials: %v", err)
	}

	return &authRequest, endEntityCert, requestorInfo, nil
}

func (v *RequestorCertificateStoreVerifierValidator) createAuthRequestVerifier() jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		typ, ok := token.Header["typ"]
		if !ok {
			return nil, errors.New("auth request JWT needs to contain 'typ' in header, but doesn't")
		}
		if typ != AuthRequestJwtTyp {
			return nil, fmt.Errorf("auth request JWT typ in header should be %v but was %v", AuthRequestJwtTyp, typ)
		}

		request := token.Claims.(*AuthorizationRequest)
		prefix := "x509_san_dns:"

		if !strings.HasPrefix(request.ClientId, prefix) {
			return nil, fmt.Errorf("client_id expected to start with 'x509_san_dns:' but doesn't (%s)", request.ClientId)
		}

		hostname := strings.TrimPrefix(request.ClientId, prefix)

		parsedCert, err := getEndEntityCertFromX5cHeader(token)
		if err != nil {
			return nil, fmt.Errorf("failed to get end-entity certificate from x5c header: %v", err)
		}

		if err := eudi_jwt.VerifyCertificate(v.verificationContext, parsedCert, &hostname); err != nil {
			return nil, fmt.Errorf("failed to verify relying party certificate: %v", err)
		}

		return parsedCert.PublicKey, nil
	}
}

// getEndEntityCertFromX5cHeader extracts the end-entity certificate from the x5c JWT header.
func getEndEntityCertFromX5cHeader(token *jwt.Token) (*x509.Certificate, error) {
	x5c, ok := token.Header["x5c"]
	if !ok {
		return nil, fmt.Errorf("auth request token doesn't contain x5c field in the header")
	}

	certs, ok := x5c.([]any)
	if !ok {
		return nil, fmt.Errorf("auth request token doesn't contain valid x5c field in the header")
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("auth request token contains empty x5c array in the header")
	}

	endEntityString, ok := certs[0].(string)
	if !ok {
		return nil, fmt.Errorf("failed to convert end-entity to string: %v", certs[0])
	}

	der, err := base64.StdEncoding.DecodeString(endEntityString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode end-entity base64 encoded der: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x.509 certificate: %v", err)
	}
	return parsedCert, nil
}

// dcqlQueryToCredentialQueryInfos converts a DcqlQuery's credential queries
// into the scheme-level CredentialQueryInfo representation.
func dcqlQueryToCredentialQueryInfos(query dcql.DcqlQuery) []scheme.CredentialQueryInfo {
	result := make([]scheme.CredentialQueryInfo, len(query.Credentials))
	for i, cq := range query.Credentials {
		var paths []string
		for path := range cq.AllClaimPaths() {
			paths = append(paths, path)
		}
		result[i] = scheme.CredentialQueryInfo{
			VctValues:  cq.Meta.VctValues,
			ClaimPaths: paths,
		}
	}
	return result
}
