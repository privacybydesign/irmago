package irmaclient

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v5"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/testdata"
)

// VerifierValidator is an interface to be used to verify verifiers by parsing and verifying the
// authorization request and returning the requestor info for the verifier.
type VerifierValidator interface {
	VerifyAuthorizationRequest(requestJwt string) (*openid4vp.AuthorizationRequest, *irma.RequestorInfo, error)
}

type RequestorSchemeVerifierValidator struct {
	fakeScheme map[string]*irma.RequestorInfo
}

func NewRequestorSchemeVerifierValidator() VerifierValidator {
	return &RequestorSchemeVerifierValidator{
		fakeScheme: map[string]*irma.RequestorInfo{
			"localhost": {
				ID:     irma.RequestorIdentifier{},
				Scheme: irma.RequestorSchemeIdentifier{},
				Name: map[string]string{
					"nl": "OpenID4VP Demo Verifier",
					"en": "OpenID4VP Demo Verifier",
				},
				Industry:   &irma.TranslatedString{},
				Hostnames:  []string{},
				Logo:       new(string),
				LogoPath:   new(string),
				ValidUntil: &irma.Timestamp{},
				Unverified: false,
				Languages:  []string{},
				Wizards:    map[irma.IssueWizardIdentifier]*irma.IssueWizard{},
			},
			"verifierapi.openid4vc.staging.yivi.app": {
				ID:     irma.RequestorIdentifier{},
				Scheme: irma.RequestorSchemeIdentifier{},
				Name: map[string]string{
					"nl": "Staging OpenID4VP Demo Verifier",
					"en": "Staging OpenID4VP Demo Verifier",
				},
				Industry: &irma.TranslatedString{},
				Hostnames: []string{
					"verifierapi.openid4vc.staging.yivi.app",
				},
				Logo:       new(string),
				LogoPath:   new(string),
				ValidUntil: &irma.Timestamp{},
				Unverified: false,
				Languages:  []string{},
				Wizards:    map[irma.IssueWizardIdentifier]*irma.IssueWizard{},
			},
		},
	}
}

type RequestorCertificateStoreVerifierValidator struct {
	trustedIntermediateCertificates *x509.CertPool
	trustedRootCertificates         *x509.CertPool
}

func NewRequestorCertificateStoreVerifierValidator() VerifierValidator {
	return &RequestorCertificateStoreVerifierValidator{
		trustedIntermediateCertificates: x509.NewCertPool(),
		trustedRootCertificates:         x509.NewCertPool(),
	}
}

func (v *RequestorCertificateStoreVerifierValidator) VerifyAuthorizationRequest(requestJwt string) (
	*openid4vp.AuthorizationRequest,
	*irma.RequestorInfo,
	error,
) {
	parsed, err := parseAuthorizationRequestJwt(requestJwt)
	if err != nil {
		return nil, nil, err
	}

	prefix := "x509_san_dns:"

	if !strings.HasPrefix(parsed.ClientId, prefix) {
		return nil, nil, fmt.Errorf("client_id expected to start with 'x509_san_dns:' but doesn't (%s)", parsed.ClientId)
	}

	hostname := strings.TrimPrefix(parsed.ClientId, prefix)
	requestorInfo, ok := v.fakeScheme[hostname]
	if !ok {
		return nil, nil, fmt.Errorf("failed to get info for hostname: %s", hostname)
	}

	return parsed, requestorInfo, nil
}

func (v *RequestorSchemeVerifierValidator) VerifyAuthorizationRequest(requestJwt string) (
	*openid4vp.AuthorizationRequest,
	*irma.RequestorInfo,
	error,
) {
	parsed, err := parseAuthorizationRequestJwt(requestJwt)
	if err != nil {
		return nil, nil, err
	}

	// Add the hostname to the VerifyOptions, so that the hostname will be checked against the SAN DNS

	//requestorInfo, ok := v.fakeScheme[hostname]
	// if !ok {
	// 	return nil, nil, fmt.Errorf("failed to get info for hostname: %s", hostname)
	// }

	return parsed, requestorInfo, nil
}

func parseAuthorizationRequestJwt(authReqJwt string) (*openid4vp.AuthorizationRequest, error) {
	trusted, err := sdjwtvc.CreateX509VerifyOptionsFromMultiplePemChains([][]byte{
		testdata.VerifierCertChain_staging_Bytes,
		testdata.VerifierCertChain_localhost_Bytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create trusted certificate verification options")
	}
	token, err := jwt.ParseWithClaims(authReqJwt, &openid4vp.AuthorizationRequest{}, createAuthRequestVerifier(trusted))

	if err != nil {
		return nil, fmt.Errorf("failed to parse auth request jwt: %v", err)
	}

	claims := token.Claims.(*openid4vp.AuthorizationRequest)

	return claims, nil
}

func createAuthRequestVerifier(trustedCertificates *x509.VerifyOptions) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		typ, ok := token.Header["typ"]
		if !ok {
			return nil, errors.New("auth request JWT needs to contain 'typ' in header, but doesn't")
		}
		if typ != openid4vp.AuthRequestJwtTyp {
			return nil, fmt.Errorf("auth request JWT typ in header should be %v but was %v", openid4vp.AuthRequestJwtTyp, typ)
		}

		x5c, ok := token.Header["x5c"]
		if !ok {
			return nil, fmt.Errorf("auth request token doesn't contain x5c field in the header")
		}

		certs, ok := x5c.([]any)
		if !ok {
			return nil, fmt.Errorf("auth request token doesn't contain valid x5c field in the header")
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

		// Add hostname to the VerifyOptions to check against SAN DNS
		request := token.Claims.(*openid4vp.AuthorizationRequest)
		prefix := "x509_san_dns:"

		if !strings.HasPrefix(request.ClientId, prefix) {
			return nil, fmt.Errorf("client_id expected to start with 'x509_san_dns:' but doesn't (%s)", request.ClientId)
		}

		hostname := strings.TrimPrefix(request.ClientId, prefix)

		_, err = parsedCert.Verify(*trustedCertificates)
		if err != nil {
			return nil, fmt.Errorf("failed to verify x5c end-entity certificate against trusted chains: %v", err)
		}

		return parsedCert.PublicKey, nil
	}
}
