package eudi

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v5"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
)

const SchemeExtensionOID = "2.1.123.1"
const ClockSkew = 60 * time.Second

// VerifierValidator is an interface to be used to validate verifiers by parsing and verifying the
// authorization request and returning the requestor info for the verifier.
type VerifierValidator interface {
	ParseAndVerifyAuthorizationRequest(requestJwt string) (*openid4vp.AuthorizationRequest, *x509.Certificate, *RelyingPartyRequestor, error)
}

type RequestorCertificateStoreVerifierValidator struct {
	verificationContext *eudi_jwt.VerificationContext
	queryValidator      QueryValidatorFactory
}

func NewRequestorCertificateStoreVerifierValidator(verificationContext *eudi_jwt.VerificationContext, queryValidatorFactory QueryValidatorFactory) VerifierValidator {
	return &RequestorCertificateStoreVerifierValidator{
		verificationContext: verificationContext,
		queryValidator:      queryValidatorFactory,
	}
}

// ParseAndVerifyAuthorizationRequest should be followed by a way to store the requestor logo in the cache
func (v *RequestorCertificateStoreVerifierValidator) ParseAndVerifyAuthorizationRequest(requestJwt string) (
	*openid4vp.AuthorizationRequest,
	*x509.Certificate,
	*RelyingPartyRequestor,
	error,
) {
	// Parse the JWT and verify it using the verifier
	var authRequest openid4vp.AuthorizationRequest
	token, err := jwt.ParseWithClaims(requestJwt, &authRequest, v.createAuthRequestVerifier())

	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse auth request jwt: %v", err)
	}

	// Get the certificate and parse it to a RequestorInfo struct
	endEntityCert, err := getEndEntityCertFromX5cHeader(token)
	if err != nil {
		// This should never happen, as the cert should already have been verified
		return nil, nil, nil, fmt.Errorf("failed to get end-entity certificate from x5c header: %v", err)
	}

	var schemeExtensionData *pkix.Extension
	for _, ext := range endEntityCert.Extensions {
		if ext.Id.String() == SchemeExtensionOID {
			schemeExtensionData = &ext
			break
		}
	}

	if schemeExtensionData == nil {
		return nil, nil, nil, fmt.Errorf("failed to verify end-entity certificate: it does not contain the required custom certificate extension with OID %s", SchemeExtensionOID)
	}

	// The scheme extension data is expected to be a DERUTF8STRING, so we need to unmarshal it
	var schemeData string
	_, err = asn1.Unmarshal(schemeExtensionData.Value, &schemeData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify end-entity certificate: failed to unmarshal scheme extension data: %v", err)
	}

	// Unmarshal the scheme JSON data to a RequestorInfo struct
	var requestorSchemeData RelyingPartyRequestor
	err = json.Unmarshal([]byte(schemeData), &requestorSchemeData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify end-entity certificate: failed to unmarshal scheme data to requestor object: %v", err)
	}

	// Now we have a valid request, we can evaluate the query against the RP authorized attributes
	queryValidator := v.queryValidator.CreateQueryValidator(&requestorSchemeData.RelyingParty)
	if err := queryValidator.ValidateQuery(&authRequest.DcqlQuery); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify queried credentials: %v", err)
	}

	return &authRequest, endEntityCert, &requestorSchemeData, nil
}

func (v *RequestorCertificateStoreVerifierValidator) createAuthRequestVerifier() jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		typ, ok := token.Header["typ"]
		if !ok {
			return nil, errors.New("auth request JWT needs to contain 'typ' in header, but doesn't")
		}
		if typ != openid4vp.AuthRequestJwtTyp {
			return nil, fmt.Errorf("auth request JWT typ in header should be %v but was %v", openid4vp.AuthRequestJwtTyp, typ)
		}

		// Add hostname to the VerifyOptions to check against SAN DNS
		request := token.Claims.(*openid4vp.AuthorizationRequest)
		prefix := "x509_san_dns:"

		if !strings.HasPrefix(request.ClientId, prefix) {
			return nil, fmt.Errorf("client_id expected to start with 'x509_san_dns:' but doesn't (%s)", request.ClientId)
		}

		hostname := strings.TrimPrefix(request.ClientId, prefix)

		parsedCert, err := getEndEntityCertFromX5cHeader(token)
		if err != nil {
			return nil, fmt.Errorf("failed to get end-entity certificate from x5c header: %v", err)
		}

		if err := v.verificationContext.VerifyCertificate(parsedCert, &hostname); err != nil {
			return nil, fmt.Errorf("failed to verify relying party certificate: %v", err)
		}

		// Validation successful, return the public key
		return parsedCert.PublicKey, nil
	}
}

func getEndEntityCertFromX5cHeader(token *jwt.Token) (*x509.Certificate, error) {
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
	return parsedCert, nil
}
