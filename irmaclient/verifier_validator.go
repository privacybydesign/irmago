package irmaclient

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
)

const SchemeExtensionOID = "2.1.123.1"

// VerifierValidator is an interface to be used to verify verifiers by parsing and verifying the
// authorization request and returning the requestor info for the verifier.
type VerifierValidator interface {
	ParseAndVerifyAuthorizationRequest(requestJwt string) (*openid4vp.AuthorizationRequest, *x509.Certificate, *eudi.RequestorSchemeData, error)
}

type RequestorCertificateStoreVerifierValidator struct {
	trustedIntermediateCertificates *x509.CertPool
	trustedRootCertificates         *x509.CertPool
}

func NewRequestorCertificateStoreVerifierValidator(rootCerts *x509.CertPool, intermediateCerts *x509.CertPool) VerifierValidator {
	return &RequestorCertificateStoreVerifierValidator{
		trustedRootCertificates:         rootCerts,
		trustedIntermediateCertificates: intermediateCerts,
	}
}

// VerifyAuthorizationRequest should be followed by a way to store the requestor logo in the cache
func (v *RequestorCertificateStoreVerifierValidator) ParseAndVerifyAuthorizationRequest(requestJwt string) (
	*openid4vp.AuthorizationRequest,
	*x509.Certificate,
	*eudi.RequestorSchemeData,
	error,
) {
	token, err := jwt.ParseWithClaims(requestJwt, &openid4vp.AuthorizationRequest{}, v.createAuthRequestVerifier())

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
		return nil, nil, nil, fmt.Errorf("end-entity certificate does not contain the required custom scheme extension with OID %s", SchemeExtensionOID)
	}

	// The scheme extension data is expected to be a DERUTF8STRING, so we need to unmarshal it
	var schemeData string
	_, err = asn1.Unmarshal(schemeExtensionData.Value, &schemeData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal scheme extension data: %v", err)
	}

	// Unmarshal the scheme JSON data to a RequestorInfo struct
	var requestorSchemeData eudi.RequestorSchemeData
	err = json.Unmarshal([]byte(schemeData), &requestorSchemeData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal scheme data to requestor object: %v", err)
	}

	claims := token.Claims.(*openid4vp.AuthorizationRequest)

	return claims, endEntityCert, &requestorSchemeData, nil
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

		certVerifyOpts := x509.VerifyOptions{
			Roots:         v.trustedRootCertificates,
			Intermediates: v.trustedIntermediateCertificates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			DNSName:       hostname,
		}

		parsedCert, err := getEndEntityCertFromX5cHeader(token)
		if err != nil {
			return nil, fmt.Errorf("failed to get end-entity certificate from x5c header: %v", err)
		}

		_, err = parsedCert.Verify(certVerifyOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to verify x5c end-entity certificate against trusted chains: %v", err)
		}

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
