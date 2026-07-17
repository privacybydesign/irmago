package openid4vp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/internal/helpers"
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
	[]clientmodels.SessionWarning,
	error,
) {
	var authRequest AuthorizationRequest
	token, err := jwt.ParseWithClaims(requestJwt, &authRequest, v.createAuthRequestVerifier())
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse auth request jwt: %v", err)
	}

	leafCert, err := getEndEntityCertFromX5cHeader(token)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to get end-entity certificate from x5c header: %v", err)
	}

	// Try to get verifier metadata in order:
	// 1. From the verifier metadata in the authorization request (if present)
	// 2. From the certificate OID (if it's a Yivi issued certificate)
	// 3. Use the CN from the certificate, without a logo, as a fallback (if all else fails)

	requestorInfo := &scheme.RelyingPartyRequestor{}

	// TODO: we'll need to figure out if/how we want to authorize on attribute level when we're dealing with a non-Yivi issued certificate. For now, we only support that functionality for Yivi issued certificates, and we authorize all attribute for certificates issued by third parties.

	if authRequest.ClientMetadata != nil && authRequest.ClientMetadata.ClientName != nil {
		requestorInfo.Organization.LegalName = map[string]string{"en": *authRequest.ClientMetadata.ClientName}

		if authRequest.ClientMetadata.LogoUri != nil {
			logoData, mimeType, err := helpers.DownloadRemoteImage(&http.Client{}, *authRequest.ClientMetadata.LogoUri)
			if err != nil {
				// If the logo download fails, we log a warning but continue without the logo
				eudi.Logger.Warnf("failed to download verifier logo from %q: %v", *authRequest.ClientMetadata.LogoUri, err)
			} else {
				requestorInfo.Organization.Logo = &scheme.Logo{
					Data:     logoData,
					MimeType: mimeType,
				}
			}
		}
	} else if info, err := utils.GetRequestorInfoFromCertificate[scheme.RelyingPartyRequestor](leafCert); err == nil {
		// Try to get the requestor info from the certificate. If this fails, most likely the certificate is not a Yivi issued certificate, and we'll fall back to the CN in the certificate
		requestorInfo = info

		// If the certificate is a Yivi issued certificate, we also validate the credential queries in the authorization request against the requestor's allowed queries in the certificate. This ensures that the verifier is only requesting credentials that it is authorized to request.
		queryValidator := v.validatorFactory.CreateQueryValidator(&requestorInfo.RelyingParty)
		credQueries := dcqlQueryToCredentialQueryInfos(authRequest.DcqlQuery)
		if err := queryValidator.ValidateCredentialQueries(credQueries); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to verify queried credentials: %v", err)
		}
	} else {
		requestorInfo.Organization.LegalName = map[string]string{"en": leafCert.Subject.CommonName}
	}

	return &authRequest, leafCert, requestorInfo, nil, nil
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

		parsedCert, err := getEndEntityCertFromX5cHeader(token)
		if err != nil {
			return nil, fmt.Errorf("failed to get end-entity certificate from x5c header: %v", err)
		}

		var hostname *string = nil

		switch {
		case strings.HasPrefix(request.ClientId, string(ClientIdentifierPrefix_X509SanDns)):
			h := strings.TrimPrefix(request.ClientId, string(ClientIdentifierPrefix_X509SanDns))
			hostname = &h

		case strings.HasPrefix(request.ClientId, string(ClientIdentifierPrefix_X509Hash)):
			// x509_hash authenticates via the certificate hash rather than a DNS name,
			// so the chain/revocation check is done without a hostname/SAN check and we leave `hostname` as nil.
			expectedHash := strings.TrimPrefix(request.ClientId, string(ClientIdentifierPrefix_X509Hash))
			hash := sha256.Sum256(parsedCert.Raw)
			actualHash := base64.RawURLEncoding.EncodeToString(hash[:])
			if actualHash != expectedHash {
				return nil, fmt.Errorf("client_id certificate hash %q does not match leaf certificate hash %q", expectedHash, actualHash)
			}

		default:
			return nil, fmt.Errorf("client_id expected to start with '%s' or '%s' but doesn't (%s)", ClientIdentifierPrefix_X509SanDns, ClientIdentifierPrefix_X509Hash, request.ClientId)
		}

		// Verify the certificate against the trusted chains and revocation lists, using the hostname if applicable.
		if err := eudi_jwt.VerifyCertificate(v.verificationContext, parsedCert, hostname); err != nil {
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
			VctValues:  cq.VctValues(),
			ClaimPaths: paths,
		}
	}
	return result
}
