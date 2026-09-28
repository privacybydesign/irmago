package openid4vp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-errors/errors"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/internal/helpers"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/jose"
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
	// The certificate the JWT was verified with is kept here by the key function, rather than on
	// the validator, so that concurrent calls do not overwrite each other's.
	var leafCert *x509.Certificate
	var authRequest AuthorizationRequest
	err := jose.Verify(requestJwt, &authRequest, func(headers jws.Headers, payload []byte) (jwa.SignatureAlgorithm, any, error) {
		// The client_id names the certificate the request must be signed with, so it has to be
		// read out of the still unverified payload to find the key.
		var unverified AuthorizationRequest
		if err := json.Unmarshal(payload, &unverified); err != nil {
			return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("failed to parse auth request claims: %v", err)
		}
		alg, cert, err := v.authorizeAuthRequestSigner(headers, &unverified)
		if err != nil {
			return jwa.EmptySignatureAlgorithm(), nil, err
		}
		leafCert = cert
		return alg, cert.PublicKey, nil
	}, authRequestParserOptions()...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse auth request jwt: %v", err)
	}

	// What the verifier is authorized to ask for comes from its certificate
	// alone, and is decided independently of how the verifier is displayed.
	//
	// A Yivi issued certificate carries the relying party's authorized attribute
	// sets in its scheme extension, and a query outside those sets has to be
	// refused however the verifier chooses to present itself. This check used to
	// share one if/else-if chain with the display name below, which made it
	// skippable: a request carrying client_metadata.client_name took the first
	// branch, so the certificate's authorization was never read and every query
	// was accepted — a verifier could widen its own authorization just by naming
	// itself in the request it signs.
	//
	// TODO: we'll need to figure out if/how we want to authorize on attribute level when we're dealing with a non-Yivi issued certificate. For now, we only support that functionality for Yivi issued certificates, and we authorize all attribute for certificates issued by third parties.
	certRequestorInfo, certSchemeErr := utils.GetRequestorInfoFromCertificate[scheme.RelyingPartyRequestor](leafCert)
	if certSchemeErr == nil {
		queryValidator := v.validatorFactory.CreateQueryValidator(&certRequestorInfo.RelyingParty)
		credQueries := dcqlQueryToCredentialQueryInfos(authRequest.DcqlQuery)
		if err := queryValidator.ValidateCredentialQueries(credQueries); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to verify queried credentials: %v", err)
		}
	}

	// Try to get verifier metadata in order:
	// 1. From the verifier metadata in the authorization request (if present)
	// 2. From the certificate OID (if it's a Yivi issued certificate)
	// 3. Use the CN from the certificate, without a logo, as a fallback (if all else fails)
	requestorInfo := &scheme.RelyingPartyRequestor{}

	switch {
	case authRequest.ClientMetadata != nil && authRequest.ClientMetadata.ClientName != nil:
		requestorInfo.Organization.LegalName = map[string]string{"en": *authRequest.ClientMetadata.ClientName}

		if authRequest.ClientMetadata.LogoUri != nil {
			logoData, mimeType, err := helpers.DownloadRemoteImage(context.Background(), common.HTTPClient, *authRequest.ClientMetadata.LogoUri)
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

	case certSchemeErr == nil:
		requestorInfo = certRequestorInfo

	default:
		// Reading the requestor info from the certificate failed, so most likely it is
		// not a Yivi issued certificate and we fall back to the CN in the certificate.
		requestorInfo.Organization.LegalName = map[string]string{"en": leafCert.Subject.CommonName}
	}

	return &authRequest, leafCert, requestorInfo, nil
}

// authorizeAuthRequestSigner checks that the JWT declares itself an authorization request, that
// its x5c certificate is one this verifier trusts, and that the certificate is the one the
// client_id names. It returns the algorithm to verify the signature with and that certificate.
func (v *RequestorCertificateStoreVerifierValidator) authorizeAuthRequestSigner(
	headers jws.Headers, request *AuthorizationRequest,
) (jwa.SignatureAlgorithm, *x509.Certificate, error) {
	typ, ok := headers.Type()
	if !ok {
		return jwa.EmptySignatureAlgorithm(), nil, errors.New("auth request JWT needs to contain 'typ' in header, but doesn't")
	}
	if typ != AuthRequestJwtTyp {
		return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("auth request JWT typ in header should be %v but was %v", AuthRequestJwtTyp, typ)
	}
	alg, err := authRequestSignatureAlgorithm(headers)
	if err != nil {
		return jwa.EmptySignatureAlgorithm(), nil, err
	}

	parsedCert, err := getEndEntityCertFromX5cHeader(headers)
	if err != nil {
		return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("failed to get end-entity certificate from x5c header: %v", err)
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
			return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("client_id certificate hash %q does not match leaf certificate hash %q", expectedHash, actualHash)
		}

	default:
		return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("client_id expected to start with '%s' or '%s' but doesn't (%s)", ClientIdentifierPrefix_X509SanDns, ClientIdentifierPrefix_X509Hash, request.ClientId)
	}

	// Verify the certificate against the trusted chains and revocation lists, using the hostname if applicable.
	if err := eudi_jwt.VerifyCertificate(v.verificationContext, parsedCert, hostname); err != nil {
		return jwa.EmptySignatureAlgorithm(), nil, fmt.Errorf("failed to verify relying party certificate: %v", err)
	}

	return alg, parsedCert, nil
}

// getEndEntityCertFromX5cHeader extracts the end-entity certificate from the x5c JWT header.
func getEndEntityCertFromX5cHeader(headers jws.Headers) (*x509.Certificate, error) {
	chain, ok := headers.X509CertChain()
	if !ok {
		return nil, errors.New("auth request token doesn't contain x5c field in the header")
	}
	if chain.Len() == 0 {
		return nil, errors.New("auth request token contains empty x5c array in the header")
	}

	endEntity, _ := chain.Get(0)
	der, err := base64.StdEncoding.DecodeString(string(endEntity))
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
//
// Both the credential type and the attribute names have to be read in a
// format-aware way. mso_mdoc names its credential type with doctype_value
// rather than vct_values, and its claim paths carry a namespace component that
// is not an attribute — so copying only vct_values and flattening every path
// component (as this did) made the validator reject every mdoc query outright:
// first for a missing vct, and had that been supplied, for requesting the
// namespace as though it were an unregistered attribute.
func dcqlQueryToCredentialQueryInfos(query dcql.DcqlQuery) []scheme.CredentialQueryInfo {
	result := make([]scheme.CredentialQueryInfo, len(query.Credentials))
	for i, cq := range query.Credentials {
		result[i] = scheme.CredentialQueryInfo{
			VctValues:      cq.VctValues(),
			DocTypeValue:   cq.DocTypeValue(),
			AttributeNames: cq.AuthorizationAttributeNames(),
		}
	}
	return result
}
