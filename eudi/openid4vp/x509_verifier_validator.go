package openid4vp

import (
	"crypto/sha256"
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
// requests signed by verifiers that use X.509 certificates (the x509_san_dns:
// and x509_hash: client_id schemes).
//
// The gate is internal validity: the request's signature must verify against the
// certificate its client_id binds it to, presented within its validity window
// and not revoked. Anchoring is not the gate's question — that is the trust
// ladder's, in the client. Revocation stays a gate because it is the CA
// withdrawing a certificate, an act of distrust rather than the absence of trust
// an untraceable chain shows.
type RequestorCertificateStoreVerifierValidator struct {
	verificationContext eudi_jwt.X509VerificationContext
}

// NewRequestorCertificateStoreVerifierValidator builds the x509 gate. The
// verification context supplies the revocation lists; its anchors are consulted
// by the trust ladder, not here.
func NewRequestorCertificateStoreVerifierValidator(verificationContext eudi_jwt.X509VerificationContext) *RequestorCertificateStoreVerifierValidator {
	return &RequestorCertificateStoreVerifierValidator{
		verificationContext: verificationContext,
	}
}

func (v *RequestorCertificateStoreVerifierValidator) ParseAndVerifyAuthorizationRequest(requestJwt string) (
	*AuthorizationRequest,
	*VerifiedRequestor,
	error,
) {
	var authRequest AuthorizationRequest
	token, err := jwt.ParseWithClaims(requestJwt, &authRequest, v.createAuthRequestVerifier())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse auth request jwt: %v", err)
	}

	leafCert, err := getEndEntityCertFromX5cHeader(token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get end-entity certificate from x5c header: %v", err)
	}

	requestor := &VerifiedRequestor{Certificate: leafCert}

	// The Yivi scheme extension, when the certificate carries one. A certificate
	// without it, or with one that does not parse, is most likely not a Yivi
	// issued certificate; that is not a failure.
	if info, err := utils.GetRequestorInfoFromCertificate[scheme.RelyingPartyRequestor](leafCert); err == nil {
		requestor.SchemeData = info
	}

	// The verifier's own account of itself: client_metadata first, the
	// certificate's common name otherwise.
	if authRequest.ClientMetadata != nil && authRequest.ClientMetadata.ClientName != nil {
		requestor.SelfAssertedName = *authRequest.ClientMetadata.ClientName
	} else {
		requestor.SelfAssertedName = leafCert.Subject.CommonName
	}

	return &authRequest, requestor, nil
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

		// A live party presenting a certificate outside its validity window is
		// refused, anchored or not.
		if err := eudi_jwt.CheckCertificateValidAt(v.verificationContext, parsedCert, ClockSkew, "relying party certificate"); err != nil {
			return nil, err
		}

		// The request must prove it is for the party its client_id names. In the
		// gate even though an unanchored SAN attests nothing: a certificate that
		// does not match its own client_id is internally incoherent.
		switch {
		case strings.HasPrefix(request.ClientId, string(ClientIdentifierPrefix_X509SanDns)):
			hostname := strings.TrimPrefix(request.ClientId, string(ClientIdentifierPrefix_X509SanDns))
			if err := parsedCert.VerifyHostname(hostname); err != nil {
				return nil, fmt.Errorf("client_id hostname %q does not match the relying party certificate: %v", hostname, err)
			}

		case strings.HasPrefix(request.ClientId, string(ClientIdentifierPrefix_X509Hash)):
			// x509_hash authenticates via the certificate hash rather than a DNS name.
			expectedHash := strings.TrimPrefix(request.ClientId, string(ClientIdentifierPrefix_X509Hash))
			hash := sha256.Sum256(parsedCert.Raw)
			actualHash := base64.RawURLEncoding.EncodeToString(hash[:])
			if actualHash != expectedHash {
				return nil, fmt.Errorf("client_id certificate hash %q does not match leaf certificate hash %q", expectedHash, actualHash)
			}

		default:
			return nil, fmt.Errorf("client_id expected to start with '%s' or '%s' but doesn't (%s)", ClientIdentifierPrefix_X509SanDns, ClientIdentifierPrefix_X509Hash, request.ClientId)
		}

		// Revocation is the one certificate failure that stays in the gate. Asked
		// on its own rather than off chain verification, which it does not need.
		if err := eudi_jwt.CheckCertificateNotRevoked(v.verificationContext, parsedCert); err != nil {
			return nil, fmt.Errorf("relying party certificate is refused: %w", err)
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
