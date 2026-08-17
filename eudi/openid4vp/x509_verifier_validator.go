package openid4vp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/privacybydesign/irmago/eudi"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/utils"
)

// RequestorCertificateStoreVerifierValidator validates OpenID4VP authorization
// requests signed by verifiers that use X.509 certificates (the x509_san_dns:
// and x509_hash: client_id schemes).
//
// The gate is internal validity: the request's signature must verify against
// the certificate its client_id binds it to, presented within its own validity
// window, and not revoked. Whether any anchor stands behind that certificate is
// deliberately not the gate's question — a chain the wallet cannot trace to an
// anchor proves nothing, so its holder passes as a legitimate-looking stranger
// and the trust ladder ranks it low, exactly like a bare self-asserted key.
// Revocation is the exception, because it is the CA withdrawing a certificate
// rather than the wallet failing to place one.
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

	// Revocation is the one certificate failure that stays in the gate: the CA
	// went out of its way to withdraw this certificate, which is an act of
	// distrust rather than the absence of trust an untraceable chain shows, and
	// it is how a compromised relying party is cut off. Asked on its own rather
	// than read off the chain verification below because the answer needs no
	// chain: the lists are signed by anchors the wallet already holds.
	if err := eudi_jwt.CheckCertificateNotRevoked(v.verificationContext, leafCert); err != nil {
		return nil, nil, fmt.Errorf("relying party certificate is refused: %w", err)
	}

	requestor := &VerifiedRequestor{Certificate: leafCert}

	// Does any anchor the wallet holds stand behind this certificate? This is
	// classification, not the gate: chain building and the digitalSignature key
	// usage, against the same trust model the ladder's certificate channel
	// consults. Anchored decides whether the certificate's contents count as
	// attested — and whether the authorization it carries is worth enforcing,
	// since an unanchored certificate's contents are the party's own word about
	// itself.
	anchored := eudi_jwt.VerifyCertificate(v.verificationContext, leafCert, nil) == nil

	if anchored {
		if info, err := utils.GetRequestorInfoFromCertificate[scheme.RelyingPartyRequestor](leafCert); err == nil {
			requestor.Attested = info

			// The one hard rule: when the party's vouching artifact carries an
			// attribute authorization, a request exceeding it fails at any
			// rung. Enforced whenever the artifact is trustworthy — never
			// skipped because the request also carries client_metadata.
			queryValidator := v.validatorFactory.CreateQueryValidator(&info.RelyingParty)
			credQueries := dcqlQueryToCredentialQueryInfos(authRequest.DcqlQuery)
			if err := queryValidator.ValidateCredentialQueries(credQueries); err != nil {
				return nil, nil, fmt.Errorf("failed to verify queried credentials: %v", err)
			}
		} else {
			// An anchored certificate without the Yivi scheme extension: a
			// third-party CA attested the subject, so its name is attested —
			// but it carries no attribute authorization to enforce.
			eudi.Logger.Debugf("openid4vp: verifier certificate carries no scheme data (%v), using its subject", err)
			requestor.Attested = scheme.NamedRelyingParty(leafCert.Subject.CommonName)
		}
	}

	// The verifier's own account of itself, whatever the anchoring:
	// client_metadata first, the certificate's contents when no anchor stands
	// behind them. A self-asserted logo is never taken, so only the name
	// travels.
	if authRequest.ClientMetadata != nil && authRequest.ClientMetadata.ClientName != nil {
		requestor.SelfAssertedName = *authRequest.ClientMetadata.ClientName
	} else if !anchored {
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

		// A live party has no business presenting an expired certificate, so the
		// gate rejects it. (Stored evidence is different — classification of a
		// stored issuer leaf is expiry-tolerant, see TrustModel.Classify.)
		if err := eudi_jwt.CheckCertificateValidAt(v.verificationContext, parsedCert, ClockSkew, "relying party certificate"); err != nil {
			return nil, err
		}

		// The client_id binding: the request must prove it is for the party
		// the client_id names. This stays in the gate even though an
		// unanchored SAN attests nothing — a request whose certificate does
		// not match its own client_id is internally incoherent.
		switch {
		case strings.HasPrefix(request.ClientId, string(ClientIdentifierPrefix_X509SanDns)):
			hostname := strings.TrimPrefix(request.ClientId, string(ClientIdentifierPrefix_X509SanDns))
			if err := parsedCert.VerifyHostname(hostname); err != nil {
				return nil, fmt.Errorf("client_id hostname %q does not match the leaf certificate: %v", hostname, err)
			}

		case strings.HasPrefix(request.ClientId, string(ClientIdentifierPrefix_X509Hash)):
			expectedHash := strings.TrimPrefix(request.ClientId, string(ClientIdentifierPrefix_X509Hash))
			hash := sha256.Sum256(parsedCert.Raw)
			actualHash := base64.RawURLEncoding.EncodeToString(hash[:])
			if actualHash != expectedHash {
				return nil, fmt.Errorf("client_id certificate hash %q does not match leaf certificate hash %q", expectedHash, actualHash)
			}

		default:
			return nil, fmt.Errorf("client_id expected to start with '%s' or '%s' but doesn't (%s)", ClientIdentifierPrefix_X509SanDns, ClientIdentifierPrefix_X509Hash, request.ClientId)
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
