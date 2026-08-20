package openid4vp

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/did"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/privacybydesign/irmago/eudi/didweb"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
)

const (
	clientIdPrefixDidJwk = "decentralized_identifier:did:jwk:"
	clientIdPrefixDidWeb = "decentralized_identifier:did:web:"
)

// DidVerifierValidator validates OpenID4VP authorization requests signed by
// verifiers that identify themselves using a DID (did:jwk or did:web).
//
// A DID authenticates the verifier by itself: the signature is checked against
// the key the DID resolves to, and that is the identity gate. A verification
// method may additionally carry an X.509 certificate over its key (RFC 7517
// §4.7); that certificate does not authenticate the verifier — the DID already
// did — but it is what the trust ladder's certificate channel ranks, and what
// carries an enforceable attribute authorization. It is honoured exactly as the
// x5c-header path honours a certificate, which is why this validator holds the
// same verification context and query-validator factory as the X.509 one.
type DidVerifierValidator struct {
	didWebResolver      *didweb.DocumentResolver
	verificationContext eudi_jwt.X509VerificationContext
	validatorFactory    QueryValidatorFactory
}

// NewDidVerifierValidator creates a new DID-based verifier validator. The
// verification context and factory are the same ones the X.509 validator holds:
// an attesting certificate on a DID key is classified and authorization-checked
// against them just as an x5c-header certificate is.
func NewDidVerifierValidator(
	allowInsecureDidWeb bool,
	verificationContext eudi_jwt.X509VerificationContext,
	validatorFactory QueryValidatorFactory,
) *DidVerifierValidator {
	return &DidVerifierValidator{
		didWebResolver:      didweb.NewDocumentResolver(allowInsecureDidWeb),
		verificationContext: verificationContext,
		validatorFactory:    validatorFactory,
	}
}

// SetAllowInsecureDidWeb enables resolving did:web DIDs over HTTP (for developer mode).
func (v *DidVerifierValidator) SetAllowInsecureDidWeb(allow bool) {
	v.didWebResolver.AllowInsecure = allow
}

// AllowsInsecureDidWeb reports whether did:web DIDs may be resolved over HTTP.
func (v *DidVerifierValidator) AllowsInsecureDidWeb() bool {
	return v.didWebResolver.AllowInsecure
}

func (v *DidVerifierValidator) ParseAndVerifyAuthorizationRequest(requestJwt string) (
	*AuthorizationRequest,
	*VerifiedRequestor,
	error,
) {
	// Pre-parse the claims to inspect client_id before signature verification
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	preToken, _, err := parser.ParseUnverified(requestJwt, &AuthorizationRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to pre-parse auth request jwt: %v", err)
	}

	preClaims := preToken.Claims.(*AuthorizationRequest)
	clientId := preClaims.ClientId

	// Resolve the public key from the DID, along with any certificate the
	// signing verification method's key carries. A key-mismatched or malformed
	// x5c refuses here (inside resolution), which is the one certificate defect
	// the DID path can detect without the verification context.
	pubKey, attestingCert, didString, err := v.resolvePublicKey(clientId, preToken.Header)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve verifier public key: %v", err)
	}

	// Parse and verify the JWT with the resolved key
	var authRequest AuthorizationRequest
	_, err = jwt.ParseWithClaims(requestJwt, &authRequest, func(token *jwt.Token) (any, error) {
		typ, ok := token.Header["typ"]
		if !ok {
			return nil, fmt.Errorf("auth request JWT needs 'typ' in header")
		}
		if typ != AuthRequestJwtTyp {
			return nil, fmt.Errorf("auth request JWT typ should be %v but was %v", AuthRequestJwtTyp, typ)
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify auth request jwt: %v", err)
	}

	requestor := &VerifiedRequestor{}

	if attestingCert != nil {
		if err := v.honourAttestingCertificate(requestor, attestingCert, &authRequest); err != nil {
			return nil, nil, err
		}
	}

	// The verifier's own account of itself, whatever the anchoring. Everything a
	// bare DID carries is the verifier's own word, so it all lands in the
	// self-asserted account. Priority:
	// 1. client_name from client_metadata (RFC 7591, best-effort)
	// 2. response_uri hostname
	// 3. domain from did:web
	// 4. "unknown" (raw did:jwk is never useful to a user)
	if authRequest.ClientMetadata != nil && authRequest.ClientMetadata.ClientName != nil {
		requestor.SelfAssertedName = *authRequest.ClientMetadata.ClientName
	} else if host := hostFromURL(authRequest.ResponseUri); host != "" {
		requestor.SelfAssertedName = host
	} else if domain, ok := didWebDomain(didString); ok {
		requestor.SelfAssertedName = domain
	} else {
		requestor.SelfAssertedName = "unknown"
	}

	return &authRequest, requestor, nil
}

// honourAttestingCertificate applies the wallet's one certificate policy to a
// DID key's attesting certificate: revoked or expired refuses the session (the
// same gate the x5c-header path applies to a live party), and an anchored
// certificate's contents become attested, carrying an enforceable authorization
// when they hold the Yivi scheme extension. An unanchored certificate is absent
// evidence — the ladder ranks it low — so its contents stay the party's own word
// and nothing is attested off it.
func (v *DidVerifierValidator) honourAttestingCertificate(
	requestor *VerifiedRequestor,
	attestingCert *x509.Certificate,
	authRequest *AuthorizationRequest,
) error {
	// A live party has no business presenting an expired or revoked certificate,
	// so the gate rejects it — mirroring the x5c-header path exactly.
	if err := eudi_jwt.CheckCertificateValidAt(v.verificationContext, attestingCert, ClockSkew, "verifier attesting certificate"); err != nil {
		return err
	}
	if err := eudi_jwt.CheckCertificateNotRevoked(v.verificationContext, attestingCert); err != nil {
		return fmt.Errorf("verifier attesting certificate is refused: %w", err)
	}

	requestor.Certificate = attestingCert

	// The anchoring, attested-name and authorization step is shared with the
	// x5c-header verifier — only the transport that produced the leaf differs.
	// The DID path derives its self-asserted account separately, so it ignores
	// whether the certificate was anchored.
	_, err := applyAttestedCertificate(v.verificationContext, v.validatorFactory, requestor, attestingCert, authRequest)
	return err
}

// hostFromURL parses a URL and returns its hostname (without port), or "" on failure.
func hostFromURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// didWebDomain extracts the domain (host) from a did:web DID string.
func didWebDomain(didStr string) (string, bool) {
	const prefix = "did:web:"
	if !strings.HasPrefix(didStr, prefix) {
		return "", false
	}
	host := strings.SplitN(strings.TrimPrefix(didStr, prefix), ":", 2)[0]
	if host == "" {
		return "", false
	}
	return host, true
}

// resolvePublicKey extracts the public key from the client_id DID, together with
// the attesting certificate the resolved verification method's key carries (nil
// when it carries none).
func (v *DidVerifierValidator) resolvePublicKey(clientId string, header map[string]any) (any, *x509.Certificate, string, error) {
	did := strings.TrimPrefix(clientId, "decentralized_identifier:")
	switch {
	case strings.HasPrefix(clientId, clientIdPrefixDidJwk):
		key, cert, err := v.resolveDidJwk(did, header)
		return key, cert, did, err

	case strings.HasPrefix(clientId, clientIdPrefixDidWeb):
		key, cert, err := v.resolveDidWeb(did, header)
		return key, cert, did, err

	default:
		return nil, nil, "", fmt.Errorf("unsupported client_id scheme: %s", clientId)
	}
}

// resolveDidJwk extracts the public key from a did:jwk DID. A did:jwk identifier
// is itself a JWK, so it may carry an x5c like any other verification method
// key — the mechanism is method-agnostic.
func (v *DidVerifierValidator) resolveDidJwk(didJwk string, header map[string]any) (any, *x509.Certificate, error) {
	key, err := didjwk.Resolve(didJwk)
	if err != nil {
		return nil, nil, err
	}

	attestingCert, err := eudi_jwt.AttestingCertificate(key)
	if err != nil {
		return nil, nil, fmt.Errorf("did:jwk carries an invalid attesting certificate: %w", err)
	}

	var rawKey any
	if err := jwk.Export(key, &rawKey); err != nil {
		return nil, nil, fmt.Errorf("failed to export raw key from did:jwk: %v", err)
	}

	return rawKey, attestingCert, nil
}

// resolveDidWeb resolves a did:web DID document and extracts the verification key.
func (v *DidVerifierValidator) resolveDidWeb(didWeb string, header map[string]any) (any, *x509.Certificate, error) {
	doc, err := v.didWebResolver.Resolve(didWeb)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve did:web document: %v", err)
	}

	key, attestingCert, err := findVerificationKey(doc, header)
	if err != nil {
		return nil, nil, err
	}

	return key, attestingCert, nil
}

// findVerificationKey finds the appropriate verification key from a DID document,
// matching by the kid header if present, and returns the attesting certificate
// the key carries (nil when it carries none). A key-mismatched or malformed x5c
// on the signing verification method is refused here, before the signature is
// even checked: a document asserting a chain for a key it does not hold is
// malformed.
func findVerificationKey(doc *did.Document, header map[string]any) (any, *x509.Certificate, error) {
	if len(doc.VerificationMethod) == 0 {
		return nil, nil, fmt.Errorf("DID document has no verification methods")
	}

	// If there's a kid header, find the matching verification method
	kid, _ := header["kid"].(string)

	for _, vm := range doc.VerificationMethod {
		if kid != "" && vm.ID != kid {
			continue
		}
		pk := vm.PublicKey()
		if pk == nil {
			continue
		}

		jwkKey := *pk
		attestingCert, err := eudi_jwt.AttestingCertificate(jwkKey)
		if err != nil {
			return nil, nil, fmt.Errorf("verification method %s carries an invalid attesting certificate: %w", vm.ID, err)
		}

		var rawKey any
		if err := jwk.Export(jwkKey, &rawKey); err != nil {
			return nil, nil, fmt.Errorf("failed to export raw key from verification method %s: %v", vm.ID, err)
		}
		return rawKey, attestingCert, nil
	}

	if kid != "" {
		return nil, nil, fmt.Errorf("no verification method found matching kid %q", kid)
	}
	return nil, nil, fmt.Errorf("no usable verification method found in DID document")
}
