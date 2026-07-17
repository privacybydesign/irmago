package openid4vp

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/did"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/privacybydesign/irmago/eudi/didweb"
	"github.com/privacybydesign/irmago/eudi/dnssec"
	"github.com/privacybydesign/irmago/eudi/scheme"
)

const (
	clientIdPrefixDidJwk = "decentralized_identifier:did:jwk:"
	clientIdPrefixDidWeb = "decentralized_identifier:did:web:"
)

// DidVerifierValidator validates OpenID4VP authorization requests signed by
// verifiers that identify themselves using a DID (did:jwk or did:web).
type DidVerifierValidator struct {
	didWebResolver *didweb.DocumentResolver
}

// NewDidVerifierValidator creates a new DID-based verifier validator.
func NewDidVerifierValidator(allowInsecureDidWeb bool) *DidVerifierValidator {
	return &DidVerifierValidator{
		didWebResolver: &didweb.DocumentResolver{
			AllowInsecure: allowInsecureDidWeb,
		},
	}
}

// SetAllowInsecureDidWeb enables resolving did:web DIDs over HTTP (for developer mode).
func (v *DidVerifierValidator) SetAllowInsecureDidWeb(allow bool) {
	v.didWebResolver.AllowInsecure = allow
}

// SetDnssecVerifier enables an optional DNSSEC check on the domain of did:web
// verifiers. A failed or missing DNSSEC chain is reported as a warning to the
// app and never blocks validation. Pass nil to disable the check.
func (v *DidVerifierValidator) SetDnssecVerifier(verifier dnssec.Verifier) {
	v.didWebResolver.DnssecVerifier = verifier
}

func (v *DidVerifierValidator) ParseAndVerifyAuthorizationRequest(requestJwt string) (
	*AuthorizationRequest,
	*x509.Certificate,
	*scheme.RelyingPartyRequestor,
	[]clientmodels.SessionWarning,
	error,
) {
	// Pre-parse the claims to inspect client_id before signature verification
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	preToken, _, err := parser.ParseUnverified(requestJwt, &AuthorizationRequest{})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to pre-parse auth request jwt: %v", err)
	}

	preClaims := preToken.Claims.(*AuthorizationRequest)
	clientId := preClaims.ClientId

	// Resolve the public key from the DID
	pubKey, didString, warnings, err := v.resolvePublicKey(clientId, preToken.Header)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to resolve verifier public key: %v", err)
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
		return nil, nil, nil, nil, fmt.Errorf("failed to verify auth request jwt: %v", err)
	}

	// Determine a human-readable display name for the verifier. Priority:
	// 1. client_name from client_metadata (RFC 7591, best-effort)
	// 2. response_uri hostname
	// 3. domain from did:web
	// 4. "unknown" (raw did:jwk is never useful to a user)
	displayName := "unknown"
	if authRequest.ClientMetadata != nil && authRequest.ClientMetadata.ClientName != nil {
		displayName = *authRequest.ClientMetadata.ClientName
	} else if host := hostFromURL(authRequest.ResponseUri); host != "" {
		displayName = host
	} else if domain, ok := didWebDomain(didString); ok {
		displayName = domain
	}

	requestorInfo := &scheme.RelyingPartyRequestor{}
	requestorInfo.Organization.LegalName = map[string]string{"en": displayName}

	// We don't validate credential queries using queryValidator.ValidateCredentialQueries(..) on purpose here, because we have no external requestorInfo containing authorized attributes

	return &authRequest, nil, requestorInfo, warnings, nil
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

// resolvePublicKey extracts the public key from the client_id DID.
func (v *DidVerifierValidator) resolvePublicKey(clientId string, header map[string]any) (any, string, []clientmodels.SessionWarning, error) {
	switch {
	case strings.HasPrefix(clientId, clientIdPrefixDidJwk):
		didJwk := strings.TrimPrefix(clientId, "decentralized_identifier:")
		key, didString, err := v.resolveDidJwk(didJwk, header)
		return key, didString, nil, err

	case strings.HasPrefix(clientId, clientIdPrefixDidWeb):
		didWeb := strings.TrimPrefix(clientId, "decentralized_identifier:")
		return v.resolveDidWeb(didWeb, header)

	default:
		return nil, "", nil, fmt.Errorf("unsupported client_id scheme: %s", clientId)
	}
}

// resolveDidJwk extracts the public key from a did:jwk DID.
func (v *DidVerifierValidator) resolveDidJwk(didJwk string, header map[string]any) (any, string, error) {
	key, err := didjwk.Resolve(didJwk)
	if err != nil {
		return nil, "", err
	}

	var rawKey any
	if err := jwk.Export(key, &rawKey); err != nil {
		return nil, "", fmt.Errorf("failed to export raw key from did:jwk: %v", err)
	}

	return rawKey, didJwk, nil
}

// resolveDidWeb resolves a did:web DID document and extracts the verification key.
// When a DNSSEC verifier is configured, the DNSSEC status of the DID's domain is
// reported as session warnings; it never blocks resolution.
func (v *DidVerifierValidator) resolveDidWeb(didWeb string, header map[string]any) (any, string, []clientmodels.SessionWarning, error) {
	doc, dnssecResult, err := v.didWebResolver.ResolveWithDnssec(didWeb)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to resolve did:web document: %v", err)
	}

	key, err := findVerificationKey(doc, header)
	if err != nil {
		return nil, "", nil, err
	}

	return key, didWeb, dnssecWarnings(didWeb, dnssecResult), nil
}

// dnssecWarnings maps a DNSSEC check outcome to session warnings for the app.
// An indeterminate outcome produces no warning: the check was not available.
func dnssecWarnings(didWeb string, result *dnssec.Result) []clientmodels.SessionWarning {
	if result == nil {
		return nil
	}
	switch result.Status {
	case dnssec.StatusBogus:
		eudi.Logger.Warnf("DNSSEC validation for %s failed: %s", didWeb, result.Detail)
		return []clientmodels.SessionWarning{clientmodels.SessionWarning_DidWebDnssecInvalid}
	case dnssec.StatusInsecure:
		return []clientmodels.SessionWarning{clientmodels.SessionWarning_DidWebDnssecMissing}
	default:
		return nil
	}
}

// findVerificationKey finds the appropriate verification key from a DID document,
// matching by the kid header if present.
func findVerificationKey(doc *did.Document, header map[string]any) (any, error) {
	if len(doc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("DID document has no verification methods")
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
		var rawKey any
		if err := jwk.Export(jwkKey, &rawKey); err != nil {
			return nil, fmt.Errorf("failed to export raw key from verification method %s: %v", vm.ID, err)
		}
		return rawKey, nil
	}

	if kid != "" {
		return nil, fmt.Errorf("no verification method found matching kid %q", kid)
	}
	return nil, fmt.Errorf("no usable verification method found in DID document")
}
