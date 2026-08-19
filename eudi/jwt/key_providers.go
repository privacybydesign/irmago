package eudi_jwt

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/did"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/privacybydesign/irmago/eudi/didweb"
	"github.com/privacybydesign/irmago/eudi/oauth2"
)

// JwtKeyProvider validates the 'typ' header against a configured allow-list,
// then dispatches signature key resolution to either X509KeyProvider (when the
// JWS protected header carries x5c) or KidKeyProvider (when it carries kid).
//
// Callers that need post-fetch access to the resolved certificate (for chain
// validation against an X509VerificationContext) can type-assert
// InnerKeyProvider to *X509KeyProvider after FetchKeys returns.
type JwtKeyProvider struct {
	allowedTyps   []string
	allowInsecure bool

	// InnerKeyProvider is populated by FetchKeys and exposes the concrete
	// provider used for verification (currently *X509KeyProvider or
	// *KidKeyProvider).
	InnerKeyProvider jws.KeyProvider
}

func NewJwtKeyProvider(allowedTyps []string, allowInsecure bool) *JwtKeyProvider {
	return &JwtKeyProvider{
		allowedTyps:   allowedTyps,
		allowInsecure: allowInsecure,
	}
}

// FetchKeys validates the 'typ' header against allowedTyps and dispatches to
// X509KeyProvider or KidKeyProvider depending on which header is present.
// 'typ' MUST be present in the protected header and MUST be one of allowedTyps.
func (p *JwtKeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	// If no signature is present, we cannot/do not need resolve the key to verify the signature.
	if sig == nil {
		return nil
	}

	typ, ok := sig.ProtectedHeaders().Type()
	if !ok || !slices.Contains(p.allowedTyps, typ) {
		return fmt.Errorf("invalid 'typ' header: %v", typ)
	}

	// Select the key reference. x5c and kid are mutually exclusive: if both were
	// accepted, a kid would overwrite an x5c here while the X.509 trust/CRL check
	// downstream (gated on the *X509KeyProvider type) is silently skipped, letting a
	// forged credential be verified against the kid-resolved key.
	x5c, x5cPresent := sig.ProtectedHeaders().X509CertChain()
	x5cPresent = x5cPresent && x5c != nil

	kid, kidPresent := sig.ProtectedHeaders().KeyID()
	kidPresent = kidPresent && kid != ""

	switch {
	case x5cPresent && kidPresent:
		return fmt.Errorf("ambiguous key reference: both 'x5c' and 'kid' headers are present")
	case x5cPresent:
		p.InnerKeyProvider = NewX509KeyProvider(x5c)
	case kidPresent:
		p.InnerKeyProvider = NewDidKeyProvider(kid, p.allowInsecure)
	default:
		return fmt.Errorf("no supported key reference header (x5c or kid) present in the signature")
	}

	return p.InnerKeyProvider.FetchKeys(ctx, sink, sig, msg)
}

type X509KeyProvider struct {
	x5cHeader *cert.Chain

	// Stores the validated certificate.
	// Note: the cert might be validated correctly (against CRL etc), but it is only valid for the JWT, if jwt.Parse(...) does not return an error (indicating a signature mismatch)!
	cert *x509.Certificate
}

func NewX509KeyProvider(x5cHeader *cert.Chain) *X509KeyProvider {
	return &X509KeyProvider{
		x5cHeader: x5cHeader,
	}
}

func (p *X509KeyProvider) GetCert() *x509.Certificate {
	return p.cert
}

func (p *X509KeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	// The first certificate in the chain should be the end-entity certificate
	if p.x5cHeader == nil || p.x5cHeader.Len() == 0 {
		return fmt.Errorf("expected x5c header, but is empty")
	}

	firstCert, _ := p.x5cHeader.Get(0)
	der, err := base64.StdEncoding.DecodeString(string(firstCert))
	if err != nil {
		return fmt.Errorf("failed to decode end-entity base64 encoded der: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("failed to parse end-entity certificate: %v", err)
	}

	// Store the cert in the provider for future use and validation
	p.cert = cert

	// Use the algorithm declared in the JWS protected header — it describes how the JWT was signed
	if sig == nil {
		return fmt.Errorf("missing JWS signature")
	}
	alg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return fmt.Errorf("missing alg header in JWS signature")
	}

	// Only allow the algorithms this module accepts, to prevent the use of weak, unsupported or
	// substituted algorithms. See SupportedSignatureAlgorithms for the list and its rationale.
	if !IsSupportedSignatureAlgorithm(alg) {
		return fmt.Errorf("unsupported signature algorithm %q in JWS protected header", alg)
	}

	sink.Key(alg, cert.PublicKey)

	return nil
}

type DidKeyProvider struct {
	kidHeader string
	// httpClient resolves did:web DID documents. NewKidKeyProvider sets it to a
	// timeout-bounded client (didweb.NewHTTPClient); tests inject their own.
	httpClient    *http.Client
	allowInsecure bool
}

func NewDidKeyProvider(kidHeader string, allowInsecure bool) *DidKeyProvider {
	return &DidKeyProvider{
		kidHeader:     kidHeader,
		httpClient:    didweb.NewHTTPClient(),
		allowInsecure: allowInsecure,
	}
}

func (p *DidKeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	if sig == nil {
		return nil
	}

	alg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return nil
	}

	// Only allow the algorithms this module accepts, to prevent the use of weak, unsupported or
	// substituted algorithms. See SupportedSignatureAlgorithms for the list and its rationale.
	if !IsSupportedSignatureAlgorithm(alg) {
		return fmt.Errorf("unsupported signature algorithm %q in JWS protected header", alg)
	}

	// Parse the JWT payload, without verifying the signature, to obtain the iss claim value
	// (which is expected to be a did:web or did:jwk DID referencing the public key) in
	// combination with the kid header value.
	// It can also be used to create the OAuth2 discovery endpoint in case the JWT header specify an `alg` header.
	jwtPayload, err := jwt.ParseInsecure(msg.Payload())
	if err != nil {
		return fmt.Errorf("cannot resolve key identifier: failed to parse JWT payload: %v", err)
	}

	issClaim, ok := jwtPayload.Issuer()
	if !ok {
		// If the iss claim is not present, we cannot resolve the key identifier using the kid header. We return without setting a key on the sink, so that the signature verification will fail later.
		return nil
	}

	if !strings.HasPrefix(issClaim, didweb.Prefix) && !strings.HasPrefix(issClaim, didjwk.Prefix) {
		// If the iss claim is not a did:web or did:jwk DID, we cannot resolve the key identifier.
		// We return without setting a key on the sink, so that the signature verification will fail later.
		return nil
	}

	// TODO: move parts to DID resolution package, so that the same code can be reused for SD-JWT VC verification and Status List Token verification.
	fullKid := p.kidHeader
	if strings.HasPrefix(p.kidHeader, "#") {
		fullKid = issClaim + p.kidHeader
	}

	doc, err := p.resolveDidDocument(issClaim)
	if err != nil {
		return fmt.Errorf("failed to resolve did document for kid: %v", err)
	}

	for _, vm := range doc.VerificationMethod {
		if vm.ID == fullKid {
			pk := vm.PublicKey()
			if pk == nil {
				return nil
			}

			// Verify the key is a public key, or throw an error if it contains private key material (which should not be used in a did:web document, but we want to be sure)
			isPrivateKey, err := jwk.IsPrivateKey(pk)
			if err != nil {
				return fmt.Errorf("failed to determine if JWK contains private key material: %v", err)
			}
			if isPrivateKey {
				return nil
			}

			// Check if the key does not have the "sig" key usage, and if so, skip it. This is a security measure to prevent the use of keys that are not intended for signature verification.
			if use, found := pk.KeyUsage(); found && use != "sig" {
				return nil
			}

			sink.Key(alg, pk)
			return nil
		}
	}

	return nil
}

// resolveDidDocument resolves the DID document for the issuer DID, dispatching on the DID method.
// Supports did:web (fetched over HTTPS) and did:jwk (synthesized from the embedded JWK).
func (p *DidKeyProvider) resolveDidDocument(issClaim string) (*did.Document, error) {
	switch {
	case strings.HasPrefix(issClaim, didjwk.Prefix):
		return didjwk.ResolveDocument(issClaim)

	case strings.HasPrefix(issClaim, didweb.Prefix):
		resolver := didweb.DocumentResolver{
			HTTPClient:    p.httpClient,
			AllowInsecure: p.allowInsecure,
		}
		return resolver.Resolve(issClaim)

	default:
		return nil, fmt.Errorf("unsupported DID method for kid resolution: %s", issClaim)
	}
}

type OAuthDiscoveryJwkKeyProvider struct {
	allowedTyps []string
	httpClient  *http.Client
}

func NewOAuthDiscoveryJwkKeyProvider(allowedTyps []string, httpClient *http.Client) *OAuthDiscoveryJwkKeyProvider {
	return &OAuthDiscoveryJwkKeyProvider{
		allowedTyps: allowedTyps,
		httpClient:  httpClient,
	}
}

func (p *OAuthDiscoveryJwkKeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	headers := sig.ProtectedHeaders()

	typ, ok := headers.Type()
	if !ok || !slices.Contains(p.allowedTyps, typ) {
		return nil
	}

	alg, ok := headers.Algorithm()
	if !ok {
		// If the alg header is not present, we cannot verify the identified key using OAuth2 discovery. We return without setting a key on the sink, and fail fast to avoid unnecessary network requests.
		return nil
	}

	// Only allow supported algorithms for OAuth2 discovered keys. This is a security measure to prevent the use of weak, unsupported or substituted algorithms.
	if !IsSupportedSignatureAlgorithm(alg) {
		return nil
	}

	kid, ok := headers.KeyID()
	if !ok {
		// If the kid header is not present, we cannot resolve the key identifier using OAuth2 discovery. We return without setting a key on the sink, so that the signature verification will fail later.
		return nil
	}

	jwtPayload, err := jwt.ParseInsecure(msg.Payload())
	if err != nil {
		return fmt.Errorf("cannot resolve key identifier: failed to parse JWT payload: %v", err)
	}

	iss, ok := jwtPayload.Issuer()
	if !ok {
		// If the iss claim is not present, we cannot resolve the key identifier using OAuth2 discovery. We return without setting a key on the sink, so that the signature verification will fail later.
		return nil
	}

	// Check if the iss claim is in fact a URL we can try to fetch OAuth metadata from
	url, err := url.Parse(iss)
	if err != nil {
		return nil
	}

	if url.Scheme != "https" && url.Scheme != "http" {
		return nil
	}

	// Use the iss claim to resolve the OAuth2 discovery endpoint and obtain the public key for the specified algorithm.
	metadata, err := oauth2.TryFetchAuthorizationServerMetadata(iss)
	if err != nil {
		// We fail explicitly here, since the JWT might actually be signed with a key that is currently not resolvable because of network issues.
		return fmt.Errorf("failed to fetch OAuth2/OpenID discovery metadata for issuer %s: %v", iss, err)
	}

	if metadata.JwksUri == nil {
		// If the discovery metadata does not contain a jwks_uri, we cannot resolve the key identifier using OAuth2 discovery. We return without setting a key on the sink, so that the signature verification will fail later.
		return nil
	}

	// Fetch the JWKS from the jwks_uri
	jwks, err := jwk.Fetch(ctx, *metadata.JwksUri, jwk.WithHTTPClient(p.httpClient))
	if err != nil {
		// We fail explicitly here, since the JWT might actually be signed with a key that is not resolvable because of network issues.
		return fmt.Errorf("failed to fetch or parse JWKS from %s: %v", *metadata.JwksUri, err)
	}

	// Find the key in the JWKS that matches the kid header and the specified algorithm
	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return fmt.Errorf("no key found in JWKS with kid %s", kid)
	}

	sink.Key(alg, key)
	return nil
}
