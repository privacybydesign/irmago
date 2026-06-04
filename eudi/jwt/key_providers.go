package eudi_jwt

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/did"
	"github.com/privacybydesign/irmago/eudi/didjwk"
	"github.com/privacybydesign/irmago/eudi/didweb"
)

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
	sink.Key(alg, cert.PublicKey)

	return nil
}

type KidKeyProvider struct {
	kidHeader     string
	httpClient    *http.Client
	allowInsecure bool
}

func NewKidKeyProvider(kidHeader string, allowInsecure bool) *KidKeyProvider {
	return &KidKeyProvider{
		kidHeader:     kidHeader,
		allowInsecure: allowInsecure,
	}
}

func (p *KidKeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	// Parse the JWT payload, without verifying the signature, to obtain the iss claim value
	// (which is expected to be a did:web or did:jwk DID referencing the public key) in
	// combination with the kid header value.
	jwtPayload, err := jwt.ParseInsecure(msg.Payload())
	if err != nil {
		return fmt.Errorf("cannot resolve key identifier: failed to parse JWT payload: %v", err)
	}

	issClaim, ok := jwtPayload.Issuer()
	if !ok {
		return fmt.Errorf("cannot resolve key identifier: failed to obtain 'iss' claim from JWT payload")
	}

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
			// Verify the key is a public key, or throw an error if it contains private key material (which should not be used in a did:web document, but we want to be sure)
			isPrivateKey, err := jwk.IsPrivateKey(*vm.PublicKeyJwk)
			if err != nil {
				return fmt.Errorf("failed to determine if JWK contains private key material: %v", err)
			}
			if isPrivateKey {
				return fmt.Errorf("cannot use a JWK containing private key material")
			}

			if sig == nil {
				return fmt.Errorf("missing JWS signature")
			}
			alg, ok := sig.ProtectedHeaders().Algorithm()
			if !ok {
				return fmt.Errorf("missing alg header in JWS signature")
			}

			sink.Key(alg, *vm.PublicKeyJwk)

			return nil
		}
	}

	return fmt.Errorf("failed to find matching verification method for kid: %s", fullKid)
}

// resolveDidDocument resolves the DID document for the issuer DID, dispatching on the DID method.
// Supports did:web (fetched over HTTPS) and did:jwk (synthesized from the embedded JWK).
func (p *KidKeyProvider) resolveDidDocument(issClaim string) (*did.Document, error) {
	switch {
	case strings.HasPrefix(issClaim, didjwk.Prefix):
		key, err := didjwk.Resolve(issClaim)
		if err != nil {
			return nil, err
		}
		return (&didjwk.DocumentBuilder{}).FromJwk(key)

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
