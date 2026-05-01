package eudi_jwt

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
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

	sigAlg, err := mapX509ToJWA(cert.SignatureAlgorithm)
	if err != nil {
		return err
	}
	sink.Key(sigAlg, cert.PublicKey)

	return nil
}

// mapX509ToJWA maps a x509.SignatureAlgorithm to a JWA.SignatureAlgorithm
func mapX509ToJWA(alg x509.SignatureAlgorithm) (jwa.SignatureAlgorithm, error) {
	switch alg {
	case x509.SHA256WithRSA:
		return jwa.RS256(), nil
	case x509.SHA384WithRSA:
		return jwa.RS384(), nil
	case x509.SHA512WithRSA:
		return jwa.RS512(), nil
	case x509.ECDSAWithSHA256:
		return jwa.ES256(), nil
	case x509.ECDSAWithSHA384:
		return jwa.ES384(), nil
	case x509.ECDSAWithSHA512:
		return jwa.ES512(), nil
	case x509.PureEd25519:
		return jwa.EdDSA(), nil
	default:
		return jwa.SignatureAlgorithm{}, errors.New("unsupported or unknown x509 signature algorithm")
	}
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
	// For now, we expect the did:web method to be used to reference to the public key, but in the future we might want to support other did methods as well

	// Parse the JWT payload, without verifying the signature, to obtain the iss claim value (which is expected to be a did:web URL referencing the public key), in combination with the kid header value
	jwtPayload, err := jwt.ParseInsecure(msg.Payload())
	if err != nil {
		return fmt.Errorf("cannot create did:web key identifier: failed to parse JWT payload: %v", err)
	}

	issClaim, ok := jwtPayload.Issuer()
	if !ok {
		return fmt.Errorf("cannot create did:web key identifier: failed to obtain 'iss' claim from JWT payload")
	}

	fullKid := fmt.Sprintf("%s%s", issClaim, p.kidHeader)

	documentResolver := didweb.DocumentResolver{
		HTTPClient:    p.httpClient,
		AllowInsecure: p.allowInsecure,
	}
	doc, err := documentResolver.Resolve(issClaim)
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

			alg, err := algorithmFromJWK(*vm.PublicKeyJwk)
			if err != nil {
				return fmt.Errorf("failed to determine algorithm from JWK: %v", err)
			}

			sink.Key(alg, *vm.PublicKeyJwk)

			return nil
		}
	}

	return fmt.Errorf("failed to find matching verification method for kid: %s", fullKid)
}

// algorithmFromJWK determines the signing algorithm from a JWK.
// It first checks the "alg" field, then falls back to inferring from the key type and curve.
func algorithmFromJWK(key jwk.Key) (jwa.SignatureAlgorithm, error) {
	if alg, ok := key.Algorithm(); ok {
		if sigAlg, ok := jwa.LookupSignatureAlgorithm(alg.String()); ok {
			return sigAlg, nil
		}
	}

	kty := key.KeyType()

	switch kty {
	case jwa.EC():
		var crv jwa.EllipticCurveAlgorithm
		if err := key.Get("crv", &crv); err != nil {
			return jwa.SignatureAlgorithm{}, fmt.Errorf("EC JWK has no curve: %v", err)
		}
		switch crv {
		case jwa.P256():
			return jwa.ES256(), nil
		case jwa.P384():
			return jwa.ES384(), nil
		case jwa.P521():
			return jwa.ES512(), nil
		default:
			return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported EC curve: %s", crv)
		}
	case jwa.OKP():
		var crv jwa.EllipticCurveAlgorithm
		if err := key.Get("crv", &crv); err != nil {
			return jwa.SignatureAlgorithm{}, fmt.Errorf("OKP JWK has no curve: %v", err)
		}
		switch crv {
		case jwa.Ed25519():
			return jwa.EdDSA(), nil
		default:
			return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported OKP curve: %s", crv)
		}
	case jwa.RSA():
		return jwa.RS256(), nil
	default:
		return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported key type: %s", kty)
	}
}
