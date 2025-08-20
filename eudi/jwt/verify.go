package eudi_jwt

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/privacybydesign/irmago/eudi/utils"
)

type VerificationContext struct {
	// X509VerificationOptionsTemplate contains all trusted certificates and settings for verifying the `x5c` header
	// field of the issuer signed jwt when provided.
	// Before certificate verification, the options are copied to a new instance, where fields like the Hostname can be set on a per-request basis.
	X509VerificationOptionsTemplate x509.VerifyOptions

	// X509RevocationLists contains all revocation lists for verifying the `x5c` header
	// field of the issuer signed jwt when provided.
	X509RevocationLists []*x509.RevocationList
}

func (context VerificationContext) GetX509VerificationOptionsFromTemplate(hostname string) x509.VerifyOptions {
	return x509.VerifyOptions{
		//CurrentTime:   context.Clock.Now(),
		Roots:         context.X509VerificationOptionsTemplate.Roots,
		Intermediates: context.X509VerificationOptionsTemplate.Intermediates,
		DNSName:       hostname,
		KeyUsages:     context.X509VerificationOptionsTemplate.KeyUsages,
	}
}

func (context VerificationContext) VerifyCertificate(cert *x509.Certificate, hostname *string, uri *string) error {
	if hostname == nil && uri == nil {
		return fmt.Errorf("either hostname or uri must be provided to verify the certificate")
	}

	// Verify the end-entity cert against the trusted chains
	var verifyOpts x509.VerifyOptions
	if hostname != nil {
		verifyOpts = context.GetX509VerificationOptionsFromTemplate(*hostname)
	} else {
		// x509.DNSName does not verify SAN URIs, so we do that manually
		if err := utils.VerifyCertificateUri(cert, *uri); err != nil {
			return err
		}

		// If URI successfully verifies, continue with the rest of the validations
		verifyOpts = context.X509VerificationOptionsTemplate
	}

	// Verify the end-entity cert against the trusted chains
	if _, err := cert.Verify(verifyOpts); err != nil {
		return fmt.Errorf("failed to verify x5c end-entity certificate: %v", err)
	}

	// Check the end-entity cert against all revocation lists from the issuing cert
	if err := utils.VerifyCertificateAgainstIssuerRevocationLists(cert, context.X509RevocationLists); err != nil {
		return fmt.Errorf("failed to verify x5c end-entity certificate against revocation lists: %v", err)
	}

	// Cert is valid, no error returned
	return nil
}

type X509KeyProvider struct {
	// Stores the validated certificate.
	// Note: the cert might be validated correctly (against CRL etc), but it is only valid for the JWT, if jwt.Parse(...) does not return an error (indicating a signature mismatch)!
	cert *x509.Certificate
}

func (p *X509KeyProvider) GetCert() *x509.Certificate {
	return p.cert
}

func (p *X509KeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	x5c, x5cPresent := sig.ProtectedHeaders().X509CertChain()

	if !x5cPresent || x5c == nil {
		return fmt.Errorf("no x5c header present in the signature, cannot verify jwt without it")
	} else {
		// The first certificate in the chain should be the end-entity certificate
		if x5c.Len() == 0 {
			return fmt.Errorf("expected x5c header, but is empty")
		}

		firstCert, _ := x5c.Get(0)

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

		sink.Key(jwa.ES256(), cert.PublicKey)
	}

	return nil
}
