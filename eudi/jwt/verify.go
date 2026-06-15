package eudi_jwt

import (
	"crypto/x509"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/utils"
)

type StaticVerificationContext struct {
	VerifyOpts      x509.VerifyOptions
	RevocationLists []*x509.RevocationList
}

func (s *StaticVerificationContext) GetVerificationOptionsTemplate() x509.VerifyOptions {
	return s.VerifyOpts
}

func (s *StaticVerificationContext) GetRevocationLists() []*x509.RevocationList {
	return s.RevocationLists
}

type X509VerificationContext interface {
	// X509VerificationOptionsTemplate contains all trusted certificates and settings for verifying the `x5c` header
	// field of the issuer signed jwt when provided.
	// Before certificate verification, the options are copied to a new instance, where fields like the Hostname can be set on a per-request basis.
	GetVerificationOptionsTemplate() x509.VerifyOptions

	// X509RevocationLists contains all revocation lists for verifying the `x5c` header
	// field of the issuer signed jwt when provided.
	GetRevocationLists() []*x509.RevocationList
}

func GetX509VerificationOptionsFromTemplate(context X509VerificationContext, hostname string) x509.VerifyOptions {
	template := context.GetVerificationOptionsTemplate()
	return x509.VerifyOptions{
		// TODO: take clock skew into consideration?
		//CurrentTime:   context.Clock.Now(),
		Roots:         template.Roots,
		Intermediates: template.Intermediates,
		DNSName:       hostname,
		KeyUsages:     template.KeyUsages,
	}
}

func VerifyCertificate(context X509VerificationContext, cert *x509.Certificate, hostname *string) error {
	// Verify the end-entity cert against the trusted chains
	var verifyOpts x509.VerifyOptions
	if hostname != nil {
		verifyOpts = GetX509VerificationOptionsFromTemplate(context, *hostname)
	} else {
		verifyOpts = context.GetVerificationOptionsTemplate()
	}

	// Verify the end-entity cert against the trusted chains
	if _, err := cert.Verify(verifyOpts); err != nil {
		return fmt.Errorf("failed to verify x5c end-entity certificate: %v", err)
	}

	// Check the end-entity cert against all revocation lists from the issuing cert
	if err := utils.VerifyCertificateAgainstIssuerRevocationLists(cert, context.GetRevocationLists()); err != nil {
		return fmt.Errorf("failed to verify x5c end-entity certificate against revocation lists: %v", err)
	}

	// Cert is valid, no error returned
	return nil
}
