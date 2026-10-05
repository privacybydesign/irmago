package eudi_jwt

import (
	"crypto/x509"
	"fmt"
	"slices"

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

// verifyCertificate verifies the given certificate against the verification options and revocation lists.
func verifyCertificate(opts x509.VerifyOptions, clrs []*x509.RevocationList, cert *x509.Certificate) error {
	// Verify the end-entity cert against the trusted chains
	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("failed to verify x5c certificate: %v", err)
	}

	// Check the cert against all revocation lists from the issuing cert
	if err := utils.VerifyCertificateAgainstIssuerRevocationLists(cert, clrs); err != nil {
		return fmt.Errorf("failed to verify x5c certificate against revocation lists: %v", err)
	}

	// Cert is valid, no error returned
	return nil
}

// VerifyCertificateChain validates a chain (x5c header) of certs, in accordance with RFC 7515 par 4.1.6.
// TODO / KNOWN LIMITATION: the intermediate certificates are checked against known CLRs, but if
// the CLR is only known via the info inside the certificate, that CLR will not be downloaded and/or checked.
func VerifyCertificateChain(context X509VerificationContext, certs []*x509.Certificate, hostname *string) error {
	// First, copy the root and intermediate certificate pool, in case we want to add certs to it, and not have any unwanted side-effects
	opts := context.GetVerificationOptionsTemplate()

	if len(certs) == 0 {
		return fmt.Errorf("no certificates provided in x5c header, expected at least one certificate")
	}

	if opts.Intermediates == nil {
		opts.Intermediates = x509.NewCertPool()
	} else {
		opts.Intermediates = opts.Intermediates.Clone()
	}

	if opts.Roots == nil {
		opts.Roots = x509.NewCertPool()
	} else {
		opts.Roots = opts.Roots.Clone()
	}

	// Certs in x5c are ordered leaf -> sub -> ...  so we reverse the order in which we validate the chain
	// i is the index in the original slice, so i == 0 corresponds to the leaf certificate
	for i, c := range slices.Backward(certs) {
		if i == 0 && hostname != nil {
			// Verify leaf certificate against the hostname
			opts.DNSName = *hostname
		}

		err := verifyCertificate(opts, context.GetRevocationLists(), c)
		if err != nil {
			return err
		}

		if i > 0 {
			// Add sub to the list of intermediates for next cert to be validated against
			opts.Intermediates.AddCert(c)
		} else {
			// Verify the digital signature key usage of the leaf cert
			if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
				return fmt.Errorf("end-entity certificate missing digitalSignature key usage")
			}
		}
	}

	return nil
}
