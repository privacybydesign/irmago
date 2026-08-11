package eudi_jwt

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

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

// VerificationTime is the moment certificate validity is checked at: the
// context's pinned CurrentTime when it has one, the wall clock otherwise —
// the same reading x509.Verify gives VerifyOptions, so an explicit validity
// check and a chain verification against the same context cannot disagree.
func VerificationTime(context X509VerificationContext) time.Time {
	if t := context.GetVerificationOptionsTemplate().CurrentTime; !t.IsZero() {
		return t
	}
	return time.Now()
}

// ErrCertificateRevoked marks the one acceptance failure that is an act of
// distrust rather than an absence of trust, so a caller that treats an
// unanchored certificate as ordinary can still single a revoked one out.
var ErrCertificateRevoked = errors.New("certificate is revoked")

// CheckCertificateValidAt reports whether cert is inside its own validity
// window at the context's verification time, allowing skew on either bound.
// what names the certificate in the error message.
//
// A certificate presented outside its window is a broken artifact, like an
// expired JWT, so the gates that meet a live party reject it. Classification of
// *stored* evidence is deliberately expiry-tolerant instead — see
// TrustModel.Classify — which is why this is a check a caller asks for rather
// than part of VerifyCertificate.
func CheckCertificateValidAt(context X509VerificationContext, cert *x509.Certificate, skew time.Duration, what string) error {
	now := VerificationTime(context)
	if now.Add(skew).Before(cert.NotBefore) || now.Add(-skew).After(cert.NotAfter) {
		return fmt.Errorf("%s is not valid at the current time (notBefore %s, notAfter %s)",
			what, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// VerifyCertificateChains is the wallet's certificate acceptance policy in one
// place: the chain must build to a pinned anchor, the end-entity certificate
// must carry the digitalSignature key usage, and it must not be revoked by any
// of its issuer's revocation lists. It returns the chains the certificate
// validated to, for callers that need to know *which* anchor stood behind it.
//
// If a hostname is provided, it is used for the SAN check. A non-zero at
// overrides the moment the chain is verified at; the zero value leaves the
// context's own reading in place.
func VerifyCertificateChains(context X509VerificationContext, cert *x509.Certificate, hostname *string, at time.Time) ([][]*x509.Certificate, error) {
	var verifyOpts x509.VerifyOptions
	if hostname != nil {
		verifyOpts = GetX509VerificationOptionsFromTemplate(context, *hostname)
	} else {
		verifyOpts = context.GetVerificationOptionsTemplate()
	}
	if !at.IsZero() {
		verifyOpts.CurrentTime = at
	}

	// Verify the end-entity cert against the trusted chains
	chains, err := cert.Verify(verifyOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to verify x5c end-entity certificate: %v", err)
	}

	// Verify the digital signature key usage of the end-entity cert
	leafCert := chains[0][0]
	if leafCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, fmt.Errorf("end-entity certificate missing digitalSignature key usage")
	}

	// Check the end-entity cert against all revocation lists from the issuing cert
	if err := utils.VerifyCertificateAgainstIssuerRevocationLists(cert, context.GetRevocationLists()); err != nil {
		return nil, fmt.Errorf("%w: failed to verify x5c end-entity certificate against revocation lists: %v", ErrCertificateRevoked, err)
	}

	return chains, nil
}

// VerifyCertificate verifies the given certificate against the trusted chains and revocation lists in the provided context.
// If a hostname is provided, it will be used for the SAN check during verification.
func VerifyCertificate(context X509VerificationContext, cert *x509.Certificate, hostname *string) error {
	_, err := VerifyCertificateChains(context, cert, hostname, time.Time{})
	return err
}
