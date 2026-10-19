package openid4vp

import (
	"crypto/x509"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/utils"
)

// trustSourceOf says where the trust in a verifier's end-entity certificate
// comes from, once it chained to a trusted root: Yivi when the certificate
// carries Yivi's relying-party scheme extension (Yivi issued it), otherwise
// another anchored CA, named by the issuer's organization.
//
// The wallet shows the first in green ("Registered with Yivi") and the second
// in blue ("Verified by …"): both are vouched for, by someone else.
func trustSourceOf(cert *x509.Certificate) (clientmodels.TrustSource, string) {
	if _, err := utils.GetRequestorInfoFromCertificate[scheme.RelyingPartyRequestor](cert); err == nil {
		return clientmodels.TrustSource_YiviTrustList, ""
	}
	return clientmodels.TrustSource_Other, issuerNameOf(cert)
}

// issuerNameOf is the display name of a certificate's issuer: its
// organization, or its common name when it has none.
func issuerNameOf(cert *x509.Certificate) string {
	if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
		return cert.Issuer.Organization[0]
	}
	return cert.Issuer.CommonName
}

// trustCertificateOf describes the end-entity certificate for the wallet's
// technical details.
func trustCertificateOf(cert *x509.Certificate) *clientmodels.TrustCertificate {
	return &clientmodels.TrustCertificate{
		Subject:  cert.Subject.String(),
		Issuer:   cert.Issuer.String(),
		NotAfter: cert.NotAfter.Unix(),
	}
}
