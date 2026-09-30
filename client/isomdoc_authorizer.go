package client

import (
	"crypto/x509"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/utils"
)

// ============================================================
// READER AUTHORIZATION OVER org-iso-mdoc
// ============================================================
//
// A relying party's entitlement to ask for a credential is recorded in the Yivi
// scheme extension of its certificate, and is a property of the relying party
// rather than of the transport it arrives on. OpenID4VP enforces it through
// RequestorCertificateStoreVerifierValidator; this is the same enforcement for a
// request that arrived over the Digital Credentials API as ISO 18013-5 CBOR.
//
// Without it, a reader refused online with "credential X is not in the
// authorized set" gets exactly what it asked for by sending the same
// certificate over org-iso-mdoc instead — which is a transport-shaped hole in an
// authorization rule that has nothing to do with transport.

// schemeReaderAuthorizer implements isomdoc.ReaderAuthorizer over the scheme
// extension, using the same validator factory the OpenID4VP path is built with
// so the two cannot drift.
type schemeReaderAuthorizer struct {
	validators openid4vp.QueryValidatorFactory
}

// AuthorizeReader reads the relying party out of the certificate and asks the
// scheme validator whether this docType and these elements are within its
// registration.
//
// A certificate with no scheme extension is refused. That is the same answer
// the OpenID4VP path gives — GetRequestorInfoFromCertificate treats a missing
// extension as a verification failure — and the safe one: an unregistered
// reader has an empty entitlement, not an unlimited one.
func (a schemeReaderAuthorizer) AuthorizeReader(
	certificate *x509.Certificate, docType string, elements []string,
) error {
	if certificate == nil {
		return fmt.Errorf("no reader certificate to read an authorization from")
	}

	requestor, err := utils.GetRequestorInfoFromCertificate[scheme.RelyingPartyRequestor](certificate)
	if err != nil {
		return err
	}

	// One credential query, shaped the way the scheme validator expects: the
	// docType for an mso_mdoc credential, and the data element identifiers. This
	// mirrors dcql.CredentialQueryInfos' mdoc case, which takes the last
	// component of each claim path — the element name — for exactly this check.
	return a.validators.
		CreateQueryValidator(&requestor.RelyingParty).
		ValidateCredentialQueries([]scheme.CredentialQueryInfo{{
			DocTypeValue:   docType,
			AttributeNames: elements,
		}})
}
