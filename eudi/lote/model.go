package lote

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// List is the content of a LoTE: a scheme header plus the providers it vouches
// for. It is the JSON payload of the signed list, in the shape of
// ETSI TS 119 602.
type List struct {
	SchemeInformation SchemeInformation      `json:"schemeInformation"`
	Providers         []TrustServiceProvider `json:"trustServiceProviders"`
}

// SchemeInformation is the list's own header: which list this is, which
// revision of it, and how long it may be believed.
type SchemeInformation struct {
	// ListIdentifier names the list. It must equal the identifier the wallet
	// recognizes the list under (RecognizedList.Id).
	ListIdentifier string `json:"listIdentifier"`
	// SequenceNumber increases with every published revision. A copy whose
	// number is below the one already stored is a rollback and is discarded.
	SequenceNumber int64 `json:"sequenceNumber"`
	// IssueDateTime is when this revision was published. Informational: the
	// wallet decides on NextUpdate.
	IssueDateTime time.Time `json:"issueDateTime"`
	// NextUpdate is when this revision stops being believed. A list past it is
	// absent evidence, not stale evidence.
	NextUpdate time.Time `json:"nextUpdate"`
}

// TrustServiceProvider is one organization on the list, with the services it is
// trusted for.
type TrustServiceProvider struct {
	// Name is the curated name of the organization, per language.
	Name clientmodels.TranslatedString `json:"name"`
	// OrganizationIdentifier is the provider's legal organization identifier
	// (ETSI EN 319 412-1 semantics, e.g. "NTRNL-12345678"). It matches the
	// organizationIdentifier attribute of a certificate's subject, which is
	// the coarsest of the three certificate keys: it recognizes the
	// organization rather than one particular certificate, so a re-keyed party
	// keeps its rung.
	OrganizationIdentifier string `json:"organizationIdentifier,omitempty"`
	// Services are the role-typed grants. A provider trusted to issue is not
	// thereby trusted to verify.
	Services []Service `json:"services"`
}

// Service is one role-typed grant: this party, in this capacity, with this
// status.
type Service struct {
	// Type is the capacity granted: ServiceTypeIssuer or ServiceTypeVerifier.
	// An entry of any other type vouches for nothing the wallet asks about.
	Type string `json:"typeIdentifier"`
	// Status is the grant's state; only StatusGranted vouches for the party.
	Status string `json:"status"`
	// Name is the curated display name for this service, which overrides the
	// provider's name when set.
	Name clientmodels.TranslatedString `json:"name,omitempty"`
	// LogoURI is the curated logo. Attested by the list, so unlike a
	// self-asserted logo it may be rendered.
	LogoURI string `json:"logoUri,omitempty"`
	// Identities are the ways this party authenticates. Any one of them
	// matching identifies the party as this entry.
	Identities []DigitalIdentity `json:"digitalIdentities"`
	// AdditionalInformation carries the profile's qualifiers, such as
	// QualifierOnboardedByYivi.
	AdditionalInformation []string `json:"additionalServiceInformation,omitempty"`
}

// DigitalIdentity is one way the party on this entry authenticates itself:
// a certificate, that certificate's subject key identifier, or an identifier in
// another space (a DID, an issuer URL).
type DigitalIdentity struct {
	// X509Certificate is the base64-encoded DER of the party's end-entity
	// certificate.
	X509Certificate string `json:"x509Certificate,omitempty"`
	// X509Ski is the base64-encoded subject key identifier of that
	// certificate, for entries that want to survive a re-issue of the same key.
	X509Ski string `json:"x509Ski,omitempty"`
	// OtherId is an identifier outside X.509; see the OtherIdType constants.
	OtherId *OtherId `json:"otherId,omitempty"`
}

// OtherId is an identifier and the space it lives in.
type OtherId struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// organizationIdentifierOid is the X.520 id-at-organizationIdentifier
// attribute. Go's pkix.Name does not decode it into a field of its own, so it
// has to be read out of the raw subject attributes.
var organizationIdentifierOid = asn1.ObjectIdentifier{2, 5, 4, 97}

// parseList decodes and sanity-checks a list payload. It rejects a payload that
// cannot be believed at all: one without an identifier to bind to a recognized
// list, or without a NextUpdate to bound how long it counts.
func parseList(payload []byte) (*List, error) {
	var list List
	if err := json.Unmarshal(payload, &list); err != nil {
		return nil, fmt.Errorf("failed to decode trust list: %v", err)
	}
	if list.SchemeInformation.ListIdentifier == "" {
		return nil, fmt.Errorf("trust list carries no listIdentifier")
	}
	if list.SchemeInformation.NextUpdate.IsZero() {
		return nil, fmt.Errorf("trust list carries no nextUpdate")
	}
	return &list, nil
}

// certificateDer returns the identity's certificate in DER form, or nil when it
// names none or names one that does not decode.
func (id DigitalIdentity) certificateDer() []byte {
	if id.X509Certificate == "" {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(id.X509Certificate)
	if err != nil {
		return nil
	}
	return der
}

// ski returns the identity's subject key identifier, or nil when it names none
// or names one that does not decode.
func (id DigitalIdentity) ski() []byte {
	if id.X509Ski == "" {
		return nil
	}
	ski, err := base64.StdEncoding.DecodeString(id.X509Ski)
	if err != nil {
		return nil
	}
	return ski
}

// organizationIdentifier reads the organizationIdentifier attribute out of a
// certificate's subject, or returns "" when the subject carries none.
func organizationIdentifier(cert *x509.Certificate) string {
	for _, attr := range cert.Subject.Names {
		if !attr.Type.Equal(organizationIdentifierOid) {
			continue
		}
		if value, ok := attr.Value.(string); ok {
			return value
		}
	}
	return ""
}
