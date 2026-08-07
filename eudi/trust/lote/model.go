// Package lote implements the recognized-list channel of the trust ladder: the
// wallet fetches Lists of Trusted Entities (LoTEs) that Yivi publishes, checks
// that they still hold, and answers whether a party is granted on one.
//
// A LoTE is an ETSI TS 119 602 trusted list in its JSON representation, signed
// as a compact JAdES-B-B — a JWS whose `x5c` chain verifies against the pinned
// Yivi trust anchors. TS 119 602 leaves the concrete field names of a profile
// to the scheme operator; the shapes in this file are Yivi's profile of the
// data model, and the doc comments name the TS 119 612 element each one stands
// in for so the two can be read side by side.
//
// The channel is fail-soft throughout, which is the whole reason it is a
// separate package from the evaluation seam: a list that cannot be fetched,
// does not verify, has expired, or has gone backwards is simply absent
// evidence. Parties then cap at low and the session proceeds. Nothing in this
// package can fail a session.
package lote

import (
	"crypto/x509"
	"encoding/asn1"
	"slices"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust"
)

// ServiceStatus is the current status of a grant (TS 119 612 `ServiceStatus`).
// Only granted counts; every other value, known or not, reads as no grant.
type ServiceStatus string

const (
	ServiceStatusGranted   ServiceStatus = "granted"
	ServiceStatusWithdrawn ServiceStatus = "withdrawn"
)

// MarkingOnboardedByYivi marks a service Yivi itself vouches for, and is the
// one marking the wallet knows about. It is meaningful only on Yivi's own list;
// see [Source.OperatedByYivi].
const MarkingOnboardedByYivi = "onboarded-by-yivi"

// organizationIdentifierOID is the X.520 `organizationIdentifier` attribute
// (id-at-organizationIdentifier, 2.5.4.97) — the subject field an EU
// certificate carries the legal entity's registered identifier in. Go's
// pkix.Name has no field for it, so it is read out of Subject.Names.
var organizationIdentifierOID = asn1.ObjectIdentifier{2, 5, 4, 97}

// List is one parsed LoTE: the scheme's own information plus the entities it
// lists.
type List struct {
	SchemeInformation SchemeInformation `json:"scheme_information"`
	Entities          []Entity          `json:"entities"`
}

// SchemeInformation is the list-level header (TS 119 612 `SchemeInformation`).
type SchemeInformation struct {
	// ListIdentifier names the list. It is the identity the wallet stores the
	// list under and the one a Listing reports, so it must be stable across
	// re-issues of the same list.
	ListIdentifier string `json:"list_identifier"`

	// SequenceNumber is TS 119 612 `TSLSequenceNumber`: a counter the scheme
	// operator increments on every re-issue. The wallet refuses a fetched list
	// whose number is lower than the one it already holds, so a captured older
	// list cannot be replayed over a newer one.
	SequenceNumber uint64 `json:"sequence_number"`

	// ListIssueDateTime is when this issue of the list was signed
	// (TS 119 612 `ListIssueDateTime`). Recorded, not enforced: the wallet
	// gates on NextUpdate, which is the operator's own statement of how long
	// the content may be relied on.
	ListIssueDateTime time.Time `json:"list_issue_date_time"`

	// NextUpdate is when the list stops being current (TS 119 612
	// `NextUpdate`). Past it the list is no evidence at all — not stale
	// evidence — so every party it granted falls back to whatever the other
	// channels say.
	NextUpdate time.Time `json:"next_update"`
}

// Entity is a listed organization (TS 119 612 `TrustServiceProvider`): who it
// is, plus the grants it holds.
type Entity struct {
	// OrganizationIdentifier is the entity's registered identifier, in the same
	// form its certificates carry in the subject's `organizationIdentifier`
	// attribute (e.g. "VATNL-123456789"). It is half of the key a certificate
	// entry is matched on: the certificate says which key, this says which
	// legal entity, and a match needs both. Empty means the entry is keyed on
	// the certificate alone.
	OrganizationIdentifier string `json:"organization_identifier,omitempty"`

	// Name is the curated display name of the entity, per language. This is
	// what a listed party is shown as, in preference to anything it asserts
	// about itself.
	Name clientmodels.TranslatedString `json:"name"`

	// LogoURI is the curated logo, empty when the entry carries none.
	LogoURI string `json:"logo_uri,omitempty"`

	// Services are the entity's grants, one per role it was granted for.
	Services []Service `json:"services"`
}

// Service is one grant (TS 119 612 `TSPService`): this entity, in this role,
// with this identity, in this state.
type Service struct {
	// Type is the role the grant is for: trust as an issuer and trust as a
	// verifier are separate grants, so an entity listed to issue credentials is
	// not thereby listed to ask for them. An unknown value matches no role.
	//
	// It is [trust.Role] rather than a type of its own because the wire values
	// are the ladder's own role names; a second type would only be those same
	// two strings, needing a mapping that could drift.
	Type trust.Role `json:"type"`

	// Status is the state of the grant. Anything other than granted is no
	// grant — a withdrawn service is listed so the withdrawal is visible, not
	// so it still counts.
	Status ServiceStatus `json:"status"`

	// DigitalIdentity is how a party proves it is this service.
	DigitalIdentity DigitalIdentity `json:"digital_identity"`

	// Name overrides the entity's name for this service, when a service is
	// presented under a different name from its operator. Empty falls back to
	// the entity's name.
	Name clientmodels.TranslatedString `json:"name,omitempty"`

	// LogoURI overrides the entity's logo for this service. Empty falls back to
	// the entity's logo.
	LogoURI string `json:"logo_uri,omitempty"`

	// Markings are the scheme-specific qualifiers on this grant
	// (TS 119 612 `AdditionalServiceInformation`). The wallet knows one,
	// [MarkingOnboardedByYivi]; the rest are carried but not acted on.
	Markings []string `json:"markings,omitempty"`
}

// HasMarking reports whether the service carries the given marking.
func (s *Service) HasMarking(marking string) bool {
	return slices.Contains(s.Markings, marking)
}

// DigitalIdentity is the set of identities a service may be recognized by
// (TS 119 612 `ServiceDigitalIdentity`). A party matches the service when it
// matches any one of them.
type DigitalIdentity struct {
	// X509Certificate is the DER of the service's certificate.
	X509Certificate []byte `json:"x509_certificate,omitempty"`

	// X509SKI is the subject key identifier of the service's certificate, for
	// entries that name the key rather than one certificate carrying it — so a
	// certificate renewal does not need a re-issue of the list.
	X509SKI []byte `json:"x509_ski,omitempty"`

	// OtherIds are identities that are not X.509. This is where a DID lands:
	// the convention is one entry with type "did" per DID, value the DID
	// string exactly as the party presents it, compared verbatim (DIDs are
	// case-sensitive beyond the scheme, so no normalization is applied).
	OtherIds []OtherId `json:"other_ids,omitempty"`
}

// OtherId is a non-X.509 identity (TS 119 612 `ServiceDigitalIdentity/Other`).
type OtherId struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// OtherIdTypeDid is the OtherId type a DID is carried under.
const OtherIdTypeDid = "did"

// certificateOrganizationIdentifier returns the subject's
// `organizationIdentifier` attribute, or "" when the certificate carries none.
func certificateOrganizationIdentifier(cert *x509.Certificate) string {
	for _, attr := range cert.Subject.Names {
		if !attr.Type.Equal(organizationIdentifierOID) {
			continue
		}
		if s, ok := attr.Value.(string); ok {
			return s
		}
	}
	return ""
}
