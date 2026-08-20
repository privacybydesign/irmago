// Package lote implements the recognized-list channel of the trust ladder: the
// wallet fetches Lists of Trusted Entities (LoTEs) that Yivi publishes, checks
// that they still hold, and answers whether a party is granted on one.
//
// A LoTE is an ETSI TS 119 602 scheme-explicit List of Trusted Entities in the
// Annex A JSON binding, signed as a compact JAdES-B-B whose `x5c` chain verifies
// against the pinned Yivi trust anchors. The types here mirror that binding
// verbatim: the JSON tags are the normative field names, and a Go name that
// differs from its tag does so for call-site readability only. See docs/adr/0004.
//
// The channel is fail-soft throughout: a list that cannot be fetched, does not
// verify, has expired, or has gone backwards is absent evidence. Parties then cap
// at low and the session proceeds. Nothing here can fail a session.
package lote

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust"
)

// LoTEVersion is the value this package emits in `LoTEVersionIdentifier`
// (clause 6.3.1). Not enforced on read: a later version whose fields still parse
// is more useful than a refusal.
const LoTEVersion = 1

// Yivi's own scheme URIs. Annex C.1 permits a scheme to mint its own; every URI
// registered in Annex C.2 is EU-specific and gated on a role Yivi does not hold.
//
// The root is provisional (docs/plans/lote-annex-a-publisher.md § Open items),
// but LoTEType is pinned by every wallet, so changing it after a release breaks
// them.
const (
	// LoTETypeRecognizedParties names the *type* of list, so staging and
	// production share it; the per-list identity is SchemeName.
	LoTETypeRecognizedParties = "https://yivi.app/19602/LoTEType/YiviRecognizedPartiesList"

	StatusDeterminationApproachYivi = "https://yivi.app/19602/YiviRecognizedPartiesList/StatusDetn/Yivi"
	SchemeTypeCommunityRulesYivi    = "https://yivi.app/19602/YiviRecognizedParties/schemerules/Yivi"
)

// ServiceTypeIdentifier is the role a grant is for (clause 6.6.1), as a URI.
// Optional in the schema, but clause 6.6.0 NOTE 2 reads an absent one as "all
// listed services are of the same type", so Yivi always emits it.
type ServiceTypeIdentifier string

const (
	ServiceTypeIssuer   ServiceTypeIdentifier = "https://yivi.app/19602/Svctype/Issuer"
	ServiceTypeVerifier ServiceTypeIdentifier = "https://yivi.app/19602/Svctype/Verifier"
)

// Role maps a service type onto the ladder's role. An unrecognized URI maps to no
// role, so a list naming one this wallet does not know grants nothing.
func (t ServiceTypeIdentifier) Role() (trust.Role, bool) {
	switch t {
	case ServiceTypeIssuer:
		return trust.RoleIssuer, true
	case ServiceTypeVerifier:
		return trust.RoleVerifier, true
	}
	return "", false
}

// ServiceTypeForRole is the inverse of [ServiceTypeIdentifier.Role].
func ServiceTypeForRole(role trust.Role) ServiceTypeIdentifier {
	switch role {
	case trust.RoleIssuer:
		return ServiceTypeIssuer
	case trust.RoleVerifier:
		return ServiceTypeVerifier
	}
	return ""
}

// ServiceStatus is the current status of a grant (clause 6.6.4), as a URI.
//
// An absent status means granted: clause 6.6.0 NOTE 1 gives all listed services
// one approval status when there is no historical information period. Yivi's list
// carries none and off-boards by removing the entry.
//
// A status that is present is honoured, but only a URI recognized here grants.
// Vocabularies are per-scheme (Annex H's Pub-EAA list spells granted
// differently), so another scheme's list will mean carrying its vocabulary on
// [Source].
type ServiceStatus string

const (
	ServiceStatusGranted   ServiceStatus = "https://yivi.app/19602/Svcstatus/Granted"
	ServiceStatusWithdrawn ServiceStatus = "https://yivi.app/19602/Svcstatus/Withdrawn"
)

// IsGranted reports whether this service is a live grant. Absent means granted;
// see [ServiceStatus].
func (si ServiceInformation) IsGranted() bool {
	if si.Status == "" {
		return true
	}
	return si.Status == ServiceStatusGranted
}

// organizationIdentifierOID is X.520 id-at-organizationIdentifier, the subject
// field an EU certificate carries the legal entity's registered identifier in.
// Go's pkix.Name has no field for it, so it is read out of Subject.Names.
var organizationIdentifierOID = asn1.ObjectIdentifier{2, 5, 4, 97}

// Document is the outermost Annex A object: a single `LoTE` member, and the
// binding forbids anything beside it.
type Document struct {
	LoTE List `json:"LoTE"`
}

// List is one parsed LoTE.
type List struct {
	SchemeInformation SchemeInformation `json:"ListAndSchemeInformation"`

	// Optional: a scheme with nothing listed yet still publishes a valid document.
	Entities []Entity `json:"TrustedEntitiesList,omitempty"`
}

// SchemeInformation is the list-level header (clause 6.3), carrying the tag
// `ListAndSchemeInformation`. Every field mandatory for explicit scheme
// information (Table 1) is non-optional here: Annex A binds only the
// scheme-explicit form.
type SchemeInformation struct {
	// See [LoTEVersion].
	LoTEVersionIdentifier int `json:"LoTEVersionIdentifier"`

	// SequenceNumber is `LoTESequenceNumber` (clause 6.3.2), incremented on every
	// re-issue. The wallet refuses a lower number than the one it holds, so an
	// older list cannot be replayed over a newer one.
	SequenceNumber uint64 `json:"LoTESequenceNumber"`

	// LoTEType names the kind of list (clause 6.3.3). Pinned by the wallet, but
	// not the list's identity: staging and production lists share it.
	LoTEType string `json:"LoTEType"`

	// SchemeOperatorName is clause 6.3.4. Load-bearing: clause 6.8.0 requires the
	// signing certificate's subject `Organization` to match one of these values.
	SchemeOperatorName MultiLang `json:"SchemeOperatorName"`

	SchemeOperatorAddress SchemeOperatorAddress `json:"SchemeOperatorAddress"`

	// SchemeName (clause 6.3.6) is this list's identity: the wallet stores the list
	// under it and refuses a document declaring another, so it must be stable
	// across re-issues and equal the source's `ListId`. Prescribed format:
	// `CC:EN_name_value` for English, `CC:name_value` otherwise, CC being
	// [SchemeTerritory].
	SchemeName MultiLang `json:"SchemeName"`

	SchemeInformationURI        MultiLangURI `json:"SchemeInformationURI"`
	StatusDeterminationApproach string       `json:"StatusDeterminationApproach"`
	SchemeTypeCommunityRules    MultiLangURI `json:"SchemeTypeCommunityRules"`

	// SchemeTerritory is clause 6.3.10. Load-bearing: clause 6.8.0 requires the
	// signing certificate's subject `Country` to match it, and [SchemeName]'s
	// prescribed format embeds it.
	SchemeTerritory string `json:"SchemeTerritory"`

	// Clause 6.3.11. The binding's `oneOf` requires every element to be the same
	// kind, which is validated at build time.
	PolicyOrLegalNotice []PolicyOrLegalNotice `json:"PolicyOrLegalNotice"`

	// Clause 6.3.14. Recorded, not enforced: the wallet gates on NextUpdate.
	ListIssueDateTime time.Time `json:"ListIssueDateTime"`

	// NextUpdate is when the list stops being current (clause 6.3.15). Past it the
	// list is no evidence at all, so every party it granted falls back to the
	// other channels.
	NextUpdate time.Time `json:"NextUpdate"`

	// Clause 6.3.16, carried for round-tripping: the wallet fetches the URL its
	// source configures.
	DistributionPoints []string `json:"DistributionPoints,omitempty"`

	// HistoricalInformationPeriod (clause 6.3.12) is not modelled: Yivi keeps no
	// service history. Its absence is why ServiceStatus is always emitted — see
	// [ServiceStatus].
}

// On the data, so the fetch and evaluation paths cannot spell the same time bound
// two ways.
func (si SchemeInformation) current(now time.Time) bool {
	return now.Add(-ClockSkew).Before(si.NextUpdate)
}

// Identity is the list's identity as the wallet pins it: SchemeName's English
// entry, the one language clause 6.3.6 prescribes a format for.
func (si SchemeInformation) Identity() string {
	return clientmodels.TranslatedString(si.SchemeName)["en"]
}

// PolicyOrLegalNotice is one element of clause 6.3.11: either a URI pointing at
// the scheme's policy or the text of a legal notice. Exactly one is set.
type PolicyOrLegalNotice struct {
	LoTEPolicy      *MultiLangURIEntry `json:"LoTEPolicy,omitempty"`
	LoTELegalNotice string             `json:"LoTELegalNotice,omitempty"`
}

// SchemeOperatorAddress is clause 6.3.5. Both members are mandatory. Its property
// names differ from [TEAddress]'s despite the identical shape, so the two cannot
// share a type.
type SchemeOperatorAddress struct {
	PostalAddress     []PostalAddress     `json:"SchemeOperatorPostalAddress"`
	ElectronicAddress []MultiLangURIEntry `json:"SchemeOperatorElectronicAddress"`
}

// Entity is a listed organization (clause 6.4.1), carrying the tag
// `TrustedEntity`.
type Entity struct {
	Information EntityInformation `json:"TrustedEntityInformation"`

	// One grant per role the entity was granted for.
	Services []Service `json:"TrustedEntityServices"`
}

// EntityInformation is who a listed organization is (clause 6.5), carrying the
// tag `TrustedEntityInformation`. TEName, TEAddress and TEInformationURI are all
// mandatory (clause 6.5.0).
type EntityInformation struct {
	// TEName (clause 6.5.1): the curated display name, shown in preference to
	// anything the party asserts about itself.
	Name MultiLang `json:"TEName"`

	TradeName MultiLang `json:"TETradeName,omitempty"`

	// Address and InformationURI are mandatory but unread by the wallet: they
	// exist because the binding requires them.
	Address        TEAddress    `json:"TEAddress"`
	InformationURI MultiLangURI `json:"TEInformationURI"`

	Extensions []YiviExtension `json:"TEInformationExtensions,omitempty"`
}

// TEAddress is clause 6.5.3. Both members are mandatory.
type TEAddress struct {
	PostalAddress     []PostalAddress     `json:"TEPostalAddress"`
	ElectronicAddress []MultiLangURIEntry `json:"TEElectronicAddress"`
}

type PostalAddress struct {
	Lang            string `json:"lang"`
	StreetAddress   string `json:"StreetAddress"`
	Locality        string `json:"Locality,omitempty"`
	StateOrProvince string `json:"StateOrProvince,omitempty"`
	PostalCode      string `json:"PostalCode,omitempty"`
	Country         string `json:"Country"`
}

// Service is one grant (clause 6.4.3), carrying the tag `TrustedEntityService`:
// this entity, in this role, with this identity, in this state. ServiceHistory
// (clause 6.4.4) is not modelled; Yivi retains no history.
type Service struct {
	Information ServiceInformation `json:"ServiceInformation"`
}

// ServiceInformation is what a grant says (clause 6.6), carrying the tag
// `ServiceInformation`. ServiceName and ServiceDigitalIdentity are mandatory
// (clause 6.6.0).
type ServiceInformation struct {
	// ServiceName (clause 6.6.2), mandatory: a service presented under its own
	// brand says so here, one that is not repeats the entity's name.
	Name MultiLang `json:"ServiceName"`

	DigitalIdentity DigitalIdentity `json:"ServiceDigitalIdentity"`

	// Clause 6.6.1: issuing and verifying are separate grants. See
	// [ServiceTypeIdentifier].
	Type ServiceTypeIdentifier `json:"ServiceTypeIdentifier"`

	// Clause 6.6.4. Absent means granted, and Yivi's own list omits it; see
	// [ServiceStatus].
	Status ServiceStatus `json:"ServiceStatus,omitempty"`

	Extensions []YiviExtension `json:"ServiceInformationExtensions,omitempty"`
}

// DigitalIdentity is the set of identities a service may be recognized by
// (clause 6.6.3). A party matches the service when it matches any one of them.
// Every member is a sequence, since one service may legitimately be recognized by
// several certificates or keys.
type DigitalIdentity struct {
	X509Certificates []PKIObject `json:"X509Certificates,omitempty"`

	// X509SKIs are subject key identifiers, for entries naming the key rather than
	// a certificate carrying it, so a renewal needs no re-issue of the list.
	X509SKIs [][]byte `json:"X509SKIs,omitempty"`

	// OtherIds are identities that are not X.509 — where a DID lands. The binding
	// makes these bare strings, compared verbatim (DIDs are case-sensitive beyond
	// the scheme), so the kind of identifier is not expressible.
	OtherIds []string `json:"OtherIds,omitempty"`

	// X509SubjectNames is part of the binding but not matched on: weaker than the
	// key material already covered.
	X509SubjectNames []string `json:"X509SubjectNames,omitempty"`
}

// PKIObject is the binding's `pkiOb`. Go marshals a []byte as standard padded
// base64, which is what `contentEncoding: base64` asks for. The optional
// `encoding` and `specRef` hints are not modelled.
type PKIObject struct {
	Val []byte `json:"val"`
}

// YiviExtension carries the members Yivi needs and Annex A has no field for; the
// binding's extension arrays are untyped, which makes this legal. Exactly one
// member is set per element, so an unknown extension is simply ignored.
//
// Holding OrganizationIdentifier here is provisional — it is half the key a
// certificate entry is matched on. See docs/plans/lote-annex-a-publisher.md
// § Open items.
type YiviExtension struct {
	// OrganizationIdentifier is the entity's registered identifier in the form its
	// certificates carry in the subject's `organizationIdentifier` attribute (e.g.
	// "VATNL-123456789"). Set on a TEInformationExtensions element only.
	OrganizationIdentifier string `json:"YiviOrganizationIdentifier,omitempty"`

	// LogoURI is the curated logo: the entity's on a TEInformationExtensions
	// element, a per-service override on a ServiceInformationExtensions one.
	LogoURI string `json:"YiviLogoURI,omitempty"`

	// Marking is one scheme-specific qualifier on a grant. Carried for
	// round-tripping but not acted on: the rung a grant confers is the source's,
	// never the entry's.
	Marking string `json:"YiviMarking,omitempty"`
}

// OrganizationIdentifier returns the entity's registered identifier, or "" when
// the entry is keyed on the certificate alone.
func (ei EntityInformation) OrganizationIdentifier() string {
	for _, ext := range ei.Extensions {
		if ext.OrganizationIdentifier != "" {
			return ext.OrganizationIdentifier
		}
	}
	return ""
}

// LogoURI returns the first logo an extension carries, or "" when none does.
func (ei EntityInformation) LogoURI() string {
	for _, ext := range ei.Extensions {
		if ext.LogoURI != "" {
			return ext.LogoURI
		}
	}
	return ""
}

// LogoURI returns the service-level logo override, or "" when none is set.
func (si ServiceInformation) LogoURI() string {
	for _, ext := range si.Extensions {
		if ext.LogoURI != "" {
			return ext.LogoURI
		}
	}
	return ""
}

// Markings returns the qualifiers on this grant, in document order.
func (si ServiceInformation) Markings() []string {
	var markings []string
	for _, ext := range si.Extensions {
		if ext.Marking != "" {
			markings = append(markings, ext.Marking)
		}
	}
	return markings
}

// MultiLang is a sequence of multilingual character strings (clause 6.1.4). On
// the wire `[{"lang":…,"value":…}]`; in Go the same language map the rest of the
// wallet resolves display text from.
type MultiLang clientmodels.TranslatedString

type multiLangEntry struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// MarshalJSON emits the entries sorted by language. The golden fixture is
// compared byte-for-byte and the refresh path diffs marshalled entities, so map
// iteration order would manufacture spurious changes.
func (m MultiLang) MarshalJSON() ([]byte, error) {
	entries := make([]multiLangEntry, 0, len(m))
	for _, lang := range slices.Sorted(maps.Keys(m)) {
		entries = append(entries, multiLangEntry{Lang: lang, Value: m[lang]})
	}
	return json.Marshal(entries)
}

func (m *MultiLang) UnmarshalJSON(raw []byte) error {
	var entries []multiLangEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return err
	}
	out := make(MultiLang, len(entries))
	for _, entry := range entries {
		if entry.Lang == "" {
			return fmt.Errorf("multilingual string has an entry without a language")
		}
		out[entry.Lang] = entry.Value
	}
	*m = out
	return nil
}

// Translated exposes the map as the type the rest of the wallet uses.
func (m MultiLang) Translated() clientmodels.TranslatedString {
	return clientmodels.TranslatedString(m)
}

// MultiLangURI is a sequence of non-empty multilingual URIs (the binding's
// `NonEmptyMultiLangURI`). Same map shape as [MultiLang], but its wire member is
// `uriValue` rather than `value`, so it cannot be an alias.
type MultiLangURI clientmodels.TranslatedString

// MultiLangURIEntry is a single `{lang,uriValue}` object, for the places the
// binding takes one rather than a sequence.
type MultiLangURIEntry struct {
	Lang     string `json:"lang"`
	URIValue string `json:"uriValue"`
}

func (m MultiLangURI) MarshalJSON() ([]byte, error) {
	entries := make([]MultiLangURIEntry, 0, len(m))
	for _, lang := range slices.Sorted(maps.Keys(m)) {
		entries = append(entries, MultiLangURIEntry{Lang: lang, URIValue: m[lang]})
	}
	return json.Marshal(entries)
}

func (m *MultiLangURI) UnmarshalJSON(raw []byte) error {
	var entries []MultiLangURIEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return err
	}
	out := make(MultiLangURI, len(entries))
	for _, entry := range entries {
		if entry.Lang == "" {
			return fmt.Errorf("multilingual URI has an entry without a language")
		}
		out[entry.Lang] = entry.URIValue
	}
	*m = out
	return nil
}

// CertificateOrganizationIdentifier returns the subject's
// `organizationIdentifier` attribute, or "" when the certificate carries none.
// Exported so whoever builds a list entry keys it the way this matcher reads it.
func CertificateOrganizationIdentifier(cert *x509.Certificate) string {
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
