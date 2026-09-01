// Package lote implements the recognized-list channel of the trust ladder: the
// wallet fetches Lists of Trusted Entities (LoTEs) that Yivi publishes, checks
// that they still hold, and answers whether a party is granted on one.
//
// A LoTE is an ETSI TS 119 602 scheme-explicit List of Trusted Entities in the
// Annex A JSON binding, signed as a compact JAdES-B-B whose `x5c` chain verifies
// against the pinned Yivi trust anchors. The types here mirror that binding
// verbatim: the JSON tags are the normative field names.
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
// The root is provisional, but LoTEType is pinned by every wallet, so changing it
// after a release breaks them.
const (
	// LoTETypeRecognizedParties names the *type* of list, so staging and
	// production share it; the per-list identity is SchemeName.
	LoTETypeRecognizedParties = "https://yivi.app/19602/LoTEType/YiviRecognizedPartiesList"

	// LoTETypeTrustAnchors names the anchor list: a LoTE whose services are CAs the
	// wallet installs as trust anchors, rather than parties it matches. A separate
	// document from the party list because a CA entry delegates — one entry
	// vouches for every certificate the CA issues — and so gets its own signer,
	// review path and cadence. A Source pins one type or the other; a document of
	// one type served at a source of the other is refused.
	LoTETypeTrustAnchors = "https://yivi.app/19602/LoTEType/YiviTrustAnchorsList"

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

	// The anchor service types: a CA whose certificates identify parties in the
	// role. The wallet installs such a service's certificate as a trust anchor in
	// that role's pool instead of matching parties against it. Role-typed like the
	// party types, because the wallet keeps one anchor pool per role — which is
	// why 119 612's Svctype/CA/PKC, conventional as it is, is not reused: it
	// carries no role.
	ServiceTypeIssuerCA   ServiceTypeIdentifier = "https://yivi.app/19602/Svctype/IssuerCA"
	ServiceTypeVerifierCA ServiceTypeIdentifier = "https://yivi.app/19602/Svctype/VerifierCA"
)

// Role maps a service type onto the ladder's role, for party lookups. An
// unrecognized URI maps to no role, so a list naming one this wallet does not
// know grants nothing. An anchor type maps to no party role either: a CA is not a
// party, and a party lookup must never match one.
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

// AnchorRole maps an anchor service type onto the role whose anchor pool the
// service's certificate belongs in. A party type, or an unknown URI, is no anchor.
func (t ServiceTypeIdentifier) AnchorRole() (trust.Role, bool) {
	switch t {
	case ServiceTypeIssuerCA:
		return trust.RoleIssuer, true
	case ServiceTypeVerifierCA:
		return trust.RoleVerifier, true
	}
	return "", false
}

// AnchorServiceTypeForRole is the inverse of [ServiceTypeIdentifier.AnchorRole].
func AnchorServiceTypeForRole(role trust.Role) ServiceTypeIdentifier {
	switch role {
	case trust.RoleIssuer:
		return ServiceTypeIssuerCA
	case trust.RoleVerifier:
		return ServiceTypeVerifierCA
	}
	return ""
}

// SupplyPointTypeCRL is the ServiceType of a supply point (clause 6.6, the
// binding's ServiceSupplyPoints) at which the CRLs a CA issues are published. A
// CA certificate's own CRL extension says where the CA gets revoked, not where
// it revokes its leaves, so an anchor list has to say the latter itself.
const SupplyPointTypeCRL = "https://yivi.app/19602/SvcSupplyPoint/CRL"

// ServiceSupplyPoint is one entry of the binding's ServiceSupplyPoints: a typed
// URI at which the service supplies something — for an anchor, its CRLs.
type ServiceSupplyPoint struct {
	ServiceType string `json:"ServiceType"`
	URIValue    string `json:"uriValue"`
}

// ServiceStatus is the current status of a grant (clause 6.6.4), as a URI.
//
// An absent status means granted: clause 6.6.0 NOTE 1 gives all listed services
// one approval status when there is no historical information period. Yivi's list
// carries none and off-boards by removing the entry.
//
// A present status is honoured, but only a URI recognized here grants:
// vocabularies are per-scheme, so another scheme's list means carrying its
// vocabulary on [Source].
type ServiceStatus string

const (
	ServiceStatusGranted   ServiceStatus = "https://yivi.app/19602/Svcstatus/Granted"
	ServiceStatusWithdrawn ServiceStatus = "https://yivi.app/19602/Svcstatus/Withdrawn"
)

// IsGranted reports whether this service is a live grant. See [ServiceStatus].
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

// SchemeInformation is the list-level header (clause 6.3). Every field mandatory
// for explicit scheme information (Table 1) is non-optional here: Annex A binds
// only the scheme-explicit form.
type SchemeInformation struct {
	LoTEVersionIdentifier int `json:"LoTEVersionIdentifier"`

	// SequenceNumber is `LoTESequenceNumber` (clause 6.3.2), incremented on every
	// re-issue. The wallet refuses a lower number than the one it holds, so an
	// older list cannot be replayed over a newer one.
	SequenceNumber uint64 `json:"LoTESequenceNumber"`

	// LoTEType names the kind of list (clause 6.3.3), not the list's identity:
	// staging and production share it.
	LoTEType string `json:"LoTEType"`

	// SchemeOperatorName is clause 6.3.4. Load-bearing: clause 6.8.0 requires the
	// signing certificate's subject `Organization` to match one of these values.
	SchemeOperatorName MultiLang `json:"SchemeOperatorName"`

	SchemeOperatorAddress SchemeOperatorAddress `json:"SchemeOperatorAddress"`

	// SchemeName (clause 6.3.6) is this list's identity: the wallet stores the list
	// under it and refuses a document declaring another, so it must be stable across
	// re-issues and equal the source's `ListId`. Format is `CC:name`, CC being
	// [SchemeTerritory].
	//
	// Only the `en` entry carries that identity — the one language clause 6.3.6
	// prescribes a format for — so every comparison reads `SchemeName["en"]`.
	SchemeName MultiLang `json:"SchemeName"`

	SchemeInformationURI        MultiLangURI `json:"SchemeInformationURI"`
	StatusDeterminationApproach string       `json:"StatusDeterminationApproach"`
	SchemeTypeCommunityRules    MultiLangURI `json:"SchemeTypeCommunityRules"`

	// SchemeTerritory is clause 6.3.10. Load-bearing: clause 6.8.0 requires the
	// signing certificate's subject `Country` to match it, and [SchemeName]'s
	// prescribed format embeds it.
	SchemeTerritory string `json:"SchemeTerritory"`

	// Clause 6.3.11. The binding's `oneOf` requires every element to be the same
	// kind, validated at build time.
	PolicyOrLegalNotice []PolicyOrLegalNotice `json:"PolicyOrLegalNotice"`

	// Clause 6.3.14. Recorded, not enforced: the wallet gates on NextUpdate.
	ListIssueDateTime time.Time `json:"ListIssueDateTime"`

	// NextUpdate is when the list stops being current (clause 6.3.15). Past it the
	// list is no evidence, so every party it granted falls back to the other
	// channels.
	NextUpdate time.Time `json:"NextUpdate"`

	// Clause 6.3.16, carried for round-tripping: the wallet fetches its source's URL.
	DistributionPoints []string `json:"DistributionPoints,omitempty"`

	// HistoricalInformationPeriod (clause 6.3.12) is not modelled: Yivi keeps no
	// service history, which is why ServiceStatus is always emitted.
}

// On the data, so the fetch and evaluation paths cannot spell the same time bound
// two ways.
func (si SchemeInformation) current(now time.Time) bool {
	return now.Add(-ClockSkew).Before(si.NextUpdate)
}

// PolicyOrLegalNotice is one element of clause 6.3.11: either a URI pointing at
// the scheme's policy or the text of a legal notice. Exactly one is set.
type PolicyOrLegalNotice struct {
	LoTEPolicy      *MultiLangURIEntry `json:"LoTEPolicy,omitempty"`
	LoTELegalNotice string             `json:"LoTELegalNotice,omitempty"`
}

// SchemeOperatorAddress is clause 6.3.5. Its property names differ from
// [TEAddress]'s despite the identical shape, so the two cannot share a type.
type SchemeOperatorAddress struct {
	PostalAddress     []PostalAddress     `json:"SchemeOperatorPostalAddress"`
	ElectronicAddress []MultiLangURIEntry `json:"SchemeOperatorElectronicAddress"`
}

// Entity is a listed organization (clause 6.4.1).
type Entity struct {
	Information EntityInformation `json:"TrustedEntityInformation"`

	// One grant per role the entity was granted for.
	Services []Service `json:"TrustedEntityServices"`
}

// EntityInformation is who a listed organization is (clause 6.5).
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

// TEAddress is clause 6.5.3.
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

// Service is one grant (clause 6.4.3): this entity, in this role, with this
// identity, in this state. ServiceHistory (clause 6.4.4) is not modelled.
type Service struct {
	Information ServiceInformation `json:"ServiceInformation"`
}

// ServiceInformation is what a grant says (clause 6.6).
type ServiceInformation struct {
	// ServiceName (clause 6.6.2): a service presented under its own brand says so
	// here, one that is not repeats the entity's name.
	Name MultiLang `json:"ServiceName"`

	DigitalIdentity DigitalIdentity `json:"ServiceDigitalIdentity"`

	// Clause 6.6.1: issuing and verifying are separate grants.
	Type ServiceTypeIdentifier `json:"ServiceTypeIdentifier"`

	// Clause 6.6.4. Absent means granted; see [ServiceStatus].
	Status ServiceStatus `json:"ServiceStatus,omitempty"`

	// SupplyPoints is where the service supplies things; on an anchor service, the
	// CRLs the CA issues. See [SupplyPointTypeCRL].
	SupplyPoints []ServiceSupplyPoint `json:"ServiceSupplyPoints,omitempty"`

	Extensions []YiviExtension `json:"ServiceInformationExtensions,omitempty"`
}

// IsAnchor reports whether this service is a CA the wallet installs as a trust
// anchor rather than a party it matches.
func (si ServiceInformation) IsAnchor() bool {
	_, ok := si.Type.AnchorRole()
	return ok
}

// Confers is the level an anchor service's CA passes on to the certificates under
// it, as the entry states it: medium when it states nothing. What the wallet
// actually installs is this capped by the source's ceiling — an entry cannot
// promote itself past what its list may confer.
//
// A deliberate departure from "the rung is the source's word, never the entry's",
// which holds for parties because being listed means one thing. A CA has two
// states Yivi wants to tell apart, anchored and under contract, and promotion has
// to be a change to data.
func (si ServiceInformation) Confers() clientmodels.TrustLevel {
	for _, ext := range si.Extensions {
		if ext.Confers != clientmodels.TrustLevel_Unevaluated {
			return ext.Confers
		}
	}
	return clientmodels.TrustLevel_Medium
}

// CRLDistributionPoints returns the CRL supply points of an anchor service: where
// the CRLs its CA issues are published.
func (si ServiceInformation) CRLDistributionPoints() []string {
	var points []string
	for _, point := range si.SupplyPoints {
		if point.ServiceType == SupplyPointTypeCRL && point.URIValue != "" {
			points = append(points, point.URIValue)
		}
	}
	return points
}

// DigitalIdentity is the set of identities a service may be recognized by
// (clause 6.6.3). A party matches when it matches any one of them; every member is
// a sequence, since one service may be recognized by several keys.
type DigitalIdentity struct {
	X509Certificates []PKIObject `json:"X509Certificates,omitempty"`

	// X509SKIs are subject key identifiers, for entries naming the key rather than
	// a certificate carrying it, so a renewal needs no re-issue of the list.
	X509SKIs [][]byte `json:"X509SKIs,omitempty"`

	// OtherIds are identities that are not X.509 — where a DID lands. Bare strings
	// in the binding, compared verbatim, so the kind of identifier is inexpressible.
	OtherIds []string `json:"OtherIds,omitempty"`

	// X509SubjectNames is part of the binding but not matched on: weaker than the
	// key material already covered.
	X509SubjectNames []string `json:"X509SubjectNames,omitempty"`
}

// PKIObject is the binding's `pkiOb`. Go marshals a []byte as the standard padded
// base64 `contentEncoding: base64` asks for. Its optional `encoding` and `specRef`
// hints are not modelled.
type PKIObject struct {
	Val []byte `json:"val"`
}

// YiviExtension carries the members Yivi needs and Annex A has no field for, which
// the binding's untyped extension arrays make legal. Exactly one member is set per
// element, so an unknown extension is ignored.
//
// Holding OrganizationIdentifier here is provisional — it is half the key a
// certificate entry is matched on.
type YiviExtension struct {
	// OrganizationIdentifier is the entity's registered identifier in the form its
	// certificates carry in the subject's `organizationIdentifier` attribute (e.g.
	// "VATNL-123456789"). Set on a TEInformationExtensions element only.
	OrganizationIdentifier string `json:"YiviOrganizationIdentifier,omitempty"`

	// LogoURI is the curated logo: the entity's on a TEInformationExtensions
	// element, a per-service override on a ServiceInformationExtensions one.
	LogoURI string `json:"YiviLogoURI,omitempty"`

	// Marking is one scheme-specific qualifier, carried for round-tripping but not
	// acted on: the rung a grant confers is the source's, never the entry's.
	Marking string `json:"YiviMarking,omitempty"`

	// Confers is the level an anchor service's CA passes on, on a
	// ServiceInformationExtensions element of an anchor service only. See
	// [ServiceInformation.Confers] for why this one is the entry's word.
	Confers clientmodels.TrustLevel `json:"YiviConfers,omitempty"`
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

// LogoURI returns the entity's curated logo, or "".
func (ei EntityInformation) LogoURI() string {
	for _, ext := range ei.Extensions {
		if ext.LogoURI != "" {
			return ext.LogoURI
		}
	}
	return ""
}

// LogoURI returns the service-level logo override, or "".
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

// MultiLang is a sequence of multilingual character strings (clause 6.1.4):
// `[{"lang":…,"value":…}]` on the wire, and in Go the language map the rest of the
// wallet resolves display text from.
type MultiLang clientmodels.TranslatedString

type multiLangEntry struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// MarshalJSON emits entries sorted by language: the golden fixture is compared
// byte-for-byte and the refresh path diffs marshalled entities, so map iteration
// order would manufacture spurious changes.
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

// MultiLangURI is a sequence of non-empty multilingual URIs. Same map shape as
// [MultiLang], but its wire member is `uriValue` rather than `value`, so it cannot
// be an alias.
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

// CertificateOrganizationIdentifier returns the subject's `organizationIdentifier`
// attribute, or "". Exported so whoever builds a list entry keys it the way this
// matcher reads it.
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
