// Package lote implements the recognized-list channel of the trust ladder: the
// wallet fetches Lists of Trusted Entities (LoTEs) that Yivi publishes, checks
// that they still hold, and answers whether a party is granted on one.
//
// A LoTE is an ETSI TS 119 602 scheme-explicit List of Trusted Entities in the
// **Annex A JSON binding**, signed as a compact JAdES-B-B — a JWS whose `x5c`
// chain verifies against the pinned Yivi trust anchors. The shapes in this file
// mirror that binding: the JSON tags are the normative field names, and a
// document this package emits validates against the schema at
// forge.etsi.org/rep/esi/x19_60201_lists_of_trusted_entities.
//
// Two spec concepts are easy to conflate and this package depends on the
// difference. A *binding* (clause 4.6) instantiates the data model in a syntax;
// a *profile* (clause 4.7) constrains a LoTE's elements. A profile never renames
// or omits mandatory components — so "our own field names" was never a licensed
// variation, which is why this package follows Annex A verbatim rather than a
// Yivi-shaped approximation of it. See docs/adr/0004.
//
// Where a Go type name differs from its JSON tag it is for call-site
// readability only; the tag is what conformance depends on. `SchemeInformation`
// carries the tag `ListAndSchemeInformation`, and `Entity`/`Service` hold their
// spec-named sub-objects in fields called `Information`.
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
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust"
)

// LoTEVersion is the value this package emits and expects in
// `LoTEVersionIdentifier` (clause 6.3.1): the version of the LoTE format for a
// specific syntax binding. It is deliberately not enforced on read — a document
// declaring a later version whose fields still parse is more useful than a
// refusal, and clause 6.3.1 exists so a parser can tell which shape to expect
// rather than to gate access.
const LoTEVersion = 1

// Yivi's own scheme URIs.
//
// Annex C.1 permits this: "Any organization operating a scheme might choose to
// create its own URIs for its own specific purposes, or request ETSI to assign
// a registered URI root under the ETSI Identified Organization Domain." Every
// URI registered in Annex C.2 is EU-specific and gated on Member State
// notification of a role Yivi does not hold, so none of them may be reused.
//
// The root is provisional — whether Yivi mints under its own domain or requests
// an ETSI Identified Organization Domain root is still open (see
// docs/plans/lote-annex-a-publisher.md § Open items). They are collected here so
// that decision is one edit, and because `LoTEType` is pinned by every wallet:
// changing it after a release is a breaking change.
const (
	// LoTETypeRecognizedParties is the `LoTEType` of Yivi's recognized-parties
	// list. It names the *type*, so staging and production share it; the
	// per-list identity is SchemeName.
	LoTETypeRecognizedParties = "https://yivi.app/19602/LoTEType/YiviRecognizedPartiesList"

	// StatusDeterminationApproachYivi is how statuses on a Yivi list are
	// determined: by Yivi's own onboarding, described at the scheme
	// information URI.
	StatusDeterminationApproachYivi = "https://yivi.app/19602/YiviRecognizedPartiesList/StatusDetn/Yivi"

	// SchemeTypeCommunityRulesYivi points at the rules a listed party is
	// assessed against.
	SchemeTypeCommunityRulesYivi = "https://yivi.app/19602/YiviRecognizedParties/schemerules/Yivi"
)

// ServiceTypeIdentifier is the role a grant is for (clause 6.6.1), as a URI.
//
// Clause 6.6.0 NOTE 2 gives an *absent* ServiceTypeIdentifier the meaning "all
// listed services are of the same type", which is wrong for a list carrying
// both roles — so although the component is optional in the schema, it is
// mandatory for Yivi and always emitted.
type ServiceTypeIdentifier string

const (
	ServiceTypeIssuer   ServiceTypeIdentifier = "https://yivi.app/19602/Svctype/Issuer"
	ServiceTypeVerifier ServiceTypeIdentifier = "https://yivi.app/19602/Svctype/Verifier"
)

// Role maps a service type onto the ladder's role. An unrecognized URI maps to
// no role and therefore matches nothing, which is how a document naming a
// service type this wallet does not know stays parseable without granting
// anything.
func (t ServiceTypeIdentifier) Role() (trust.Role, bool) {
	switch t {
	case ServiceTypeIssuer:
		return trust.RoleIssuer, true
	case ServiceTypeVerifier:
		return trust.RoleVerifier, true
	}
	return "", false
}

// ServiceTypeForRole is the inverse of [ServiceTypeIdentifier.Role], for
// whoever builds a list entry — a test fixture, the publisher — so the two
// directions cannot drift.
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
// **An absent status means granted.** Clause 6.6.0 NOTE 1: when there is no
// historical information period and no ServiceStatus, all listed services share
// one approval status — so being on the list is the approval. Five of the six EU
// profiles (Annexes D, E, F, G, I) say the component "shall not be used" for
// exactly this reason, and Yivi follows them: its list carries no status, and
// off-boarding removes the entry rather than marking it.
//
// A status that *is* present is honoured, because a list from another scheme may
// carry one. Only a URI this package recognises grants; anything else reads as no
// grant, which fails closed against a vocabulary we do not know.
//
// Each scheme has its own vocabulary — Annex H's Pub-EAA list uses
// `…/PubEAAProvidersList/SvcStatus/notified` for what Yivi would call granted —
// so "which URI means granted" is properly a property of the source, not a global
// constant. Consuming another scheme's list will mean carrying its vocabulary on
// [Source]; until then the constants below are the only ones understood.
type ServiceStatus string

const (
	ServiceStatusGranted   ServiceStatus = "https://yivi.app/19602/Svcstatus/Granted"
	ServiceStatusWithdrawn ServiceStatus = "https://yivi.app/19602/Svcstatus/Withdrawn"
)

// IsGranted reports whether this service is a live grant.
//
// The rule lives here rather than at the lookup site so that the absent-means-
// granted reading is stated once. Getting it wrong in either direction is quiet:
// too strict and a conformant list grants nobody with no error, too loose and a
// withdrawal keeps granting.
func (si ServiceInformation) IsGranted() bool {
	if si.Status == "" {
		return true
	}
	return si.Status == ServiceStatusGranted
}

// organizationIdentifierOID is the X.520 `organizationIdentifier` attribute
// (id-at-organizationIdentifier, 2.5.4.97) — the subject field an EU
// certificate carries the legal entity's registered identifier in. Go's
// pkix.Name has no field for it, so it is read out of Subject.Names.
var organizationIdentifierOID = asn1.ObjectIdentifier{2, 5, 4, 97}

// Document is the outermost Annex A object. The binding wraps the list in a
// single `LoTE` member and forbids anything beside it, so the wrapper is a type
// of its own rather than an inlined field.
type Document struct {
	LoTE List `json:"LoTE"`
}

// List is one parsed LoTE: the scheme's own information plus the entities it
// lists.
type List struct {
	// SchemeInformation carries the tag `ListAndSchemeInformation`.
	SchemeInformation SchemeInformation `json:"ListAndSchemeInformation"`

	// Entities carries the tag `TrustedEntitiesList`. Optional in the binding —
	// a scheme with nothing listed yet still publishes a valid document.
	Entities []Entity `json:"TrustedEntitiesList,omitempty"`
}

// SchemeInformation is the list-level header (clause 6.3), carrying the tag
// `ListAndSchemeInformation`.
//
// Every field mandatory for *explicit* scheme information (Table 1) is present
// and non-optional here, because Yivi publishes scheme-explicit: Annex A binds
// only the scheme-explicit LoTE, so there is no standard JSON binding to fall
// back on for the implicit form.
type SchemeInformation struct {
	// LoTEVersionIdentifier is the version of the LoTE format for this binding
	// (clause 6.3.1). See [LoTEVersion].
	LoTEVersionIdentifier int `json:"LoTEVersionIdentifier"`

	// SequenceNumber is `LoTESequenceNumber` (clause 6.3.2): a counter the
	// scheme operator increments on every re-issue. The wallet refuses a
	// fetched list whose number is lower than the one it already holds, so a
	// captured older list cannot be replayed over a newer one.
	SequenceNumber uint64 `json:"LoTESequenceNumber"`

	// LoTEType names the kind of list (clause 6.3.3), unique per profile. It is
	// pinned by the wallet alongside SchemeName, but it is *not* the list's
	// identity: staging and production lists of the same kind share it.
	LoTEType string `json:"LoTEType"`

	// SchemeOperatorName is the entity in charge of establishing, publishing,
	// signing and maintaining the list (clause 6.3.4). Load-bearing beyond
	// display: clause 6.8.0 requires the signing certificate's subject
	// `Organization` to match one of these values.
	SchemeOperatorName MultiLang `json:"SchemeOperatorName"`

	// SchemeOperatorAddress is the operator's postal and electronic address
	// (clause 6.3.5).
	SchemeOperatorAddress SchemeOperatorAddress `json:"SchemeOperatorAddress"`

	// SchemeName names the scheme (clause 6.3.6) and is **this list's
	// identity**: the spec requires it to be "used in formal references to the
	// scheme in question, unique, and not used by any other scheme operated by
	// the same entity". The wallet stores the list under it and refuses a
	// document declaring a different one, so it must be stable across re-issues
	// and must equal the `ListId` configured for the source.
	//
	// Its format is prescribed: `CC:EN_name_value` for English and
	// `CC:name_value` for other languages, where CC is [SchemeTerritory].
	SchemeName MultiLang `json:"SchemeName"`

	// SchemeInformationURI points at where the scheme is described
	// (clause 6.3.7).
	SchemeInformationURI MultiLangURI `json:"SchemeInformationURI"`

	// StatusDeterminationApproach is how the statuses in this list are arrived
	// at (clause 6.3.8).
	StatusDeterminationApproach string `json:"StatusDeterminationApproach"`

	// SchemeTypeCommunityRules points at the rules listed parties are assessed
	// against (clause 6.3.9).
	SchemeTypeCommunityRules MultiLangURI `json:"SchemeTypeCommunityRules"`

	// SchemeTerritory is the country code the scheme operates under
	// (clause 6.3.10). Load-bearing beyond display: clause 6.8.0 requires the
	// signing certificate's subject `Country` to match it, and [SchemeName]'s
	// prescribed format embeds it.
	SchemeTerritory string `json:"SchemeTerritory"`

	// PolicyOrLegalNotice is the scheme's policy or legal notice
	// (clause 6.3.11). The binding's `oneOf` requires every element to be the
	// same kind — all policies or all legal notices — which is a build-time
	// validation rather than something the type can express.
	PolicyOrLegalNotice []PolicyOrLegalNotice `json:"PolicyOrLegalNotice"`

	// ListIssueDateTime is when this issue of the list was signed
	// (clause 6.3.14). Recorded, not enforced: the wallet gates on NextUpdate,
	// which is the operator's own statement of how long the content may be
	// relied on.
	ListIssueDateTime time.Time `json:"ListIssueDateTime"`

	// NextUpdate is when the list stops being current (clause 6.3.15). Past it
	// the list is no evidence at all — not stale evidence — so every party it
	// granted falls back to whatever the other channels say. Clause 6.3.15
	// requires a consumer to discard an expired LoTE precisely so an old one
	// cannot be substituted.
	NextUpdate time.Time `json:"NextUpdate"`

	// DistributionPoints are the URIs this list is published at
	// (clause 6.3.16). Optional, and not acted on by the wallet — it fetches
	// the URL its source configures. Carried so a document naming them
	// round-trips.
	DistributionPoints []string `json:"DistributionPoints,omitempty"`

	// HistoricalInformationPeriod (clause 6.3.12) is deliberately not modelled:
	// Yivi keeps no service history, and clause 6.4.2 ties history retention to
	// whether a service must stay listed even once it would otherwise drop off.
	// Its absence is also why ServiceStatus is always emitted — clause 6.6.0
	// NOTE 1 gives an absent status a meaning when there is no retention period.
}

// current reports whether a list carrying this scheme information may still be
// relied on at now, i.e. whether now is before its NextUpdate. It lives on the
// data the rule is about so the fetch path and the evaluation path cannot spell
// the same time bound two ways.
func (si SchemeInformation) current(now time.Time) bool {
	return now.Add(-ClockSkew).Before(si.NextUpdate)
}

// Identity is the list's identity as the wallet pins it: SchemeName's English
// entry. English is the one language clause 6.3.6 prescribes a format for, so it
// is the only entry guaranteed to be present and structured.
func (si SchemeInformation) Identity() string {
	return clientmodels.TranslatedString(si.SchemeName)["en"]
}

// PolicyOrLegalNotice is one element of clause 6.3.11: either a URI pointing at
// the scheme's policy, or the text of a legal notice. Exactly one is set.
type PolicyOrLegalNotice struct {
	LoTEPolicy      *MultiLangURIEntry `json:"LoTEPolicy,omitempty"`
	LoTELegalNotice string             `json:"LoTELegalNotice,omitempty"`
}

// SchemeOperatorAddress is clause 6.3.5. Both members are mandatory. Its
// property names differ from [TEAddress]'s despite the identical shape, so the
// two cannot share a type.
type SchemeOperatorAddress struct {
	PostalAddress     []PostalAddress     `json:"SchemeOperatorPostalAddress"`
	ElectronicAddress []MultiLangURIEntry `json:"SchemeOperatorElectronicAddress"`
}

// Entity is a listed organization (clause 6.4.1), carrying the tag
// `TrustedEntity`.
type Entity struct {
	// Information carries the tag `TrustedEntityInformation`.
	Information EntityInformation `json:"TrustedEntityInformation"`

	// Services carries the tag `TrustedEntityServices`: the entity's grants,
	// one per role it was granted for.
	Services []Service `json:"TrustedEntityServices"`
}

// EntityInformation is who a listed organization is (clause 6.5), carrying the
// tag `TrustedEntityInformation`. TEName, TEAddress and TEInformationURI are all
// mandatory (clause 6.5.0).
type EntityInformation struct {
	// Name is `TEName` (clause 6.5.1): the curated display name of the legal
	// entity, per language. This is what a listed party is shown as, in
	// preference to anything it asserts about itself.
	Name MultiLang `json:"TEName"`

	// TradeName is `TETradeName` (clause 6.5.2). Optional.
	TradeName MultiLang `json:"TETradeName,omitempty"`

	// Address is `TEAddress` (clause 6.5.3). Mandatory, and mandatory in both
	// halves — a postal *and* an electronic address. The wallet does not read
	// it; it exists because the binding requires it, which makes listing a
	// party more expensive to curate than it was.
	Address TEAddress `json:"TEAddress"`

	// InformationURI is `TEInformationURI` (clause 6.5.4): where a user can
	// read about this entity. Mandatory, and likewise unread by the wallet.
	InformationURI MultiLangURI `json:"TEInformationURI"`

	// Extensions is `TEInformationExtensions` (clause 6.5.5), carrying the two
	// Yivi members the binding has no field for. See [YiviExtension].
	Extensions []YiviExtension `json:"TEInformationExtensions,omitempty"`
}

// TEAddress is clause 6.5.3. Both members are mandatory.
type TEAddress struct {
	PostalAddress     []PostalAddress     `json:"TEPostalAddress"`
	ElectronicAddress []MultiLangURIEntry `json:"TEElectronicAddress"`
}

// PostalAddress is one language's rendering of a postal address. `lang`,
// `StreetAddress` and `Country` are mandatory; the rest are optional.
type PostalAddress struct {
	Lang            string `json:"lang"`
	StreetAddress   string `json:"StreetAddress"`
	Locality        string `json:"Locality,omitempty"`
	StateOrProvince string `json:"StateOrProvince,omitempty"`
	PostalCode      string `json:"PostalCode,omitempty"`
	Country         string `json:"Country"`
}

// Service is one grant (clause 6.4.3), carrying the tag `TrustedEntityService`:
// this entity, in this role, with this identity, in this state.
type Service struct {
	// Information carries the tag `ServiceInformation`.
	Information ServiceInformation `json:"ServiceInformation"`

	// ServiceHistory is deliberately not modelled: Yivi retains no history, so
	// there is nothing to put in it and clause 6.4.4 makes it conditional on
	// retention being applicable.
}

// ServiceInformation is what a grant says (clause 6.6), carrying the tag
// `ServiceInformation`. ServiceName and ServiceDigitalIdentity are mandatory
// (clause 6.6.0).
type ServiceInformation struct {
	// Name is `ServiceName` (clause 6.6.2). **Mandatory**, unlike the optional
	// per-service override it replaces: a service presented under its own brand
	// says so here, and one that is not simply repeats the entity's name.
	Name MultiLang `json:"ServiceName"`

	// DigitalIdentity is `ServiceDigitalIdentity` (clause 6.6.3): how a party
	// proves it is this service.
	DigitalIdentity DigitalIdentity `json:"ServiceDigitalIdentity"`

	// Type is `ServiceTypeIdentifier` (clause 6.6.1): the role the grant is
	// for. Trust as an issuer and trust as a verifier are separate grants, so
	// an entity listed to issue credentials is not thereby listed to ask for
	// them. Optional in the binding, mandatory for Yivi — see
	// [ServiceTypeIdentifier].
	Type ServiceTypeIdentifier `json:"ServiceTypeIdentifier"`

	// Status is `ServiceStatus` (clause 6.6.4). **Absent means granted** — see
	// [ServiceStatus] and [ServiceInformation.IsGranted]. Omitted from Yivi's
	// own list, and read when another scheme's list carries one.
	Status ServiceStatus `json:"ServiceStatus,omitempty"`

	// Extensions is `ServiceInformationExtensions` (clause 6.6.9), carrying
	// the service-level logo override and the scheme-specific markings the
	// binding has no field for. See [YiviExtension].
	Extensions []YiviExtension `json:"ServiceInformationExtensions,omitempty"`
}

// DigitalIdentity is the set of identities a service may be recognized by
// (clause 6.6.3). A party matches the service when it matches any one of them.
//
// Every member is a *sequence* in the binding, where the previous Yivi shape had
// single values. That is the binding's shape, not a Yivi choice: one service may
// legitimately be recognized by several certificates or keys.
type DigitalIdentity struct {
	// X509Certificates are the service's certificates, each as a `pkiOb` whose
	// `val` is the DER.
	X509Certificates []PKIObject `json:"X509Certificates,omitempty"`

	// X509SKIs are subject key identifiers, for entries that name the key
	// rather than one certificate carrying it — so a certificate renewal does
	// not need a re-issue of the list.
	X509SKIs [][]byte `json:"X509SKIs,omitempty"`

	// OtherIds are identities that are not X.509. This is where a DID lands.
	//
	// The binding makes an OtherId a **bare string**, so the previous
	// `{type,value}` pair is gone: a DID is already a URI and self-describing,
	// and it is compared verbatim (DIDs are case-sensitive beyond the scheme,
	// so no normalization is applied). The flip side is that the binding cannot
	// express what kind of identifier an entry holds, so a non-DID URI here
	// would be indistinguishable by shape alone.
	OtherIds []string `json:"OtherIds,omitempty"`

	// X509SubjectNames and PublicKeyValues are part of the binding but not
	// matched on: subject names are weaker than the key material already
	// covered, and a bare JWK names no certificate to CRL-check.
	X509SubjectNames []string `json:"X509SubjectNames,omitempty"`
}

// PKIObject is the binding's `pkiOb`. Go marshals a []byte as standard padded
// base64, which is what `contentEncoding: base64` asks for. The binding's
// optional `encoding` and `specRef` hints are not modelled: nothing emits them
// and nothing reads them.
type PKIObject struct {
	Val []byte `json:"val"`
}

// YiviExtension carries the members Yivi needs and Annex A has no field for.
// The binding's extension arrays are untyped, which is what makes this legal.
//
// Exactly one member is set per element, so a reader can tell them apart and
// an unknown extension from a future scheme version is simply ignored.
//
// **This placement is provisional for OrganizationIdentifier.** It is half the
// key a certificate entry is matched on, and identity-matching data living in
// an extension is uncomfortable — see docs/plans/lote-annex-a-publisher.md
// § Open items. Logo and Marking belong in an extension without reservation.
type YiviExtension struct {
	// OrganizationIdentifier is the entity's registered identifier, in the same
	// form its certificates carry in the subject's `organizationIdentifier`
	// attribute (e.g. "VATNL-123456789"). Set on a TEInformationExtensions
	// element only.
	OrganizationIdentifier string `json:"YiviOrganizationIdentifier,omitempty"`

	// LogoURI is the curated logo. On a TEInformationExtensions element it is
	// the entity's; on a ServiceInformationExtensions element it overrides it
	// for that service.
	LogoURI string `json:"YiviLogoURI,omitempty"`

	// Marking is one scheme-specific qualifier on a grant. Carried but not
	// acted on: the wallet knows no marking — the rung a grant confers is the
	// source's, never the entry's. Kept so a document carrying qualifiers
	// round-trips and future qualifiers have a place to land.
	Marking string `json:"YiviMarking,omitempty"`
}

// OrganizationIdentifier returns the entity's registered identifier, or "" when
// no extension carries one. Empty means the entry is keyed on the certificate
// alone.
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

// MultiLang is a sequence of multilingual character strings (clause 6.1.4).
//
// On the wire it is `[{"lang":…,"value":…}]`; in Go it is the same language map
// the rest of the wallet resolves display text from, so nothing downstream of a
// Listing has to know the binding's shape. The conversion lives here, at the
// wire edge, rather than being spread over the callers.
type MultiLang clientmodels.TranslatedString

type multiLangEntry struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// MarshalJSON emits the entries sorted by language. Deterministic order matters
// twice over: the golden fixture is compared byte-for-byte, and the refresh path
// decides whether a re-issue changed anything by comparing marshalled entities —
// so map iteration order would manufacture spurious changes and wake the app.
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
// `NonEmptyMultiLangURI`). Same map shape as [MultiLang], different wire member
// name — `uriValue` rather than `value` — which is why it is a separate type
// rather than an alias.
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
//
// Exported so that whoever builds a list entry — a test fixture, a publisher
// tool — keys it the way this matcher reads it, instead of re-deriving the OID
// and agreeing only with itself.
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
