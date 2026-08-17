package eudicli

import (
	"cmp"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
)

// The curation format read by `lote build`.
//
// It is deliberately **not** Annex A. Annex A is the wire format — verbose by
// design, with `[{lang,value}]` sequences, plural identity arrays, URI
// vocabularies and extension objects — and hand-editing it to onboard a party
// would be error-prone in exactly the places that fail silently. Everything a
// curator has to know here is the party: its name, address, and how it
// authenticates. `build` turns that into a conformant document and refuses to
// emit one it cannot make conformant.
//
// Because this is an input format rather than a published one, its field names
// are ours and carry no conformance weight. Certificates are referenced by
// filename rather than inlined so that a diff of an onboarding stays readable.

const (
	schemeFileName  = "scheme.json"
	entitiesDirName = "entities"
	certsDirName    = "certs"
)

// schemeSource is scheme.json: the scheme's own information, which changes far
// less often than the entities do.
type schemeSource struct {
	// SequenceNumber is bumped on every re-issue. Reviewable in the diff on
	// purpose: the wallet accepts an unchanged number, so a missed bump does not
	// fail the publish — it silently flattens replay protection, and
	// `verify --against` is what catches that.
	SequenceNumber uint64 `json:"sequence_number"`

	// NextUpdateDays is how long this issue may be relied on. No EU profile
	// applies to a Yivi list, so their six-month cap does not bind and this is
	// the scheme operator's choice.
	NextUpdateDays int `json:"next_update_days"`

	// SchemeName is the list's identity, and must equal the ListId the wallet is
	// configured with. Its English entry has a prescribed form, `CC:name`.
	SchemeName map[string]string `json:"scheme_name"`

	// OperatorName must match the signing certificate's subject Organization.
	OperatorName map[string]string `json:"operator_name"`

	// Territory must match the signing certificate's subject Country.
	Territory string `json:"territory"`

	InformationURI  map[string]string `json:"information_uri"`
	OperatorAddress addressSource     `json:"operator_address"`

	// PolicyURI and LegalNotice are the two forms of clause 6.3.11. Exactly one
	// must be given: the binding's `oneOf` forbids a document carrying both.
	PolicyURI   map[string]string `json:"policy_uri,omitempty"`
	LegalNotice string            `json:"legal_notice,omitempty"`

	DistributionPoints []string `json:"distribution_points,omitempty"`

	// The scheme URIs. Empty takes the Yivi defaults compiled into the lote
	// package, which is what a Yivi list wants; they are overridable so this tool
	// can also build a list for another scheme operator.
	LoTEType                    string            `json:"lote_type,omitempty"`
	StatusDeterminationApproach string            `json:"status_determination_approach,omitempty"`
	SchemeTypeCommunityRules    map[string]string `json:"scheme_type_community_rules,omitempty"`
}

// addressSource is a postal-plus-electronic address. Annex A requires both
// halves wherever it requires an address at all.
type addressSource struct {
	Postal     []postalSource    `json:"postal"`
	Electronic map[string]string `json:"electronic"`
}

type postalSource struct {
	Lang            string `json:"lang"`
	Street          string `json:"street"`
	Locality        string `json:"locality,omitempty"`
	StateOrProvince string `json:"state_or_province,omitempty"`
	PostalCode      string `json:"postal_code,omitempty"`
	Country         string `json:"country"`
}

// entitySource is one file under entities/: one listed organization.
type entitySource struct {
	Name      map[string]string `json:"name"`
	TradeName map[string]string `json:"trade_name,omitempty"`

	// OrganizationIdentifier is the registered identifier as the party's
	// certificates carry it. When set it is *part of the key* for certificate
	// entries: the certificate says which key, this says whose.
	OrganizationIdentifier string `json:"organization_identifier,omitempty"`

	LogoURI        string            `json:"logo_uri,omitempty"`
	InformationURI map[string]string `json:"information_uri"`
	Address        addressSource     `json:"address"`
	Services       []serviceSource   `json:"services"`
}

// serviceSource is one grant: this entity, in this role, recognized by these
// identities, in this state.
type serviceSource struct {
	// Role is "issuer" or "verifier". `build` maps it to the service type URI, so
	// a curator never types one.
	Role string `json:"role"`

	// Status is "granted" or "withdrawn"; empty means granted.
	//
	// A withdrawn service is **left out of the published document** rather than
	// marked in it: the published list says who is trusted now, and on a list
	// carrying no statuses — which is what Yivi and five of the six EU profiles
	// publish — the only way to express a withdrawal is absence.
	//
	// It stays in the curation file so the off-boarding is legible in git, which
	// is where Yivi's audit trail actually lives, and so it can be reversed by
	// editing one word. `build` reports what it excluded.
	Status string `json:"status,omitempty"`

	// Name overrides the entity's name for this service. Annex A makes
	// ServiceName mandatory, so an empty one is filled from the entity rather
	// than left out.
	Name     map[string]string `json:"name,omitempty"`
	LogoURI  string            `json:"logo_uri,omitempty"`
	Markings []string          `json:"markings,omitempty"`

	Identity identitySource `json:"identity"`
}

// identitySource is how a party proves it is this service.
type identitySource struct {
	// Certificates pin whole certificates, by filename under certs/.
	Certificates []string `json:"certificates,omitempty"`

	// CertificateSKIs pin the *key* rather than the certificate, also by
	// filename under certs/: `build` reads the subject key identifier out of the
	// named certificate. Naming the file rather than pasting base64 is what stops
	// an entry being keyed on a value the wallet's lookup would never match —
	// the same reason the entity identifier is read from the certificate too.
	//
	// Prefer these: an entry keyed on the key keeps granting across a renewal
	// that reuses it, so a certificate rollover needs no re-issue of the list.
	CertificateSKIs []string `json:"certificate_skis,omitempty"`

	// DIDs are compared verbatim; DIDs are case-sensitive past the scheme.
	DIDs []string `json:"dids,omitempty"`
}

// buildStats is what `build` reports about a document beyond the document
// itself. Withdrawals are absences in the output, so they have to be counted
// here or they happen silently.
type buildStats struct {
	// WithdrawnServices is how many services were left out as withdrawn.
	WithdrawnServices int
	// DroppedEntities names entities left out entirely because every one of
	// their services was withdrawn.
	DroppedEntities []string
}

// loadSource reads a curation directory and turns it into a conformant list.
//
// issuedAt is the moment stamped into ListIssueDateTime, from which NextUpdate is
// derived. It is a parameter rather than time.Now() so a test can build a
// byte-identical document twice.
func loadSource(dir string, issuedAt time.Time) (lote.List, buildStats, error) {
	var stats buildStats

	scheme, err := readSchemeSource(dir)
	if err != nil {
		return lote.List{}, stats, err
	}

	entities, err := readEntitySources(dir)
	if err != nil {
		return lote.List{}, stats, err
	}

	schemeInfo, err := scheme.toSchemeInformation(issuedAt)
	if err != nil {
		return lote.List{}, stats, fmt.Errorf("%s: %w", schemeFileName, err)
	}

	list := lote.List{SchemeInformation: schemeInfo}
	// claimed maps an identity to the file that already claimed it, so two
	// entries recognizing the same party can be reported with both filenames.
	claimed := map[string]string{}
	for _, named := range entities {
		entity, withdrawn, err := named.source.toEntity(dir, claimed, named.file)
		if err != nil {
			return lote.List{}, stats, fmt.Errorf("%s: %w", named.file, err)
		}
		stats.WithdrawnServices += withdrawn

		// Annex A requires at least one service per entity, and an entity with
		// nothing granted says nothing anyway.
		if len(entity.Services) == 0 {
			stats.DroppedEntities = append(stats.DroppedEntities, named.file)
			continue
		}
		list.Entities = append(list.Entities, entity)
	}
	return list, stats, nil
}

func readSchemeSource(dir string) (schemeSource, error) {
	var scheme schemeSource
	path := filepath.Join(dir, schemeFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return scheme, fmt.Errorf("read %s: %w", schemeFileName, err)
	}
	if err := strictUnmarshal(raw, &scheme); err != nil {
		return scheme, fmt.Errorf("%s: %w", schemeFileName, err)
	}
	return scheme, nil
}

// namedEntitySource keeps the filename alongside the parsed entity, so every
// error names the file a curator has to open.
type namedEntitySource struct {
	file   string
	source entitySource
}

func readEntitySources(dir string) ([]namedEntitySource, error) {
	pattern := filepath.Join(dir, entitiesDirName, "*.json")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		// Not an error: a scheme with nothing listed yet publishes a valid
		// document granting nobody, and that is a reasonable first list.
		return nil, nil
	}
	// Sorted so a rebuild of unchanged input is byte-identical; entity order is
	// what the wallet's change detection compares over.
	sort.Strings(paths)

	entities := make([]namedEntitySource, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var entity entitySource
		relative := filepath.Join(entitiesDirName, filepath.Base(path))
		if err := strictUnmarshal(raw, &entity); err != nil {
			return nil, fmt.Errorf("%s: %w", relative, err)
		}
		entities = append(entities, namedEntitySource{file: relative, source: entity})
	}
	return entities, nil
}

// strictUnmarshal refuses unknown fields. A curation file is hand-written, so a
// misspelled key is far more likely to be a mistake that silently drops a grant
// than a deliberate extension.
func strictUnmarshal(raw []byte, into any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	return nil
}

func (s schemeSource) toSchemeInformation(issuedAt time.Time) (lote.SchemeInformation, error) {
	var info lote.SchemeInformation

	if s.SequenceNumber == 0 {
		return info, fmt.Errorf("sequence_number must be set and greater than zero")
	}
	if s.NextUpdateDays <= 0 {
		return info, fmt.Errorf("next_update_days must be greater than zero")
	}
	if s.Territory == "" {
		return info, fmt.Errorf("territory is required; it must match the signing certificate's subject Country")
	}

	name := s.SchemeName["en"]
	if name == "" {
		return info, fmt.Errorf("scheme_name must have an \"en\" entry: it is the list's identity")
	}
	// Clause 6.3.6 prescribes `CC:name`, where CC is the scheme territory. The
	// wallet does not police this, so if it is not checked here it is not checked
	// at all.
	if !strings.HasPrefix(name, s.Territory+":") {
		return info, fmt.Errorf(
			"scheme_name %q must start with %q: clause 6.3.6 prescribes CC:name, where CC is the scheme territory",
			name, s.Territory+":")
	}
	if len(s.OperatorName) == 0 {
		return info, fmt.Errorf("operator_name is required; it must match the signing certificate's subject Organization")
	}
	if s.InformationURI["en"] == "" {
		return info, fmt.Errorf("information_uri must have an \"en\" entry")
	}

	policy, err := s.policyOrLegalNotice()
	if err != nil {
		return info, err
	}
	operatorAddress, err := s.OperatorAddress.validate("operator_address")
	if err != nil {
		return info, err
	}

	communityRules := lote.MultiLangURI{"en": lote.SchemeTypeCommunityRulesYivi}
	if len(s.SchemeTypeCommunityRules) > 0 {
		communityRules = lote.MultiLangURI(s.SchemeTypeCommunityRules)
	}

	return lote.SchemeInformation{
		LoTEVersionIdentifier: lote.LoTEVersion,
		SequenceNumber:        s.SequenceNumber,
		LoTEType:              cmp.Or(s.LoTEType, lote.LoTETypeRecognizedParties),
		SchemeOperatorName:    lote.MultiLang(s.OperatorName),
		SchemeOperatorAddress: lote.SchemeOperatorAddress{
			PostalAddress:     operatorAddress.postal,
			ElectronicAddress: operatorAddress.electronic,
		},
		SchemeName:                  lote.MultiLang(s.SchemeName),
		SchemeInformationURI:        lote.MultiLangURI(s.InformationURI),
		StatusDeterminationApproach: cmp.Or(s.StatusDeterminationApproach, lote.StatusDeterminationApproachYivi),
		SchemeTypeCommunityRules:    communityRules,
		SchemeTerritory:             s.Territory,
		PolicyOrLegalNotice:         policy,
		ListIssueDateTime:           issuedAt,
		NextUpdate:                  issuedAt.AddDate(0, 0, s.NextUpdateDays),
		DistributionPoints:          s.DistributionPoints,
	}, nil
}

// policyOrLegalNotice builds clause 6.3.11. The binding's `oneOf` means a
// document may carry policies or legal notices but not a mixture, so exactly one
// of the two inputs must be given.
func (s schemeSource) policyOrLegalNotice() ([]lote.PolicyOrLegalNotice, error) {
	hasPolicy := len(s.PolicyURI) > 0
	hasNotice := s.LegalNotice != ""
	switch {
	case hasPolicy && hasNotice:
		return nil, fmt.Errorf("policy_uri and legal_notice are mutually exclusive: the binding forbids a document carrying both")
	case hasPolicy:
		notices := make([]lote.PolicyOrLegalNotice, 0, len(s.PolicyURI))
		for _, lang := range slices.Sorted(maps.Keys(s.PolicyURI)) {
			notices = append(notices, lote.PolicyOrLegalNotice{
				LoTEPolicy: &lote.MultiLangURIEntry{Lang: lang, URIValue: s.PolicyURI[lang]},
			})
		}
		return notices, nil
	case hasNotice:
		return []lote.PolicyOrLegalNotice{{LoTELegalNotice: s.LegalNotice}}, nil
	default:
		return nil, fmt.Errorf("one of policy_uri or legal_notice is required")
	}
}

// validatedAddress is an address that has been checked and converted.
type validatedAddress struct {
	postal     []lote.PostalAddress
	electronic []lote.MultiLangURIEntry
}

func (a addressSource) validate(field string) (validatedAddress, error) {
	var out validatedAddress
	if len(a.Postal) == 0 {
		return out, fmt.Errorf("%s.postal is required: Annex A requires a postal address", field)
	}
	if len(a.Electronic) == 0 {
		return out, fmt.Errorf("%s.electronic is required: Annex A requires an electronic address", field)
	}
	for i, postal := range a.Postal {
		if postal.Lang == "" || postal.Street == "" || postal.Country == "" {
			return out, fmt.Errorf("%s.postal[%d] requires lang, street and country", field, i)
		}
		out.postal = append(out.postal, lote.PostalAddress{
			Lang:            postal.Lang,
			StreetAddress:   postal.Street,
			Locality:        postal.Locality,
			StateOrProvince: postal.StateOrProvince,
			PostalCode:      postal.PostalCode,
			Country:         postal.Country,
		})
	}
	for _, lang := range slices.Sorted(maps.Keys(a.Electronic)) {
		out.electronic = append(out.electronic, lote.MultiLangURIEntry{Lang: lang, URIValue: a.Electronic[lang]})
	}
	return out, nil
}

// toEntity converts one curation file, reporting how many of its services were
// left out as withdrawn. An entity whose every service is withdrawn comes back
// with no services, which the caller drops.
func (e entitySource) toEntity(dir string, claimed map[string]string, file string) (lote.Entity, int, error) {
	var entity lote.Entity

	if e.Name["en"] == "" {
		return entity, 0, fmt.Errorf("name must have an \"en\" entry")
	}
	if e.InformationURI["en"] == "" {
		return entity, 0, fmt.Errorf("information_uri must have an \"en\" entry: Annex A requires TEInformationURI")
	}
	if len(e.Services) == 0 {
		return entity, 0, fmt.Errorf("services is empty: an entity with no grants says nothing")
	}
	address, err := e.Address.validate("address")
	if err != nil {
		return entity, 0, err
	}

	information := lote.EntityInformation{
		Name:           lote.MultiLang(e.Name),
		Address:        lote.TEAddress{PostalAddress: address.postal, ElectronicAddress: address.electronic},
		InformationURI: lote.MultiLangURI(e.InformationURI),
	}
	if len(e.TradeName) > 0 {
		information.TradeName = lote.MultiLang(e.TradeName)
	}
	if e.OrganizationIdentifier != "" {
		information.Extensions = append(information.Extensions,
			lote.YiviExtension{OrganizationIdentifier: e.OrganizationIdentifier})
	}
	if e.LogoURI != "" {
		information.Extensions = append(information.Extensions, lote.YiviExtension{LogoURI: e.LogoURI})
	}
	entity.Information = information

	withdrawn := 0
	for i, source := range e.Services {
		excluded, err := source.isWithdrawn()
		if err != nil {
			return entity, 0, fmt.Errorf("services[%d]: %w", i, err)
		}
		if excluded {
			// Not converted at all, so its identities are not claimed either: a
			// key an off-boarded party no longer holds is free for whoever does.
			// The flip side is that a typo inside a withdrawn entry goes
			// unnoticed until someone un-withdraws it.
			withdrawn++
			continue
		}

		service, err := source.toService(dir, e.Name, claimed, file)
		if err != nil {
			return entity, 0, fmt.Errorf("services[%d]: %w", i, err)
		}
		entity.Services = append(entity.Services, service)
	}
	return entity, withdrawn, nil
}

func (s serviceSource) toService(
	dir string,
	entityName map[string]string,
	claimed map[string]string,
	file string,
) (lote.Service, error) {
	var service lote.Service

	role, err := parseRole(s.Role)
	if err != nil {
		return service, err
	}

	identity, err := s.Identity.toDigitalIdentity(dir, role, claimed, file)
	if err != nil {
		return service, err
	}

	// ServiceName is mandatory, and a service not presented under its own brand
	// repeats the entity's — which is also what keeps the entity name showing,
	// since the service name overrides it for display.
	name := s.Name
	if len(name) == 0 {
		name = entityName
	}

	// No ServiceStatus is emitted: on a list carrying none, being listed is the
	// grant. A withdrawal is an absence, handled before this is reached.
	information := lote.ServiceInformation{
		Name:            lote.MultiLang(name),
		DigitalIdentity: identity,
		Type:            lote.ServiceTypeForRole(role),
	}
	if s.LogoURI != "" {
		information.Extensions = append(information.Extensions, lote.YiviExtension{LogoURI: s.LogoURI})
	}
	for _, marking := range s.Markings {
		information.Extensions = append(information.Extensions, lote.YiviExtension{Marking: marking})
	}

	service.Information = information
	return service, nil
}

func (i identitySource) toDigitalIdentity(
	dir string,
	role trust.Role,
	claimed map[string]string,
	file string,
) (lote.DigitalIdentity, error) {
	var identity lote.DigitalIdentity

	if len(i.Certificates) == 0 && len(i.CertificateSKIs) == 0 && len(i.DIDs) == 0 {
		return identity, fmt.Errorf("identity names nothing: a service with no digital identity can never match a party")
	}

	// claim registers an identity and reports a clash. Two entries recognizing
	// the same party in the same role is not a merge — the wallet takes the first
	// granting entry it finds, so the second is dead weight at best and a
	// contradiction at worst.
	claim := func(kind, value string) error {
		key := string(role) + "\x00" + kind + "\x00" + value
		if previous, ok := claimed[key]; ok {
			return fmt.Errorf("%s %s is already granted as %s in %s", kind, value, role, previous)
		}
		claimed[key] = file
		return nil
	}

	for _, name := range i.Certificates {
		cert, err := readCertificate(dir, name)
		if err != nil {
			return identity, err
		}
		if err := claim("certificate", name); err != nil {
			return identity, err
		}
		identity.X509Certificates = append(identity.X509Certificates, lote.PKIObject{Val: cert.Raw})
	}

	for _, name := range i.CertificateSKIs {
		cert, err := readCertificate(dir, name)
		if err != nil {
			return identity, err
		}
		if len(cert.SubjectKeyId) == 0 {
			return identity, fmt.Errorf(
				"certificate %s carries no subjectKeyIdentifier, so it cannot be keyed on its key; pin it under certificates instead",
				name)
		}
		if err := claim("certificate_ski", name); err != nil {
			return identity, err
		}
		identity.X509SKIs = append(identity.X509SKIs, cert.SubjectKeyId)
	}

	for _, did := range i.DIDs {
		if did == "" {
			return identity, fmt.Errorf("identity.dids contains an empty entry")
		}
		if err := claim("did", did); err != nil {
			return identity, err
		}
		identity.OtherIds = append(identity.OtherIds, did)
	}

	return identity, nil
}

// readCertificate reads a certificate from certs/, accepting PEM or raw DER.
func readCertificate(dir, name string) (*x509.Certificate, error) {
	// Rejected rather than cleaned: a path escaping certs/ is a mistake worth
	// reporting, not something to silently reinterpret.
	if name != filepath.Base(name) {
		return nil, fmt.Errorf("certificate %q must be a bare filename under %s/", name, certsDirName)
	}
	path := filepath.Join(dir, certsDirName, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate %s: %w", name, err)
	}
	if block, _ := pem.Decode(raw); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("certificate %s holds a %q PEM block, not a CERTIFICATE", name, block.Type)
		}
		raw = block.Bytes
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", name, err)
	}
	return cert, nil
}

func parseRole(role string) (trust.Role, error) {
	switch role {
	case string(trust.RoleIssuer):
		return trust.RoleIssuer, nil
	case string(trust.RoleVerifier):
		return trust.RoleVerifier, nil
	case "":
		return "", fmt.Errorf("role is required (%q or %q)", trust.RoleIssuer, trust.RoleVerifier)
	}
	return "", fmt.Errorf("unknown role %q (expected %q or %q)", role, trust.RoleIssuer, trust.RoleVerifier)
}

// isWithdrawn reports whether this service is left out of the published document.
// Empty means granted: an entry nobody has withdrawn is the common case, and a
// required field there would only invite copy-paste.
func (s serviceSource) isWithdrawn() (bool, error) {
	switch s.Status {
	case "", "granted":
		return false, nil
	case "withdrawn":
		return true, nil
	}
	return false, fmt.Errorf("unknown status %q (expected \"granted\" or \"withdrawn\")", s.Status)
}

// translated is a small helper for the human-facing commands, which want one
// language rather than a map.
func translated(m lote.MultiLang) string {
	return clientmodels.TranslatedString(m)["en"]
}
