package eudicli

import (
	"bytes"
	"cmp"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
)

// The curation format read by `lote build`.
//
// It is deliberately not Annex A: hand-editing the wire format to onboard a party
// would be error-prone in exactly the places that fail silently. A curator states
// the party — name, address, how it authenticates — and `build` turns that into a
// conformant document or refuses. The field names here are ours and carry no
// conformance weight; certificates are referenced by filename so a diff of an
// onboarding stays readable.

const (
	schemeFileName  = "scheme.json"
	entitiesDirName = "entities"
	certsDirName    = "certs"
)

// schemeSource is scheme.json: the scheme's own information, which changes far
// less often than the entities do.
type schemeSource struct {
	// SequenceNumber is optional here, and normally supplied by the publisher
	// instead: clause 6.3.2 requires it to start at 1, be incremented at every
	// release and never be re-cycled or lowered, which is bookkeeping against what
	// is already published and so cannot be done from this file. It is kept for
	// manual and development builds; `build --sequence-number` overrides it.
	SequenceNumber uint64 `json:"sequence_number,omitempty"`

	// NextUpdateDays is how long this issue may be relied on. No EU profile applies
	// to a Yivi list, so their six-month cap does not bind.
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

	// The scheme URIs. Empty takes the Yivi defaults from the lote package;
	// overridable so this tool can also build another operator's list.
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

type entitySource struct {
	Name      map[string]string `json:"name"`
	TradeName map[string]string `json:"trade_name,omitempty"`

	// OrganizationIdentifier is the registered identifier as the party's
	// certificates carry it. When set it is part of the key for certificate
	// entries: the certificate says which key, this says whose.
	OrganizationIdentifier string `json:"organization_identifier,omitempty"`

	LogoURI        string            `json:"logo_uri,omitempty"`
	InformationURI map[string]string `json:"information_uri"`
	Address        addressSource     `json:"address"`
	Services       []serviceSource   `json:"services"`
}

type serviceSource struct {
	// Role is "issuer" or "verifier". `build` maps it to the service type URI, so
	// a curator never types one.
	Role string `json:"role"`

	// Status is "granted" or "withdrawn"; empty means granted.
	//
	// A withdrawn service is left out of the published document rather than marked
	// in it: on a list carrying no statuses, the only way to express a withdrawal
	// is absence. It stays in the curation file so the off-boarding is legible in
	// git and reversible by editing one word; `build` reports what it excluded.
	Status string `json:"status,omitempty"`

	// Name overrides the entity's name for this service. ServiceName is mandatory,
	// so an empty one is filled from the entity.
	Name     map[string]string `json:"name,omitempty"`
	LogoURI  string            `json:"logo_uri,omitempty"`
	Markings []string          `json:"markings,omitempty"`

	Identity identitySource `json:"identity"`
}

type identitySource struct {
	// By filename under certs/.
	Certificates []string `json:"certificates,omitempty"`

	// CertificateSKIs pin the key rather than the certificate, also by filename
	// under certs/: `build` reads the subject key identifier out of the named
	// certificate, so an entry cannot be keyed on a value the wallet's lookup
	// would never match. Prefer these — an entry keyed on the key keeps granting
	// across a renewal that reuses it.
	CertificateSKIs []string `json:"certificate_skis,omitempty"`

	// DIDs are compared verbatim; DIDs are case-sensitive past the scheme.
	DIDs []string `json:"dids,omitempty"`
}

// buildStats is what `build` reports beyond the document itself. Withdrawals are
// absences in the output, so they have to be counted here.
type buildStats struct {
	WithdrawnServices int
	// DroppedEntities are the entities left out entirely, every service withdrawn.
	DroppedEntities []string
}

// loadSource reads a curation directory and turns it into a conformant list.
// issuedAt is stamped into ListIssueDateTime and NextUpdate derived from it; a
// parameter rather than time.Now() so a test can build the same document twice.
// documentJSON renders a list as the published document. `build` writes it and
// `show --json` prints it, and a release gate diffs one against the other — so
// they share a renderer rather than each formatting to the same convention by
// coincidence.
func documentJSON(list lote.List) ([]byte, error) {
	raw, err := json.MarshalIndent(lote.Document{LoTE: list}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// sequenceFromScheme tells loadSource to take the sequence number out of
// scheme.json rather than from the publisher.
const sequenceFromScheme uint64 = 0

// loadSource reads a curation directory into a list. A non-zero sequenceNumber is
// the publisher's, and overrides whatever scheme.json says.
func loadSource(dir string, issuedAt time.Time, sequenceNumber uint64) (lote.List, buildStats, error) {
	var stats buildStats

	scheme, err := readSchemeSource(dir)
	if err != nil {
		return lote.List{}, stats, err
	}

	entities, err := readEntitySources(dir)
	if err != nil {
		return lote.List{}, stats, err
	}

	schemeInfo, err := scheme.toSchemeInformation(issuedAt, sequenceNumber)
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

		// Annex A requires at least one service per entity.
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
		// Not an error: a scheme with nothing listed yet publishes a valid document
		// granting nobody.
		return nil, nil
	}
	// Sorted so a rebuild of unchanged input is byte-identical: entity order is
	// what the wallet's change detection compares over.
	slices.Sort(paths)

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

// strictUnmarshal refuses unknown fields: in a hand-written curation file, a
// misspelled key is a grant silently dropped.
func strictUnmarshal(raw []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into)
}

func (s schemeSource) toSchemeInformation(issuedAt time.Time, sequenceNumber uint64) (lote.SchemeInformation, error) {
	var info lote.SchemeInformation

	// The publisher's number wins where it has one: only it can see what is already
	// published, and clause 6.3.2 defines the number relative to that.
	sequence := cmp.Or(sequenceNumber, s.SequenceNumber)
	if sequence == 0 {
		return info, fmt.Errorf(
			"no sequence number: pass --sequence-number, or set sequence_number in %s", schemeFileName)
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
	// wallet does not police it, so this is the only check.
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
		SequenceNumber:        sequence,
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
// left out as withdrawn. One with none left comes back empty for the caller to
// drop.
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
			// Not converted, so its identities are not claimed either: a key an
			// off-boarded party no longer holds is free for whoever does.
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

	// ServiceName is mandatory, and it overrides the entity name for display, so a
	// service without its own brand repeats the entity's.
	name := s.Name
	if len(name) == 0 {
		name = entityName
	}

	// No ServiceStatus is emitted: on a list carrying none, being listed is the
	// grant, and a withdrawal is an absence handled before this.
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

	// claim registers an identity and reports a clash: the wallet takes the first
	// granting entry it finds, so a second one for the same party in the same role
	// is dead weight at best.
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
	// Rejected rather than cleaned: a path escaping certs/ is worth reporting.
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

// isWithdrawn reports whether this service is left out of the published document;
// an empty status means granted.
func (s serviceSource) isWithdrawn() (bool, error) {
	switch s.Status {
	case "", "granted":
		return false, nil
	case "withdrawn":
		return true, nil
	}
	return false, fmt.Errorf("unknown status %q (expected \"granted\" or \"withdrawn\")", s.Status)
}

// translated is for the human-facing commands, which want one language.
func translated(m lote.MultiLang) string {
	return clientmodels.TranslatedString(m)["en"]
}
