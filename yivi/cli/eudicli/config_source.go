package eudicli

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
)

// The curation format read by `config build`.
//
// It is deliberately not the wire format: hand-editing base64 DER to onboard a
// party would be error-prone in exactly the places that fail silently. A curator
// states the party — name, roles, level, how it authenticates — and `build` turns
// that into the config the wallet reads or refuses. Certificates are referenced by
// filename so a diff of an onboarding stays readable.
//
// One directory per entity, holding its own certificates: onboarding a party adds
// a directory and removing one takes its certificates with it. The directory name
// is the entity id, so ids are unique by construction.
//
// The curation files are read strictly — a member this tool does not know is
// refused — where the wire format is read leniently by the wallet. A typo in a
// curation file must fail in review, not publish as a silently missing field.

const (
	configSourceFileName = "config.json"
	entitiesDirName      = "entities"
	entityFileName       = "entity.json"
	credentialsDirName   = "credentials"
	credentialFileName   = "credential.json"
)

// configSource is config.json: the config's own information, which changes far
// less often than the entities do.
type configSource struct {
	// SchemaVersion defaults to the major this tool builds, minor 0.
	SchemaVersion string `json:"schema_version,omitempty"`

	// ID is the config's id, the key the wallet files it under; Environment the
	// environment it is for. Both must match what the wallet build expects.
	ID          string `json:"id"`
	Environment string `json:"environment"`

	// Version is optional here, and normally supplied by the publisher with
	// `build --version` instead: it must never go down relative to what is
	// published, which is bookkeeping against the live config and so cannot be
	// done from this file alone. Kept for manual and development builds.
	Version uint64 `json:"version,omitempty"`

	// NextUpdateDays is how long an issue counts as fresh; GracePeriodDays how
	// long after that it counts as stale rather than expired.
	NextUpdateDays  int `json:"next_update_days"`
	GracePeriodDays int `json:"grace_period_days"`

	MinimumAppBuild int64               `json:"minimum_app_build,omitempty"`
	Policy          walletconfig.Policy `json:"policy"`
}

// entitySource is entities/<id>/entity.json.
type entitySource struct {
	Name       clientmodels.TranslatedString `json:"name"`
	Roles      []walletconfig.Role           `json:"roles"`
	TrustLevel clientmodels.TrustLevel       `json:"trust_level"`
	Logo       *logoSource                   `json:"logo,omitempty"`
	Handles    []handleSource                `json:"handles"`
	// Constraints are written as on the wire.
	Constraints *walletconfig.Constraints `json:"constraints,omitempty"`
}

// logoSource names the logo's URL and either its digest or a file beside the
// entity to compute the digest from, so a curator never types a hash.
type logoSource struct {
	URL    string `json:"url"`
	Digest string `json:"digest,omitempty"`
	File   string `json:"file,omitempty"`
}

// handleSource is a handle with certificates by bare filename, resolved inside
// the entity's own directory, so an entity can name only its own.
type handleSource struct {
	Type walletconfig.HandleType `json:"type"`

	RootCertificate       string   `json:"root_certificate,omitempty"`
	Intermediates         []string `json:"intermediates,omitempty"`
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`

	Certificate string `json:"certificate,omitempty"`

	DID string `json:"did,omitempty"`
}

// credentialSource is credentials/<name>/credential.json: one catalogue entry.
// The directory name is for the curator's eyes only — a vct is a URL or URN and
// makes a poor directory name — and the entry is keyed by its vct.
type credentialSource struct {
	VCT            string           `json:"vct"`
	VCTMetadataURL string           `json:"vct_metadata_url,omitempty"`
	InStore        bool             `json:"in_store,omitempty"`
	Offerings      []offeringSource `json:"offerings"`
}

type offeringSource struct {
	IssuanceURLs      map[string]string `json:"issuance_urls"`
	IssuerMetadataURL string            `json:"issuer_metadata_url,omitempty"`
}

// buildOptions is what the publisher decides about a build beyond the curation.
type buildOptions struct {
	// IssuedAt is stamped into issued_at, and next_update derived from it. A
	// parameter rather than time.Now() so a rebuild of unchanged input can be made
	// byte-identical for a reviewer to diff.
	IssuedAt time.Time
	// Version overrides config.json when non-zero.
	Version uint64
}

// loadSource reads a curation directory into a validated config.
func loadSource(dir string, opts buildOptions) (*walletconfig.Config, error) {
	source, err := readConfigSource(dir)
	if err != nil {
		return nil, err
	}

	version := source.Version
	if opts.Version != 0 {
		version = opts.Version
	}
	if version == 0 {
		return nil, fmt.Errorf("%s: no version: set \"version\" in the file or pass --version", configSourceFileName)
	}
	if source.NextUpdateDays <= 0 {
		return nil, fmt.Errorf("%s: next_update_days must be at least 1", configSourceFileName)
	}
	if source.GracePeriodDays < 0 {
		return nil, fmt.Errorf("%s: grace_period_days must not be negative", configSourceFileName)
	}
	schemaVersion := source.SchemaVersion
	if schemaVersion == "" {
		schemaVersion = walletconfig.CurrentSchemaVersion
	}

	issuedAt := opts.IssuedAt.UTC().Truncate(time.Second)
	config := &walletconfig.Config{
		SchemaVersion:   schemaVersion,
		ID:              source.ID,
		Environment:     source.Environment,
		Version:         version,
		IssuedAt:        walletconfig.NewUnixTime(issuedAt),
		NextUpdate:      walletconfig.NewUnixTime(issuedAt.Add(time.Duration(source.NextUpdateDays) * 24 * time.Hour)),
		GracePeriodSecs: int64(source.GracePeriodDays) * 24 * 60 * 60,
		MinimumAppBuild: source.MinimumAppBuild,
		Policy:          source.Policy,
		TrustedEntities: []walletconfig.TrustedEntity{},
	}

	entities, err := readEntitySources(dir)
	if err != nil {
		return nil, err
	}
	for _, named := range entities {
		entity, err := named.source.toEntity(named.id, named.dir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(entitiesDirName, named.id, entityFileName), err)
		}
		config.TrustedEntities = append(config.TrustedEntities, entity)
	}

	credentials, err := readCredentialSources(dir)
	if err != nil {
		return nil, err
	}
	for _, credential := range credentials {
		config.CredentialCatalog = append(config.CredentialCatalog, credential.toCatalogEntry())
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("the built config does not validate:\n%w", err)
	}
	return config, nil
}

func readConfigSource(dir string) (configSource, error) {
	var source configSource
	raw, err := os.ReadFile(filepath.Join(dir, configSourceFileName))
	if err != nil {
		return source, fmt.Errorf("read %s: %w", configSourceFileName, err)
	}
	if err := strictUnmarshal(raw, &source); err != nil {
		return source, fmt.Errorf("%s: %w", configSourceFileName, err)
	}
	return source, nil
}

type namedEntitySource struct {
	id     string
	dir    string
	source entitySource
}

// readEntitySources reads every entities/<id>/entity.json, in id order, so a
// rebuild of unchanged input is byte-identical.
func readEntitySources(dir string) ([]namedEntitySource, error) {
	entitiesDir := filepath.Join(dir, entitiesDirName)
	dirEntries, err := os.ReadDir(entitiesDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", entitiesDirName, err)
	}

	var entities []namedEntitySource
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() {
			continue
		}
		entityDir := filepath.Join(entitiesDir, dirEntry.Name())
		raw, err := os.ReadFile(filepath.Join(entityDir, entityFileName))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filepath.Join(entitiesDirName, dirEntry.Name(), entityFileName), err)
		}
		var source entitySource
		if err := strictUnmarshal(raw, &source); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(entitiesDirName, dirEntry.Name(), entityFileName), err)
		}
		entities = append(entities, namedEntitySource{id: dirEntry.Name(), dir: entityDir, source: source})
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].id < entities[j].id })
	return entities, nil
}

// readCredentialSources reads every credentials/<name>/credential.json, in
// directory-name order.
func readCredentialSources(dir string) ([]credentialSource, error) {
	credentialsDir := filepath.Join(dir, credentialsDirName)
	dirEntries, err := os.ReadDir(credentialsDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", credentialsDirName, err)
	}

	var credentials []credentialSource
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() {
			continue
		}
		file := filepath.Join(credentialsDirName, dirEntry.Name(), credentialFileName)
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", file, err)
		}
		var source credentialSource
		if err := strictUnmarshal(raw, &source); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		credentials = append(credentials, source)
	}
	return credentials, nil
}

func (c credentialSource) toCatalogEntry() walletconfig.CatalogEntry {
	entry := walletconfig.CatalogEntry{VCT: c.VCT, VCTMetadataURL: c.VCTMetadataURL, InStore: c.InStore}
	for _, offering := range c.Offerings {
		entry.Offerings = append(entry.Offerings, walletconfig.Offering{
			IssuanceURLs:      offering.IssuanceURLs,
			IssuerMetadataURL: offering.IssuerMetadataURL,
		})
	}
	return entry
}

func (e entitySource) toEntity(id, dir string) (walletconfig.TrustedEntity, error) {
	entity := walletconfig.TrustedEntity{
		ID:          id,
		Name:        e.Name,
		Roles:       e.Roles,
		TrustLevel:  e.TrustLevel,
		Constraints: e.Constraints,
	}

	if e.Logo != nil {
		logo, err := e.Logo.toLogo(dir)
		if err != nil {
			return entity, fmt.Errorf("logo: %w", err)
		}
		entity.Logo = logo
	}

	for i, source := range e.Handles {
		handle, err := source.toHandle(dir)
		if err != nil {
			return entity, fmt.Errorf("handles[%d]: %w", i, err)
		}
		entity.Handles = append(entity.Handles, handle)
	}
	return entity, nil
}

func (l logoSource) toLogo(dir string) (*walletconfig.Logo, error) {
	logo := &walletconfig.Logo{URL: l.URL, Digest: l.Digest}
	switch {
	case l.File != "" && l.Digest != "":
		return nil, fmt.Errorf("give either \"digest\" or \"file\", not both")
	case l.File != "":
		data, err := readEntityFile(dir, l.File)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		logo.Digest = "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	case l.Digest == "":
		return nil, fmt.Errorf("give \"digest\" or a \"file\" to compute it from")
	}
	return logo, nil
}

// toHandle turns the curation handle into the wire handle, reading the named
// certificates. A handle type this tool does not know is refused: the wallet
// ignores an unknown type, but a curator naming one has made a typo.
func (h handleSource) toHandle(dir string) (walletconfig.Handle, error) {
	handle := walletconfig.Handle{Type: h.Type, CRLDistributionPoints: h.CRLDistributionPoints, DID: h.DID}
	switch h.Type {
	case walletconfig.HandleTypeX509CA:
		if h.RootCertificate == "" {
			return handle, fmt.Errorf("x509_ca: root_certificate is required")
		}
		root, err := readEntityCertificate(dir, h.RootCertificate)
		if err != nil {
			return handle, err
		}
		handle.RootCertificate = &walletconfig.Certificate{Certificate: root}
		for _, name := range h.Intermediates {
			intermediate, err := readEntityCertificate(dir, name)
			if err != nil {
				return handle, err
			}
			handle.Intermediates = append(handle.Intermediates, walletconfig.Certificate{Certificate: intermediate})
		}
	case walletconfig.HandleTypeX509Cert:
		if h.Certificate == "" {
			return handle, fmt.Errorf("x509_cert: certificate is required")
		}
		certificate, err := readEntityCertificate(dir, h.Certificate)
		if err != nil {
			return handle, err
		}
		handle.Certificate = &walletconfig.Certificate{Certificate: certificate}
	case walletconfig.HandleTypeDID:
		// Validated by the config.
	case "":
		return handle, fmt.Errorf("type is required")
	default:
		return handle, fmt.Errorf("unknown handle type %q", h.Type)
	}
	return handle, nil
}

// readEntityFile reads a file named in an entity's curation file. Bare filenames
// only: an entity cannot reach outside its own directory.
func readEntityFile(dir, name string) ([]byte, error) {
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return nil, fmt.Errorf("%q: a file is named by bare filename inside the entity's own directory", name)
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func readEntityCertificate(dir, name string) (*x509.Certificate, error) {
	if _, err := readEntityFile(dir, name); err != nil {
		return nil, err
	}
	return readCertificate(filepath.Join(dir, name))
}

// strictUnmarshal decodes JSON refusing unknown members and trailing data.
func strictUnmarshal(raw []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing data after the document")
	}
	return nil
}

// configJSON renders a config as the published payload. `build` writes it and
// `show --json` prints it, and a release gate diffs one against the other, so
// they share a renderer rather than each formatting to the same convention by
// coincidence.
func configJSON(config *walletconfig.Config) ([]byte, error) {
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
