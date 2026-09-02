package walletconfig

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// Typ is the JWS `typ` header a signed wallet config carries. It keeps a JWS the
// config CA signed for some other purpose from being served as a config.
const Typ = "yivi-wallet-config+jwt"

// SupportedSchemaMajor is the schema major this client reads. A different major
// is published at a different URL, so meeting one here means a misconfigured
// environment descriptor rather than a format the client should try to read.
const SupportedSchemaMajor = 1

// Config is the payload of a signed wallet config.
//
// Fields this client does not know are ignored when parsing — encoding/json's
// default, relied on deliberately — which is what lets a minor schema bump ship
// additively. Fields it does know are validated by [Config.Validate].
type Config struct {
	// SchemaVersion is `major.minor`. The major must be SupportedSchemaMajor.
	SchemaVersion string `json:"schema_version"`

	// ID identifies the config: what a Store files it under, and what the
	// environment's ConfigID must equal. One environment publishes one config,
	// so in practice one id per environment.
	ID string `json:"id"`

	// Environment must equal the name of the environment whose root verified the
	// signature: belt and braces on top of the per-environment root.
	Environment string `json:"environment"`

	// Version is monotonic per environment. A verified config carrying a lower
	// version than the one held is a rollback and is refused.
	Version uint64 `json:"version"`

	IssuedAt   UnixTime `json:"issued_at"`
	NextUpdate UnixTime `json:"next_update"`

	// GracePeriodSecs is how long after NextUpdate the config counts as stale
	// rather than expired. Zero means it expires at NextUpdate.
	GracePeriodSecs int64 `json:"grace_period_secs,omitempty"`

	// MinimumAppBuild is the lowest app build this config is meant for; zero
	// means no minimum. Enforcing it is the client's job, not this package's.
	MinimumAppBuild int64 `json:"minimum_app_build,omitempty"`

	Policy Policy `json:"policy"`

	// TrustedEntities is the one list of parties and CAs. It may be empty: a
	// config that vouches for nobody is a valid config.
	TrustedEntities []TrustedEntity `json:"trusted_entities"`
}

// Policy is what the wallet enforces on every session, as opposed to what it
// knows about individual parties.
type Policy struct {
	MinimumTrustLevel MinimumTrustLevel `json:"minimum_trust_level"`
}

// MinimumTrustLevel is the rung a party must reach for a session of each type to
// proceed. Below it the session is refused; at or above it but below high, the
// session proceeds with a warning.
type MinimumTrustLevel struct {
	Issuance   clientmodels.TrustLevel `json:"issuance"`
	Disclosure clientmodels.TrustLevel `json:"disclosure"`
}

// Role is one of the two things an entity may be trusted to do. Trust as an
// issuer and trust as a verifier are separate grants.
type Role string

const (
	RoleIssuer   Role = "issuer"
	RoleVerifier Role = "verifier"
)

// TrustedEntity is one party or CA Yivi vouches for. A CA is an entity whose
// handle anchors a subtree; a party in both roles is one entry with two roles.
type TrustedEntity struct {
	ID   string                        `json:"id"`
	Name clientmodels.TranslatedString `json:"name"`
	Logo *Logo                         `json:"logo,omitempty"`

	// Roles the entity is trusted in. A role this client does not know is kept
	// but grants nothing, so a future role is not a format break.
	Roles []Role `json:"roles"`

	// TrustLevel is the rung this listing confers. On a CA entity it is the
	// level everything chaining to it earns; on an individual party, the listed
	// level.
	TrustLevel clientmodels.TrustLevel `json:"trust_level"`

	// Handles are the ways a party in a session is matched to this entity.
	Handles []Handle `json:"handles"`

	// Constraints, when present, replace what the party's own certificate says it
	// may do. Absent means unconstrained (the trust-level policy still applies).
	Constraints *Constraints `json:"constraints,omitempty"`
}

// HasRole reports whether the entity is listed in role.
func (e *TrustedEntity) HasRole(role Role) bool {
	for _, r := range e.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Logo is fetched lazily and verified against its digest before display.
type Logo struct {
	URL string `json:"url"`
	// Digest is `sha256-<base64>` over the image bytes.
	Digest string `json:"digest"`
}

// HandleType says which mechanism a Handle identifies a party by.
type HandleType string

const (
	// HandleTypeX509CA anchors a subtree: every certificate chaining to
	// RootCertificate belongs to this entity.
	HandleTypeX509CA HandleType = "x509_ca"
	// HandleTypeX509Cert matches one end-entity certificate exactly.
	HandleTypeX509Cert HandleType = "x509_cert"
	// HandleTypeDID matches one DID exactly. No wildcards.
	HandleTypeDID HandleType = "did"
)

// Handle is one way to recognize an entity. Which fields apply depends on Type;
// a field belonging to another type is a validation error, so a curator's slip
// is caught at build time rather than silently matching nothing.
//
// A Type this client does not know validates as-is and is skipped by consumers:
// adding a handle type is meant to be a minor change.
type Handle struct {
	Type HandleType `json:"type"`

	// x509_ca
	RootCertificate       *Certificate  `json:"root_certificate,omitempty"`
	Intermediates         []Certificate `json:"intermediates,omitempty"`
	CRLDistributionPoints []string      `json:"crl_distribution_points,omitempty"`

	// x509_cert
	Certificate *Certificate `json:"certificate,omitempty"`

	// did
	DID string `json:"did,omitempty"`
}

// IsKnownType reports whether this client understands the handle's type. An
// unknown handle is carried but matches nothing.
func (h *Handle) IsKnownType() bool {
	switch h.Type {
	case HandleTypeX509CA, HandleTypeX509Cert, HandleTypeDID:
		return true
	}
	return false
}

// Constraints narrow what an entity may do in each role it holds.
type Constraints struct {
	Issuance   *IssuanceConstraint   `json:"issuance,omitempty"`
	Disclosure *DisclosureConstraint `json:"disclosure,omitempty"`
}

// IssuanceConstraint lists the credential types (vct values or credential type
// ids) the entity may issue.
type IssuanceConstraint struct {
	AllowedCredentials []string `json:"allowed_credentials"`
}

// DisclosureConstraint lists what the entity may ask for.
type DisclosureConstraint struct {
	AllowedQueries []AllowedQuery `json:"allowed_queries"`
}

// AllowedQuery is one credential type and the attributes of it that may be
// requested. An empty Attributes list allows any attribute of the credential.
type AllowedQuery struct {
	Credential string   `json:"credential"`
	Attributes []string `json:"attributes,omitempty"`
}

// Certificate is an X.509 certificate carried as base64 DER in JSON. It parses
// on decode, so a config that made it through Validate has no unparseable
// certificate in it.
type Certificate struct {
	*x509.Certificate
}

func (c Certificate) MarshalJSON() ([]byte, error) {
	if c.Certificate == nil {
		return []byte("null"), nil
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(c.Raw))
}

func (c *Certificate) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		c.Certificate = nil
		return nil
	}
	var encoded string
	if err := json.Unmarshal(b, &encoded); err != nil {
		return fmt.Errorf("certificate: expected a base64 string: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("certificate: not base64: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("certificate: not a DER certificate: %v", err)
	}
	c.Certificate = parsed
	return nil
}

// UnixTime is a moment carried as integer Unix seconds in JSON.
type UnixTime struct {
	time.Time
}

// NewUnixTime truncates t to the second, which is all the wire format carries,
// so a value survives a round trip unchanged.
func NewUnixTime(t time.Time) UnixTime {
	return UnixTime{t.Truncate(time.Second).UTC()}
}

func (t UnixTime) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return strconv.AppendInt(nil, t.Unix(), 10), nil
}

func (t *UnixTime) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*t = UnixTime{}
		return nil
	}
	seconds, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return fmt.Errorf("expected Unix seconds as an integer, got %s", b)
	}
	if seconds <= 0 {
		return fmt.Errorf("expected Unix seconds after the epoch, got %d", seconds)
	}
	*t = UnixTime{time.Unix(seconds, 0).UTC()}
	return nil
}

// Freshness is where a config stands relative to its own next_update.
type Freshness int

const (
	// Absent is the zero value: no config is held, so nothing has a freshness.
	Absent Freshness = iota
	// Fresh: before next_update. Full effect.
	Fresh
	// Stale: past next_update but within the grace period. Full effect; the
	// client is retrying the fetch eagerly.
	Stale
	// Expired: past the grace period. List-derived trust should stop counting;
	// chain validation against the last-known CA anchors keeps working, since a
	// certificate does not expire because a list did.
	Expired
)

func (f Freshness) String() string {
	switch f {
	case Absent:
		return "absent"
	case Fresh:
		return "fresh"
	case Stale:
		return "stale"
	case Expired:
		return "expired"
	}
	return fmt.Sprintf("Freshness(%d)", int(f))
}

// GracePeriod is the length of the stale window after NextUpdate.
func (c *Config) GracePeriod() time.Duration {
	return time.Duration(c.GracePeriodSecs) * time.Second
}

// ExpiresAt is when the config leaves the stale window.
func (c *Config) ExpiresAt() time.Time {
	return c.NextUpdate.Add(c.GracePeriod())
}

// FreshnessAt classifies the config at a moment. The boundaries are exclusive
// on the fresh side: at exactly next_update the config is stale.
func (c *Config) FreshnessAt(now time.Time) Freshness {
	if now.Before(c.NextUpdate.Time) {
		return Fresh
	}
	if now.Before(c.ExpiresAt()) {
		return Stale
	}
	return Expired
}

// Validate reports everything wrong with the config at once, so a curator fixes
// a document in one round. A nil error means every field this client knows is
// well-formed; it says nothing about whether the config is current or signed.
func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if major, _, err := parseSchemaVersion(c.SchemaVersion); err != nil {
		fail("schema_version: %v", err)
	} else if major != SupportedSchemaMajor {
		fail("schema_version %q: major %d is not supported, this client reads major %d",
			c.SchemaVersion, major, SupportedSchemaMajor)
	}
	if c.ID == "" {
		fail("id is required")
	}
	if c.Environment == "" {
		fail("environment is required")
	}
	if c.Version == 0 {
		fail("version must be at least 1")
	}
	if c.IssuedAt.IsZero() {
		fail("issued_at is required")
	}
	if c.NextUpdate.IsZero() {
		fail("next_update is required")
	} else if !c.IssuedAt.IsZero() && !c.NextUpdate.After(c.IssuedAt.Time) {
		fail("next_update (%s) must be after issued_at (%s)",
			c.NextUpdate.Format(time.RFC3339), c.IssuedAt.Format(time.RFC3339))
	}
	if c.GracePeriodSecs < 0 {
		fail("grace_period_secs must not be negative")
	}
	if c.MinimumAppBuild < 0 {
		fail("minimum_app_build must not be negative")
	}
	if !c.Policy.MinimumTrustLevel.Issuance.IsRung() {
		fail("policy.minimum_trust_level.issuance: %q is not a trust level", c.Policy.MinimumTrustLevel.Issuance)
	}
	if !c.Policy.MinimumTrustLevel.Disclosure.IsRung() {
		fail("policy.minimum_trust_level.disclosure: %q is not a trust level", c.Policy.MinimumTrustLevel.Disclosure)
	}

	seen := map[string]bool{}
	for i := range c.TrustedEntities {
		entity := &c.TrustedEntities[i]
		at := fmt.Sprintf("trusted_entities[%d]", i)
		if entity.ID != "" {
			at = fmt.Sprintf("%s (%q)", at, entity.ID)
		}
		switch {
		case entity.ID == "":
			fail("%s: id is required", at)
		case seen[entity.ID]:
			fail("%s: id is used by another entity", at)
		}
		seen[entity.ID] = true
		for _, err := range entity.validate() {
			fail("%s: %v", at, err)
		}
	}

	return errors.Join(errs...)
}

// parseSchemaVersion splits `major.minor`.
func parseSchemaVersion(v string) (major, minor int, err error) {
	majorText, minorText, ok := strings.Cut(v, ".")
	if !ok {
		return 0, 0, fmt.Errorf("%q is not of the form major.minor", v)
	}
	major, err = strconv.Atoi(majorText)
	if err != nil || major < 0 {
		return 0, 0, fmt.Errorf("%q has no integer major", v)
	}
	minor, err = strconv.Atoi(minorText)
	if err != nil || minor < 0 {
		return 0, 0, fmt.Errorf("%q has no integer minor", v)
	}
	return major, minor, nil
}

func (e *TrustedEntity) validate() []error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if !hasTranslation(e.Name) {
		fail("name needs at least one translation")
	}
	if e.Logo != nil {
		for _, err := range e.Logo.validate() {
			fail("logo: %v", err)
		}
	}

	if len(e.Roles) == 0 {
		fail("roles is required")
	}
	seenRoles := map[Role]bool{}
	for _, role := range e.Roles {
		if seenRoles[role] {
			fail("roles: %q is listed twice", role)
		}
		seenRoles[role] = true
	}

	if !e.TrustLevel.IsRung() {
		fail("trust_level: %q is not a trust level", e.TrustLevel)
	}

	if len(e.Handles) == 0 {
		fail("handles is required")
	}
	for i := range e.Handles {
		if err := e.Handles[i].validate(); err != nil {
			fail("handles[%d]: %v", i, err)
		}
	}

	if e.Constraints != nil {
		for _, err := range e.Constraints.validate(e) {
			fail("constraints: %v", err)
		}
	}
	return errs
}

func hasTranslation(name clientmodels.TranslatedString) bool {
	for _, text := range name {
		if strings.TrimSpace(text) != "" {
			return true
		}
	}
	return false
}

func (l *Logo) validate() []error {
	var errs []error
	if err := requireHTTPSURL(l.URL); err != nil {
		errs = append(errs, fmt.Errorf("url: %v", err))
	}
	if !strings.HasPrefix(l.Digest, "sha256-") || len(l.Digest) == len("sha256-") {
		errs = append(errs, fmt.Errorf("digest must be of the form sha256-<base64>"))
	}
	return errs
}

func requireHTTPSURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q does not parse: %v", raw, err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%q is not an https URL", raw)
	}
	return nil
}

func (h *Handle) validate() error {
	switch h.Type {
	case "":
		return errors.New("type is required")
	case HandleTypeX509CA:
		if h.RootCertificate == nil || h.RootCertificate.Certificate == nil {
			return errors.New("x509_ca: root_certificate is required")
		}
		if !h.RootCertificate.IsCA {
			return errors.New("x509_ca: root_certificate is not a CA certificate")
		}
		for i, intermediate := range h.Intermediates {
			if intermediate.Certificate == nil {
				return fmt.Errorf("x509_ca: intermediates[%d] is null", i)
			}
			if !intermediate.IsCA {
				return fmt.Errorf("x509_ca: intermediates[%d] is not a CA certificate", i)
			}
		}
		for i, distributionPoint := range h.CRLDistributionPoints {
			if _, err := url.ParseRequestURI(distributionPoint); err != nil {
				return fmt.Errorf("x509_ca: crl_distribution_points[%d]: %v", i, err)
			}
		}
		return h.rejectStray(h.Certificate != nil, "certificate", h.DID != "", "did")
	case HandleTypeX509Cert:
		if h.Certificate == nil || h.Certificate.Certificate == nil {
			return errors.New("x509_cert: certificate is required")
		}
		return h.rejectStray(
			h.RootCertificate != nil, "root_certificate",
			len(h.Intermediates) > 0, "intermediates",
			len(h.CRLDistributionPoints) > 0, "crl_distribution_points",
			h.DID != "", "did")
	case HandleTypeDID:
		if !looksLikeDID(h.DID) {
			return fmt.Errorf("did: %q is not of the form did:<method>:<identifier>", h.DID)
		}
		return h.rejectStray(
			h.RootCertificate != nil, "root_certificate",
			len(h.Intermediates) > 0, "intermediates",
			len(h.CRLDistributionPoints) > 0, "crl_distribution_points",
			h.Certificate != nil, "certificate")
	}
	// An unknown type is a later minor's handle: kept, matched by nobody.
	return nil
}

// rejectStray refuses fields of another handle type on this one. Arguments come
// in (present bool, field name) pairs.
func (h *Handle) rejectStray(pairs ...any) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i].(bool) {
			return fmt.Errorf("%s: %s does not belong on a handle of this type", h.Type, pairs[i+1].(string))
		}
	}
	return nil
}

func looksLikeDID(did string) bool {
	method, identifier, ok := strings.Cut(strings.TrimPrefix(did, "did:"), ":")
	return strings.HasPrefix(did, "did:") && ok && method != "" && identifier != ""
}

func (c *Constraints) validate(entity *TrustedEntity) []error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}
	if c.Issuance != nil {
		if !entity.HasRole(RoleIssuer) {
			fail("issuance: the entity has no issuer role")
		}
		for i, credential := range c.Issuance.AllowedCredentials {
			if credential == "" {
				fail("issuance.allowed_credentials[%d] is empty", i)
			}
		}
	}
	if c.Disclosure != nil {
		if !entity.HasRole(RoleVerifier) {
			fail("disclosure: the entity has no verifier role")
		}
		for i, query := range c.Disclosure.AllowedQueries {
			if query.Credential == "" {
				fail("disclosure.allowed_queries[%d].credential is empty", i)
			}
			for j, attribute := range query.Attributes {
				if attribute == "" {
					fail("disclosure.allowed_queries[%d].attributes[%d] is empty", i, j)
				}
			}
		}
	}
	return errs
}
