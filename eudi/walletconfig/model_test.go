package walletconfig

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate_AcceptsAMinimalConfig(t *testing.T) {
	require.NoError(t, NewTestConfig("test", 1, time.Now()).Validate())
}

// Every shape the wallet understands, in one document.
func TestConfig_Validate_AcceptsAFullyFeaturedConfig(t *testing.T) {
	config := fullyFeaturedConfig(t)
	require.NoError(t, config.Validate())
}

func TestConfig_Validate_AcceptsAnEmptyEntityList(t *testing.T) {
	config := NewTestConfig("test", 1, time.Now())
	config.TrustedEntities = nil
	require.NoError(t, config.Validate())
}

// A later minor adds fields, handle types and roles. None of that may make an
// older client refuse the document.
func TestConfig_Validate_ToleratesWhatALaterMinorAdds(t *testing.T) {
	config := NewTestConfig("test", 1, time.Now())
	config.SchemaVersion = "1.7"
	config.TrustedEntities[0].Roles = append(config.TrustedEntities[0].Roles, "wallet_provider")
	config.TrustedEntities[0].Handles = append(config.TrustedEntities[0].Handles,
		Handle{Type: "openid_federation_entity"})
	require.NoError(t, config.Validate())

	require.False(t, config.TrustedEntities[0].Handles[1].IsKnownType())
	require.True(t, config.TrustedEntities[0].Handles[0].IsKnownType())
}

func TestConfig_Validate_RejectsEachMalformedField(t *testing.T) {
	caKey, ca := NewTestCA(t, "Some CA", nil, nil)
	_, leaf := NewTestEndEntity(t, "some-party", ca, caKey, nil)

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"schema_version malformed", func(c *Config) { c.SchemaVersion = "1" }, "major.minor"},
		{"schema_version non-numeric", func(c *Config) { c.SchemaVersion = "one.zero" }, "no integer major"},
		{"schema major unsupported", func(c *Config) { c.SchemaVersion = "2.0" }, "major 2 is not supported"},
		{"environment missing", func(c *Config) { c.Environment = "" }, "environment is required"},
		{"version zero", func(c *Config) { c.Version = 0 }, "version must be at least 1"},
		{"issued_at missing", func(c *Config) { c.IssuedAt = UnixTime{} }, "issued_at is required"},
		{"next_update missing", func(c *Config) { c.NextUpdate = UnixTime{} }, "next_update is required"},
		{"next_update not after issued_at", func(c *Config) { c.NextUpdate = c.IssuedAt }, "must be after issued_at"},
		{"grace negative", func(c *Config) { c.GracePeriodSecs = -1 }, "grace_period_secs"},
		{"minimum_app_build negative", func(c *Config) { c.MinimumAppBuild = -1 }, "minimum_app_build"},
		{"policy issuance level unknown", func(c *Config) { c.Policy.MinimumTrustLevel.Issuance = "mid" }, "policy.minimum_trust_level.issuance"},
		{"policy disclosure level missing", func(c *Config) { c.Policy.MinimumTrustLevel.Disclosure = "" }, "policy.minimum_trust_level.disclosure"},
		{"entity id missing", func(c *Config) { c.TrustedEntities[0].ID = "" }, "id is required"},
		{"entity id duplicate", func(c *Config) { c.TrustedEntities = append(c.TrustedEntities, c.TrustedEntities[0]) }, "used by another entity"},
		{"entity name missing", func(c *Config) { c.TrustedEntities[0].Name = nil }, "name needs at least one translation"},
		{"entity name blank", func(c *Config) { c.TrustedEntities[0].Name = clientmodels.TranslatedString{"en": "  "} }, "name needs at least one translation"},
		{"entity roles missing", func(c *Config) { c.TrustedEntities[0].Roles = nil }, "roles is required"},
		{"entity role twice", func(c *Config) { c.TrustedEntities[0].Roles = []Role{RoleIssuer, RoleIssuer} }, "listed twice"},
		{"entity trust_level missing", func(c *Config) { c.TrustedEntities[0].TrustLevel = "" }, "trust_level"},
		{"entity trust_level unknown", func(c *Config) { c.TrustedEntities[0].TrustLevel = "very_high" }, "trust_level"},
		{"entity handles missing", func(c *Config) { c.TrustedEntities[0].Handles = nil }, "handles is required"},
		{"handle type missing", func(c *Config) { c.TrustedEntities[0].Handles[0] = Handle{DID: "did:web:x.example"} }, "type is required"},
		{"did malformed", func(c *Config) { c.TrustedEntities[0].Handles[0].DID = "did:web" }, "did:<method>:<identifier>"},
		{"did without prefix", func(c *Config) { c.TrustedEntities[0].Handles[0].DID = "web:x.example" }, "did:<method>:<identifier>"},
		{"did handle with a certificate", func(c *Config) {
			c.TrustedEntities[0].Handles[0].Certificate = &Certificate{leaf}
		}, "certificate does not belong"},
		{"x509_ca without root", func(c *Config) { c.TrustedEntities[0].Handles[0] = Handle{Type: HandleTypeX509CA} }, "root_certificate is required"},
		{"x509_ca root not a CA", func(c *Config) {
			c.TrustedEntities[0].Handles[0] = Handle{Type: HandleTypeX509CA, RootCertificate: &Certificate{leaf}}
		}, "not a CA certificate"},
		{"x509_ca intermediate not a CA", func(c *Config) {
			c.TrustedEntities[0].Handles[0] = Handle{Type: HandleTypeX509CA, RootCertificate: &Certificate{ca}, Intermediates: []Certificate{{leaf}}}
		}, "intermediates[0] is not a CA"},
		{"x509_ca crl distribution point malformed", func(c *Config) {
			c.TrustedEntities[0].Handles[0] = Handle{Type: HandleTypeX509CA, RootCertificate: &Certificate{ca}, CRLDistributionPoints: []string{"not a url"}}
		}, "crl_distribution_points[0]"},
		{"x509_ca with a did", func(c *Config) {
			c.TrustedEntities[0].Handles[0] = Handle{Type: HandleTypeX509CA, RootCertificate: &Certificate{ca}, DID: "did:web:x.example"}
		}, "did does not belong"},
		{"x509_cert without certificate", func(c *Config) { c.TrustedEntities[0].Handles[0] = Handle{Type: HandleTypeX509Cert} }, "certificate is required"},
		{"x509_cert with a root", func(c *Config) {
			c.TrustedEntities[0].Handles[0] = Handle{Type: HandleTypeX509Cert, Certificate: &Certificate{leaf}, RootCertificate: &Certificate{ca}}
		}, "root_certificate does not belong"},
		{"logo not https", func(c *Config) {
			c.TrustedEntities[0].Logo = &Logo{URL: "http://logos.example/x.png", Digest: "sha256-abc"}
		}, "not an https URL"},
		{"logo digest malformed", func(c *Config) {
			c.TrustedEntities[0].Logo = &Logo{URL: "https://logos.example/x.png", Digest: "abc"}
		}, "sha256-<base64>"},
		{"issuance constraint without issuer role", func(c *Config) {
			c.TrustedEntities[0].Roles = []Role{RoleVerifier}
			c.TrustedEntities[0].Constraints = &Constraints{Issuance: &IssuanceConstraint{AllowedCredentials: []string{"x"}}}
		}, "no issuer role"},
		{"disclosure constraint without verifier role", func(c *Config) {
			c.TrustedEntities[0].Constraints = &Constraints{Disclosure: &DisclosureConstraint{AllowedQueries: []AllowedQuery{{Credential: "x"}}}}
		}, "no verifier role"},
		{"empty allowed credential", func(c *Config) {
			c.TrustedEntities[0].Constraints = &Constraints{Issuance: &IssuanceConstraint{AllowedCredentials: []string{""}}}
		}, "allowed_credentials[0] is empty"},
		{"empty allowed query credential", func(c *Config) {
			c.TrustedEntities[0].Roles = []Role{RoleIssuer, RoleVerifier}
			c.TrustedEntities[0].Constraints = &Constraints{Disclosure: &DisclosureConstraint{AllowedQueries: []AllowedQuery{{Attributes: []string{"a"}}}}}
		}, "allowed_queries[0].credential is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := NewTestConfig("test", 1, time.Now())
			tc.mutate(config)
			err := config.Validate()
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// A curator fixes a document in one round, so every problem is reported at once.
func TestConfig_Validate_ReportsEveryProblemAtOnce(t *testing.T) {
	config := NewTestConfig("test", 1, time.Now())
	config.Version = 0
	config.Environment = ""
	config.TrustedEntities[0].ID = ""

	err := config.Validate()
	require.ErrorContains(t, err, "version must be at least 1")
	require.ErrorContains(t, err, "environment is required")
	require.ErrorContains(t, err, "trusted_entities[0]: id is required")
}

func TestConfig_FreshnessAt(t *testing.T) {
	nextUpdate := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	config := &Config{NextUpdate: NewUnixTime(nextUpdate), GracePeriodSecs: 7 * 24 * 60 * 60}
	grace := config.GracePeriod()

	require.Equal(t, Fresh, config.FreshnessAt(nextUpdate.Add(-time.Second)))
	require.Equal(t, Stale, config.FreshnessAt(nextUpdate), "at next_update itself the config is stale")
	require.Equal(t, Stale, config.FreshnessAt(nextUpdate.Add(grace-time.Second)))
	require.Equal(t, Expired, config.FreshnessAt(nextUpdate.Add(grace)), "at the end of the grace period it is expired")
	require.Equal(t, nextUpdate.Add(grace), config.ExpiresAt())

	noGrace := &Config{NextUpdate: NewUnixTime(nextUpdate)}
	require.Equal(t, Fresh, noGrace.FreshnessAt(nextUpdate.Add(-time.Second)))
	require.Equal(t, Expired, noGrace.FreshnessAt(nextUpdate), "without grace, stale is skipped")
}

func TestFreshness_String(t *testing.T) {
	require.Equal(t, "absent", Absent.String())
	require.Equal(t, "fresh", Fresh.String())
	require.Equal(t, "stale", Stale.String())
	require.Equal(t, "expired", Expired.String())
}

func TestUnixTime_JSON(t *testing.T) {
	moment := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

	encoded, err := json.Marshal(NewUnixTime(moment))
	require.NoError(t, err)
	require.Equal(t, "1788350400", string(encoded))

	var decoded UnixTime
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.True(t, moment.Equal(decoded.Time))

	require.NoError(t, json.Unmarshal([]byte("null"), &decoded))
	require.True(t, decoded.IsZero())

	for _, malformed := range []string{`"1788350400"`, `1788350400.5`, `-1`, `0`, `"2026-09-02T12:00:00Z"`} {
		require.Error(t, json.Unmarshal([]byte(malformed), &decoded), "input %s", malformed)
	}

	zero, err := json.Marshal(UnixTime{})
	require.NoError(t, err)
	require.Equal(t, "null", string(zero))
}

func TestNewUnixTime_TruncatesToTheSecond(t *testing.T) {
	moment := time.Date(2026, 9, 2, 12, 0, 0, 999_999_999, time.UTC)
	require.True(t, NewUnixTime(moment).Equal(moment.Truncate(time.Second)))
}

func TestCertificate_JSON(t *testing.T) {
	_, ca := NewTestCA(t, "Some CA", nil, nil)

	encoded, err := json.Marshal(Certificate{ca})
	require.NoError(t, err)

	var decoded Certificate
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.True(t, ca.Equal(decoded.Certificate))

	require.NoError(t, json.Unmarshal([]byte("null"), &decoded))
	require.Nil(t, decoded.Certificate)

	require.ErrorContains(t, json.Unmarshal([]byte(`"not base64!"`), &decoded), "not base64")
	require.ErrorContains(t, json.Unmarshal([]byte(`"aGVsbG8="`), &decoded), "not a DER certificate")
	require.ErrorContains(t, json.Unmarshal([]byte(`42`), &decoded), "expected a base64 string")

	nothing, err := json.Marshal(Certificate{})
	require.NoError(t, err)
	require.Equal(t, "null", string(nothing))
}

// The wire shape of a handle is its type plus that type's fields, nothing else.
func TestHandle_JSONCarriesOnlyItsOwnFields(t *testing.T) {
	encoded, err := json.Marshal(Handle{Type: HandleTypeDID, DID: "did:web:x.example"})
	require.NoError(t, err)
	require.JSONEq(t, `{"type":"did","did":"did:web:x.example"}`, string(encoded))

	_, ca := NewTestCA(t, "Some CA", nil, nil)
	encoded, err = json.Marshal(Handle{Type: HandleTypeX509CA, RootCertificate: &Certificate{ca}, CRLDistributionPoints: []string{"https://crl.example/ca.crl"}})
	require.NoError(t, err)
	var shape map[string]any
	require.NoError(t, json.Unmarshal(encoded, &shape))
	require.ElementsMatch(t, []string{"type", "root_certificate", "crl_distribution_points"}, keysOf(shape))
	require.IsType(t, "", shape["root_certificate"], "a certificate travels as a base64 string")
}

func TestTrustedEntity_HasRole(t *testing.T) {
	entity := TrustedEntity{Roles: []Role{RoleIssuer}}
	require.True(t, entity.HasRole(RoleIssuer))
	require.False(t, entity.HasRole(RoleVerifier))
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// fullyFeaturedConfig exercises every handle type, both constraint kinds, a logo
// and both roles.
func fullyFeaturedConfig(t *testing.T) *Config {
	t.Helper()
	rootKey, root := NewTestCA(t, "Party Root CA", nil, nil)
	intermediateKey, intermediate := NewTestCA(t, "Party Issuing CA", root, rootKey)
	_, party := NewTestEndEntity(t, "party.example", intermediate, intermediateKey, nil)

	config := NewTestConfig("test", 1, time.Now())
	config.MinimumAppBuild = 812340
	config.Policy.MinimumTrustLevel.Disclosure = clientmodels.TrustLevel_Medium
	config.TrustedEntities = []TrustedEntity{
		{
			ID:         "party-ca",
			Name:       clientmodels.TranslatedString{"en": "Party CA"},
			Roles:      []Role{RoleIssuer, RoleVerifier},
			TrustLevel: clientmodels.TrustLevel_Medium,
			Handles: []Handle{{
				Type:                  HandleTypeX509CA,
				RootCertificate:       &Certificate{root},
				Intermediates:         []Certificate{{intermediate}},
				CRLDistributionPoints: []string{"https://crl.example/root.crl"},
			}},
		},
		{
			ID:         "party",
			Name:       clientmodels.TranslatedString{"en": "Party", "nl": "Partij"},
			Logo:       &Logo{URL: "https://assets.example/party.png", Digest: "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="},
			Roles:      []Role{RoleIssuer, RoleVerifier},
			TrustLevel: clientmodels.TrustLevel_High,
			Handles: []Handle{
				{Type: HandleTypeX509Cert, Certificate: &Certificate{party}},
				{Type: HandleTypeDID, DID: "did:web:party.example"},
			},
			Constraints: &Constraints{
				Issuance:   &IssuanceConstraint{AllowedCredentials: []string{"https://party.example/vct/email"}},
				Disclosure: &DisclosureConstraint{AllowedQueries: []AllowedQuery{{Credential: "https://party.example/vct/email", Attributes: []string{"email"}}}},
			},
		},
	}
	return config
}
