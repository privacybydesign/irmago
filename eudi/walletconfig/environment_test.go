package walletconfig

import (
	"context"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// The Yivi environments compile in the anchors that used to be PEM constants,
// as entities in the config's own model, and are unpublished until the config
// CA exists.
func TestYiviEnvironments(t *testing.T) {
	environments := YiviEnvironments()
	require.NoError(t, ValidateEnvironments(environments))
	require.Len(t, environments, 2)

	production, staging := environments[0], environments[1]
	require.Equal(t, EnvironmentProduction, production.Name)
	require.Equal(t, EnvironmentStaging, staging.Name)
	require.False(t, production.IsPublished())
	require.False(t, staging.IsPublished())

	names := func(env Environment) map[string]TrustedEntity {
		byID := map[string]TrustedEntity{}
		for _, entity := range env.BuiltinEntities {
			byID[entity.ID] = entity
		}
		return byID
	}
	prod := names(production)
	require.Len(t, prod, 3)
	issuers := prod["yivi-issuers"]
	require.Equal(t, []Role{RoleIssuer}, issuers.Roles)
	require.Equal(t, clientmodels.TrustLevel_High, issuers.TrustLevel)
	require.Len(t, issuers.Handles, 1)
	require.Equal(t, HandleTypeX509CA, issuers.Handles[0].Type)
	require.Equal(t, "Yivi Requestors Root CA", issuers.Handles[0].RootCertificate.Subject.CommonName)
	require.Len(t, issuers.Handles[0].Intermediates, 1)
	require.Equal(t, "Yivi Attestation Providers CA", issuers.Handles[0].Intermediates[0].Subject.CommonName)
	require.Len(t, issuers.Handles[0].CRLDistributionPoints, 2)
	require.Equal(t, "Yivi Relying Parties CA", prod["yivi-verifiers"].Handles[0].Intermediates[0].Subject.CommonName)
	require.Equal(t, []Role{RoleIssuer, RoleVerifier}, prod["verid"].Roles)
	require.Equal(t, "Ver.iD Root CA", prod["verid"].Handles[0].RootCertificate.Subject.CommonName)

	stag := names(staging)
	require.Equal(t, "Yivi Staging Requestors Root CA", stag["yivi-staging-issuers"].Handles[0].RootCertificate.Subject.CommonName)
	require.Equal(t, "Ver.iD Dev Root CA", stag["verid-dev"].Handles[0].RootCertificate.Subject.CommonName)
}

func TestValidateEnvironments_UnpublishedEnvironments(t *testing.T) {
	_, root := NewTestCA(t, "Some Root", nil, nil)
	builtin := []TrustedEntity{{
		ID: "x", Name: clientmodels.TranslatedString{"en": "X"}, Roles: []Role{RoleIssuer},
		TrustLevel: clientmodels.TrustLevel_High,
		Handles:    []Handle{{Type: HandleTypeDID, DID: "did:web:x.example"}},
	}}

	require.NoError(t, ValidateEnvironments([]Environment{{Name: "demo", BuiltinEntities: builtin}}),
		"an environment may run on built-in entities alone")
	require.ErrorContains(t, ValidateEnvironments([]Environment{{Name: "demo", ConfigURL: "https://config.example/"}}),
		"SigningRoot is nil")
	require.ErrorContains(t, ValidateEnvironments([]Environment{{Name: "demo", SigningRoot: root}}),
		"not an absolute URL")
	require.ErrorContains(t, ValidateEnvironments([]Environment{{Name: "demo", BundledConfigPath: "/some/bundle.jws"}}),
		"no SigningRoot to verify it against")

	broken := builtin
	broken[0].TrustLevel = "very_high"
	require.ErrorContains(t, ValidateEnvironments([]Environment{{Name: "demo", BuiltinEntities: broken}}),
		"built-in entities")
}

// An unpublished environment fetches nothing and holds no config; what it
// trusts is what is compiled in.
func TestManager_UnpublishedEnvironmentRunsOnBuiltinEntities(t *testing.T) {
	server := NewTestServer(t)
	env := Environment{
		Name: "demo",
		BuiltinEntities: []TrustedEntity{{
			ID: "x", Name: clientmodels.TranslatedString{"en": "X"}, Roles: []Role{RoleIssuer},
			TrustLevel: clientmodels.TrustLevel_High,
			Handles:    []Handle{{Type: HandleTypeDID, DID: "did:web:x.example"}},
		}},
	}
	m, err := NewManager(Options{Environments: []Environment{env}, Active: "demo", HTTPClient: server.Client()})
	require.NoError(t, err)

	snapshot := m.Snapshot()
	require.Nil(t, snapshot.Config)
	require.Equal(t, Absent, snapshot.Freshness)
	require.Len(t, snapshot.Environment.BuiltinEntities, 1)
	require.Equal(t, DefaultPolicy(), snapshot.Policy())
	require.Zero(t, snapshot.MinimumAppBuild())

	changed, err := m.Refresh(context.Background())
	require.NoError(t, err)
	require.False(t, changed)
	changed, err = m.RefreshIfDue(context.Background())
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, 0, server.Hits(), "nothing to fetch")
}

func TestSnapshot_PolicyAndMinimumAppBuild(t *testing.T) {
	config := NewTestConfig("test", 1, time.Now())
	config.Policy.MinimumTrustLevel.Disclosure = clientmodels.TrustLevel_Medium
	config.MinimumAppBuild = 42

	snapshot := Snapshot{Config: config}
	require.Equal(t, clientmodels.TrustLevel_Medium, snapshot.Policy().MinimumTrustLevel.Disclosure)
	require.Equal(t, int64(42), snapshot.MinimumAppBuild())

	require.Equal(t, DefaultPolicy(), Snapshot{}.Policy())
	require.True(t, DefaultPolicy().MinimumTrustLevel.Issuance.IsRung())
}
