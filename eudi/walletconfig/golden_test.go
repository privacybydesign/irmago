package walletconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/stretchr/testify/require"
)

// A committed, signed config — the one document in the suite this package did
// not marshal itself, and so the only test that notices a JSON tag or a header
// changing. Every other test builds its config out of the structs in model.go,
// so a rename passes the whole suite while breaking every config a real
// publisher emits.
//
// testdata/walletconfig/golden/config.json is the same payload in readable
// form, kept honest by TestGolden_ReadableCopyMatchesTheSignedOne.
//
// It must not rot: Verify does not check the config's own time bounds, the
// assertions pin a clock inside every validity window rather than reading the
// wall clock, and the certificates live for decades. Regenerate with
// `go run ./testdata/walletconfig/mkgolden`; keep the constants below in step.

var (
	goldenIssuedAt   = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	goldenNextUpdate = goldenIssuedAt.Add(30 * 24 * time.Hour)
	goldenGrace      = 7 * 24 * time.Hour
	// goldenNow is the moment every assertion here is evaluated at.
	goldenNow = goldenIssuedAt.Add(12 * time.Hour)
)

func goldenDir() string {
	// eudi/walletconfig → repo root.
	return filepath.Join("..", "..", "testdata", "walletconfig", "golden")
}

func goldenRaw(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenDir(), "config.jws"))
	require.NoError(t, err)
	return raw
}

func goldenEnvironment(t *testing.T) Environment {
	t.Helper()
	rootPem, err := os.ReadFile(filepath.Join(goldenDir(), "root.crt"))
	require.NoError(t, err)
	chain, err := utils.ParsePemCertificateChain(rootPem)
	require.NoError(t, err)
	require.Len(t, chain, 1)
	return Environment{
		Name:              "golden",
		ConfigID:          "yivi-golden",
		ConfigURL:         "https://config.golden.example/wallet-config/v1/",
		SigningRoot:       chain[0],
		BundledConfigPath: filepath.Join(goldenDir(), "config.jws"),
	}
}

func TestGolden_VerifiesAndParses(t *testing.T) {
	verified, err := Verify(goldenRaw(t), goldenEnvironment(t), goldenNow)
	require.NoError(t, err)
	config := verified.Config

	require.Equal(t, "1.0", config.SchemaVersion)
	require.Equal(t, "yivi-golden", config.ID)
	require.Equal(t, "golden", config.Environment)
	require.Equal(t, uint64(1), config.Version)
	require.True(t, goldenIssuedAt.Equal(config.IssuedAt.Time))
	require.True(t, goldenNextUpdate.Equal(config.NextUpdate.Time))
	require.Equal(t, goldenGrace, config.GracePeriod())
	require.Equal(t, int64(100), config.MinimumAppBuild)
	require.Equal(t, clientmodels.TrustLevel_Low, config.Policy.MinimumTrustLevel.Issuance)
	require.Equal(t, clientmodels.TrustLevel_Medium, config.Policy.MinimumTrustLevel.Disclosure)

	require.Len(t, config.TrustedEntities, 3)

	ca := config.TrustedEntities[0]
	require.Equal(t, "golden-issuer-ca", ca.ID)
	require.Equal(t, "Gouden Uitgevers", ca.Name["nl"])
	require.Equal(t, []Role{RoleIssuer}, ca.Roles)
	require.Equal(t, clientmodels.TrustLevel_High, ca.TrustLevel)
	require.Len(t, ca.Handles, 1)
	require.Equal(t, HandleTypeX509CA, ca.Handles[0].Type)
	require.Equal(t, "Golden Issuer Root CA", ca.Handles[0].RootCertificate.Subject.CommonName)
	require.Len(t, ca.Handles[0].Intermediates, 1)
	require.Equal(t, "Golden Issuer CA", ca.Handles[0].Intermediates[0].Subject.CommonName)
	require.Equal(t, []string{"https://crl.golden.example/root.crl"}, ca.Handles[0].CRLDistributionPoints)
	require.Nil(t, ca.Constraints)

	party := config.TrustedEntities[1]
	require.Equal(t, "golden-party", party.ID)
	require.Equal(t, []Role{RoleIssuer, RoleVerifier}, party.Roles)
	require.Equal(t, "https://assets.golden.example/party.png", party.Logo.URL)
	require.Equal(t, HandleTypeDID, party.Handles[0].Type)
	require.Equal(t, "did:web:party.golden.example", party.Handles[0].DID)
	require.Equal(t, []string{"https://golden.example/vct/email"}, party.Constraints.Issuance.AllowedCredentials)

	verifier := config.TrustedEntities[2]
	require.Equal(t, "golden-verifier", verifier.ID)
	require.Equal(t, []Role{RoleVerifier}, verifier.Roles)
	require.Equal(t, clientmodels.TrustLevel_Medium, verifier.TrustLevel)
	require.Equal(t, HandleTypeX509Cert, verifier.Handles[0].Type)
	require.Equal(t, []string{"verifier.golden.example"}, verifier.Handles[0].Certificate.DNSNames)
	require.NotNil(t, verifier.Constraints.Disclosure)
	require.Equal(t, []AllowedQuery{{Credential: "https://golden.example/vct/email", Attributes: []string{"email"}}},
		verifier.Constraints.Disclosure.AllowedQueries)
	require.Nil(t, verifier.Constraints.Issuance)

	require.Equal(t, "yivi-golden-config-signer", verified.Signer.Subject.CommonName)
}

func TestGolden_ReadableCopyMatchesTheSignedOne(t *testing.T) {
	verified, err := Verify(goldenRaw(t), goldenEnvironment(t), goldenNow)
	require.NoError(t, err)

	readable, err := os.ReadFile(filepath.Join(goldenDir(), "config.json"))
	require.NoError(t, err)
	var fromReadable Config
	require.NoError(t, json.Unmarshal(readable, &fromReadable))

	require.JSONEq(t, string(mustJSON(t, &fromReadable)), string(mustJSON(t, verified.Config)))
}

func TestGolden_FreshnessWindow(t *testing.T) {
	verified, err := Verify(goldenRaw(t), goldenEnvironment(t), goldenNow)
	require.NoError(t, err)

	require.Equal(t, Fresh, verified.Config.FreshnessAt(goldenNow))
	require.Equal(t, Stale, verified.Config.FreshnessAt(goldenNextUpdate.Add(time.Hour)))
	require.Equal(t, Expired, verified.Config.FreshnessAt(goldenNextUpdate.Add(goldenGrace)))
}

// The bundled-asset path end to end, with a real file: what a wallet does on its
// first, offline run.
func TestGolden_LoadsAsABundledConfig(t *testing.T) {
	clock := NewTestClock(goldenNow)
	store := NewMemoryStore()
	m, err := NewManager(Options{
		Environments: []Environment{goldenEnvironment(t)},
		Active:       "golden",
		Store:        store,
		Now:          clock.Now,
	})
	require.NoError(t, err)

	snapshot := m.Snapshot()
	require.NotNil(t, snapshot.Config)
	require.Equal(t, uint64(1), snapshot.Config.Version)
	require.Equal(t, Fresh, snapshot.Freshness)

	persisted, ok := store.Get("yivi-golden")
	require.True(t, ok)
	require.Equal(t, goldenRaw(t), persisted)
}

// The fixture verifies only under its own root: the golden root is not a test
// signer's, and vice versa.
func TestGolden_DoesNotVerifyUnderAnotherRoot(t *testing.T) {
	other := NewTestSigner(t)
	_, err := Verify(goldenRaw(t), other.Environment("golden", testConfigURL), goldenNow)
	require.ErrorContains(t, err, "unknown authority")
}
