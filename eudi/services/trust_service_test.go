package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipherstorage"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

// trustWorld is a wallet's trust machinery over one test environment: a config
// signer, a config server, the eudi configuration with its trust models, and a
// credential store to rank stored credentials from.
type trustWorld struct {
	signer    *walletconfig.TestSigner
	server    *walletconfig.TestServer
	clock     *walletconfig.TestClock
	store     *walletconfig.MemoryStore
	manager   *walletconfig.Manager
	conf      *eudi.Configuration
	credStore db.CredentialStore
	service   *TrustService
}

func newTrustWorld(t *testing.T, config *walletconfig.Config, builtin ...walletconfig.TrustedEntity) *trustWorld {
	t.Helper()
	w := &trustWorld{
		signer: walletconfig.NewTestSigner(t),
		server: walletconfig.NewTestServer(t),
		clock:  walletconfig.NewTestClock(time.Now().Truncate(time.Second)),
		store:  walletconfig.NewMemoryStore(),
	}
	env := w.signer.Environment("test", w.server.URL)
	env.BuiltinEntities = builtin
	if config != nil {
		require.NoError(t, w.store.Put(config.ID, w.signer.Sign(t, config)))
	}

	var err error
	w.manager, err = walletconfig.NewManager(walletconfig.Options{
		Environments: []walletconfig.Environment{env, {Name: "other"}},
		Active:       "test",
		Store:        w.store,
		HTTPClient:   w.server.Client(),
		Now:          w.clock.Now,
	})
	require.NoError(t, err)

	eudiAppDataPath := filepath.Join(test.CreateTestStorage(t), "eudi")
	require.NoError(t, common.EnsureDirectoryExists(eudiAppDataPath))
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	storage, err := sqlcipherstorage.New(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = storage.Close() })

	w.conf, err = eudi.NewConfiguration(storage)
	require.NoError(t, err)
	w.conf.WalletConfig = w.manager
	require.NoError(t, w.conf.Reload())

	w.credStore = db.NewCredentialStore(storage.Db())
	w.service = NewTrustService(w.manager, w.conf, w.credStore, 0)
	return w
}

func testConfigWith(now time.Time, entities ...walletconfig.TrustedEntity) *walletconfig.Config {
	config := walletconfig.NewTestConfig("test", 1, now)
	config.TrustedEntities = entities
	return config
}

func didIssuer(id, did string, level clientmodels.TrustLevel) walletconfig.TrustedEntity {
	return walletconfig.TrustedEntity{
		ID: id, Name: clientmodels.TranslatedString{"en": id},
		Roles: []walletconfig.Role{walletconfig.RoleIssuer}, TrustLevel: level,
		Handles: []walletconfig.Handle{{Type: walletconfig.HandleTypeDID, DID: did}},
	}
}

// storeBatch stores a one-instance batch issued under iss with the raw credential.
func (w *trustWorld) storeBatch(t *testing.T, hash, iss string, raw []byte) *models.CredentialBatch {
	t.Helper()
	batch := &models.CredentialBatch{
		IssuerIdentifier:           iss,
		CredentialIssuerIdentifier: iss,
		VerifiableCredentialType:   "https://example.com/vct",
		Format:                     models.CredentialFormatSdJwtVc,
		Hash:                       hash,
		ProcessedSdJwtPayload:      datatypes.JSON([]byte(`{}`)),
		IssuedAt:                   datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
		BatchSize:                  1,
		RemainingCount:             1,
		Instances:                  []models.IssuedCredentialInstance{{RawCredential: raw}},
	}
	require.NoError(t, w.credStore.StoreBatch(batch))
	return batch
}

// rawSdJwtSignedBy is an SD-JWT whose issuer-signed JWT carries the signer's
// certificate in x5c. The signature is real but nothing here verifies it: a
// stored credential verified at issuance.
func rawSdJwtSignedBy(t *testing.T, signer *walletconfig.TestSigner) []byte {
	t.Helper()
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "dc+sd-jwt"))
	require.NoError(t, headers.Set(jws.X509CertChainKey, walletconfig.TestChainHeader(t, signer.Cert)))
	signed, err := jws.Sign([]byte(`{"vct":"https://example.com/vct"}`), jws.WithKey(jwa.ES256(), signer.Key, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return append(signed, '~')
}

func TestIssuerCertificateFromRawSdJwt(t *testing.T) {
	signer := walletconfig.NewTestSigner(t)
	certificate := IssuerCertificateFromRawSdJwt(rawSdJwtSignedBy(t, signer))
	require.NotNil(t, certificate)
	require.True(t, signer.Cert.Equal(certificate))

	require.Nil(t, IssuerCertificateFromRawSdJwt([]byte("not a jwt")))
	require.Nil(t, IssuerCertificateFromRawSdJwt([]byte("eyJhbGciOiJFUzI1NiJ9.e30.sig~")), "no x5c, no certificate")
}

func TestTrustService_RanksAStoredCredentialsIssuerByDID(t *testing.T) {
	w := newTrustWorld(t, testConfigWith(time.Now(), didIssuer("listed", "did:web:issuer.example", clientmodels.TrustLevel_Medium)))
	listed := w.storeBatch(t, "listed", "did:web:issuer.example", []byte("eyJhbGciOiJFUzI1NiJ9.e30.sig~"))
	stranger := w.storeBatch(t, "stranger", "did:web:stranger.example", []byte("eyJhbGciOiJFUzI1NiJ9.e30.sig~"))

	level, meets := w.service.IssuerStanding(listed)
	require.Equal(t, clientmodels.TrustLevel_Medium, level)
	require.True(t, meets)

	level, meets = w.service.IssuerStanding(stranger)
	require.Equal(t, clientmodels.TrustLevel_Low, level)
	require.True(t, meets, "the default policy admits low")
}

// The certificate an x5c issuer signed with is read off the stored credential,
// so the credential's rung follows the config as anchors come and go.
func TestTrustService_RanksAStoredCredentialsIssuerByCertificate(t *testing.T) {
	issuerCA := walletconfig.NewTestSigner(t) // its Root/Intermediate/Cert stand in for an issuer CA and its leaf
	config := testConfigWith(time.Now(), walletconfig.TrustedEntity{
		ID: "issuer-ca", Name: clientmodels.TranslatedString{"en": "Issuer CA"},
		Roles: []walletconfig.Role{walletconfig.RoleIssuer}, TrustLevel: clientmodels.TrustLevel_High,
		Handles: []walletconfig.Handle{{
			Type:            walletconfig.HandleTypeX509CA,
			RootCertificate: &walletconfig.Certificate{Certificate: issuerCA.Root},
			Intermediates:   []walletconfig.Certificate{{Certificate: issuerCA.Intermediate}},
		}},
	})
	w := newTrustWorld(t, config)
	batch := w.storeBatch(t, "x5c", "https://issuer.example", rawSdJwtSignedBy(t, issuerCA))

	level, meets := w.service.IssuerStanding(batch)
	require.Equal(t, clientmodels.TrustLevel_High, level)
	require.True(t, meets)

	evidence := w.service.BatchIssuerEvidence(batch)
	require.True(t, issuerCA.Cert.Equal(evidence.Certificate))
	require.Empty(t, evidence.DID)
}

func TestTrustService_IssuerBelowThePolicyDoesNotMeetIt(t *testing.T) {
	config := testConfigWith(time.Now(), didIssuer("listed", "did:web:issuer.example", clientmodels.TrustLevel_Medium))
	config.Policy.MinimumTrustLevel.Issuance = clientmodels.TrustLevel_Medium
	w := newTrustWorld(t, config)
	listed := w.storeBatch(t, "listed", "did:web:issuer.example", []byte("eyJhbGciOiJFUzI1NiJ9.e30.sig~"))
	stranger := w.storeBatch(t, "stranger", "did:web:stranger.example", []byte("eyJhbGciOiJFUzI1NiJ9.e30.sig~"))

	_, meets := w.service.IssuerStanding(listed)
	require.True(t, meets)
	level, meets := w.service.IssuerStanding(stranger)
	require.Equal(t, clientmodels.TrustLevel_Low, level)
	require.False(t, meets, "below the issuance minimum: badged and excluded from disclosure")
}

// A refresh that changes the config rebuilds the trust models, so a CA the new
// config lists anchors at once.
func TestTrustService_RefreshReloadsTheTrustModels(t *testing.T) {
	w := newTrustWorld(t, testConfigWith(time.Now()))
	issuerCA := walletconfig.NewTestSigner(t)
	_, err := w.conf.Issuers.ValidateChain(issuerCA.Cert)
	require.Error(t, err, "nothing anchors the issuer CA yet")

	next := testConfigWith(w.clock.Now(), walletconfig.TrustedEntity{
		ID: "issuer-ca", Name: clientmodels.TranslatedString{"en": "Issuer CA"},
		Roles: []walletconfig.Role{walletconfig.RoleIssuer}, TrustLevel: clientmodels.TrustLevel_High,
		Handles: []walletconfig.Handle{{
			Type:            walletconfig.HandleTypeX509CA,
			RootCertificate: &walletconfig.Certificate{Certificate: issuerCA.Root},
			Intermediates:   []walletconfig.Certificate{{Certificate: issuerCA.Intermediate}},
		}},
	})
	next.Version = 2
	w.server.SetBody(w.signer.Sign(t, next))

	changed, err := w.service.Refresh(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	_, err = w.conf.Issuers.ValidateChain(issuerCA.Cert)
	require.NoError(t, err, "the listed CA anchors after the refresh")

	changed, err = w.service.Refresh(context.Background())
	require.NoError(t, err)
	require.False(t, changed, "throttled and unchanged")
}

func TestTrustService_SwitchEnvironmentRebuildsTheTrustModels(t *testing.T) {
	builtinCA := walletconfig.NewTestSigner(t)
	w := newTrustWorld(t, nil, walletconfig.TrustedEntity{
		ID: "builtin-ca", Name: clientmodels.TranslatedString{"en": "Built-in CA"},
		Roles: []walletconfig.Role{walletconfig.RoleVerifier}, TrustLevel: clientmodels.TrustLevel_High,
		Handles: []walletconfig.Handle{{
			Type:            walletconfig.HandleTypeX509CA,
			RootCertificate: &walletconfig.Certificate{Certificate: builtinCA.Root},
			Intermediates:   []walletconfig.Certificate{{Certificate: builtinCA.Intermediate}},
		}},
	})
	_, err := w.conf.Verifiers.ValidateChain(builtinCA.Cert)
	require.NoError(t, err)
	require.Equal(t, "test", w.service.Environment().Name)

	require.NoError(t, w.service.SwitchEnvironment("other"))
	require.Equal(t, "other", w.service.Environment().Name)
	_, err = w.conf.Verifiers.ValidateChain(builtinCA.Cert)
	require.Error(t, err, "the other environment anchors none of this one's CAs")

	require.ErrorContains(t, w.service.SwitchEnvironment("nowhere"), "not one of the configured environments")
}

func TestLoadCuratedLogo(t *testing.T) {
	logoBytes := []byte("png bytes")
	digest := sha256.Sum256(logoBytes)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(logoBytes)
	}))
	t.Cleanup(server.Close)
	manager := filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()).Verifiers().LogoManager()

	logo := &walletconfig.Logo{URL: server.URL + "/logo.png", Digest: "sha256-" + base64.StdEncoding.EncodeToString(digest[:])}
	image := LoadCuratedLogo(context.Background(), manager, server.Client(), logo)
	require.NotNil(t, image)
	require.Equal(t, base64.StdEncoding.EncodeToString(logoBytes), image.Base64)
	require.Equal(t, "image/png", *image.MimeType)

	// Served from the cache the second time.
	server.Close()
	require.NotNil(t, LoadCuratedLogo(context.Background(), manager, server.Client(), logo))

	// A logo whose bytes do not match the curator's digest is not shown.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("tampered")) }))
	t.Cleanup(other.Close)
	expected := sha256.Sum256([]byte("what the curator saw"))
	tampered := &walletconfig.Logo{URL: other.URL + "/logo.png", Digest: "sha256-" + base64.StdEncoding.EncodeToString(expected[:])}
	require.Nil(t, LoadCuratedLogo(context.Background(), manager, other.Client(), tampered))

	require.Nil(t, LoadCuratedLogo(context.Background(), manager, nil, nil))
	require.Nil(t, LoadCuratedLogo(context.Background(), nil, nil, logo))
}

func TestDigestMatches(t *testing.T) {
	data := []byte("hello")
	sum := sha256.Sum256(data)
	require.True(t, digestMatches("sha256-"+base64.StdEncoding.EncodeToString(sum[:]), data))
	require.False(t, digestMatches("sha256-"+base64.StdEncoding.EncodeToString(sum[:]), []byte("other")))
	require.False(t, digestMatches("md5-abc", data))
	require.False(t, digestMatches("sha256-not base64!", data))
	require.True(t, strings.HasPrefix(curatedLogoKey(&walletconfig.Logo{Digest: "sha256-x"}), "curated-"))
}
