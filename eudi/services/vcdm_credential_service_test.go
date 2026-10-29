package services

import (
	"crypto"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdmsdjwt"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt/sdjwttest"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const testVcdmIssuer = "https://openid4vc.staging.yivi.app"

var testVcdmTypeIdentity = vcdm.ContextV2 + " " + vcdm.TypeVerifiableCredential + " ExampleCredential"

type vcdmTestEnv struct {
	db      *gorm.DB
	store   db.VcdmStore
	keys    db.HolderBindingKeyStore
	service *sdJwtVcdmCredentialService
	parser  CredentialFormatParser
}

func newVcdmTestEnv(t *testing.T) *vcdmTestEnv {
	t.Helper()
	d := newTestHolderDB(t)
	store := db.NewVcdmStore(d)
	keys := db.NewHolderBindingKeyStore(d)
	fs := filesystem.NewFileSystemStorage([32]byte{}, t.TempDir())
	revocation := NewRevocationService(nil, nil, store)
	return &vcdmTestEnv{
		db:      d,
		store:   store,
		keys:    keys,
		service: NewSdJwtVcdmCredentialService(store, keys, fs, revocation, clientmodels.NewCurrentLocale("en")),
		parser:  NewSdJwtVcdmCredentialFormatParser(newTestVcdmHolderVerifier()),
	}
}

// newTestVcdmHolderVerifier checks status the way the wallet does, trusting the
// test issuer for status lists as well as credentials.
func newTestVcdmHolderVerifier() *vcdmsdjwt.HolderVerificationProcessor {
	ctx := vcdmsdjwt.CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	ctx.StatusChecker = statuslist.NewChecker(statuslist.VerificationContext{X509Context: ctx.X509VerificationContext}, nil)
	ctx.BitstringStatusChecker = newTestBitstringChecker(ctx)
	return vcdmsdjwt.NewHolderVerificationProcessor(ctx)
}

// newRawVcdm builds a real SD-JWT-secured VCDM credential signed with the test
// issuer key and bound to the test holder key.
func newRawVcdm(t *testing.T, subjectClaims ...*sdjwt.ClaimElement) string {
	t.Helper()
	x5c, err := utils.ParsePemCertificateChainToX5cFormat(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	require.NoError(t, err)
	cnf, err := sdjwt.HolderKeyClaim(testdata.ParseHolderPubJwk())
	require.NoError(t, err)

	subject := append([]*sdjwt.ClaimElement{sdjwt.Claim("id", "did:example:holder")}, subjectClaims...)
	claims := []*sdjwt.ClaimElement{
		sdjwt.Array(vcdm.ContextKey, sdjwt.Item(vcdm.ContextV2)),
		sdjwt.Array(vcdm.TypeKey, sdjwt.Item(vcdm.TypeVerifiableCredential), sdjwt.Item("ExampleCredential")),
		sdjwt.Claim(vcdm.IssuerKey, testVcdmIssuer),
		sdjwt.Claim(vcdm.ValidFromKey, "2020-01-01T00:00:00Z"),
		sdjwt.Claim(vcdm.ValidUntilKey, "2035-01-01T00:00:00Z"),
		sdjwt.Object(vcdm.CredentialSubjectKey, subject...),
		cnf,
	}

	built, err := sdjwt.NewBuilder().
		WithPayload(claims...).
		WithIssuerCertificateChain(x5c).
		WithTyp(vcdmsdjwt.MediaTypeVcSdJwt).
		Build(sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey())
	require.NoError(t, err)
	return string(built)
}

func (e *vcdmTestEnv) parse(t *testing.T, raw string) *ParsedCredential {
	t.Helper()
	parsed, err := e.parser.ParseAndVerify(raw, testVcdmIssuer, false)
	require.NoError(t, err)
	return parsed
}

func (e *vcdmTestEnv) issuerMetadata() metadata.CredentialIssuerMetadata {
	md := newMinimalIssuerMetadata("config-id", metadata.CredentialFormatIdentifier_SdJwtVcdm)
	md.CredentialIssuer = testVcdmIssuer
	return md
}

func TestSdJwtVcdmParser_ParsesVcdm(t *testing.T) {
	env := newVcdmTestEnv(t)
	parsed := env.parse(t, newRawVcdm(t, sdjwt.SdClaim("given_name", "Alice")))

	assert.Equal(t, models.CredentialFormatSdJwtVcdm, parsed.Format)
	assert.Equal(t, testVcdmTypeIdentity, parsed.VerifiableCredentialType)
	assert.Equal(t, testVcdmIssuer, parsed.IssuerIdentifier)
	require.NotNil(t, parsed.SdJwtVcdm)
	assert.Nil(t, parsed.SdJwtVc)

	// No JWT iat/exp were signed, so validity comes from the document.
	require.NotNil(t, parsed.IssuedAt)
	assert.Equal(t, int64(1577836800), *parsed.IssuedAt) // 2020-01-01T00:00:00Z
	require.NotNil(t, parsed.ExpiresAt)
	assert.Equal(t, int64(2051222400), *parsed.ExpiresAt) // 2035-01-01T00:00:00Z
}

func TestSdJwtVcdmStore_EmptySlice(t *testing.T) {
	env := newVcdmTestEnv(t)

	require.NoError(t, env.service.Store(nil, "config-id", env.issuerMetadata(), false, nil))

	batches, err := env.store.ListBatches()
	require.NoError(t, err)
	assert.Empty(t, batches)
}

func TestSdJwtVcdmStore_StoresBatch(t *testing.T) {
	env := newVcdmTestEnv(t)
	raw := newRawVcdm(t, sdjwt.SdClaim("given_name", "Alice"))

	require.NoError(t, env.service.Store([]*ParsedCredential{env.parse(t, raw)}, "config-id", env.issuerMetadata(), false, nil))

	batches, err := env.store.ListBatches()
	require.NoError(t, err)
	require.Len(t, batches, 1)
	batch := batches[0]

	assert.Equal(t, models.CredentialFormatSdJwtVcdm, batch.Format)
	assert.Equal(t, testVcdmTypeIdentity, batch.TypeIdentity)
	assert.Equal(t, testVcdmIssuer, batch.IssuerIdentifier)
	assert.Equal(t, testVcdmIssuer, batch.CredentialIssuer)
	assert.NotEmpty(t, batch.Hash)
	assert.True(t, batch.IssuerVerified)
	assert.Equal(t, int64(1577836800), batch.IssuedAt.Unix())
	require.True(t, batch.ExpiresAt.Valid)
	assert.Equal(t, int64(2051222400), batch.ExpiresAt.V.Unix())

	instance, err := env.store.GetUnusedInstance(batch.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte(raw), instance.RawCredential)
}

func TestSdJwtVcdmStore_ReissuanceReplacesBatch(t *testing.T) {
	env := newVcdmTestEnv(t)
	md := env.issuerMetadata()

	for _, name := range []string{"Alice", "Alice", "Bob"} {
		parsed := env.parse(t, newRawVcdm(t, sdjwt.SdClaim("given_name", name)))
		require.NoError(t, env.service.Store([]*ParsedCredential{parsed}, "config-id", md, false, nil))
	}

	// The second Alice has the same content hash as the first and replaces it;
	// Bob is a different credential and sits next to it.
	batches, err := env.store.ListBatches()
	require.NoError(t, err)
	require.Len(t, batches, 2)
	assert.NotEqual(t, batches[0].Hash, batches[1].Hash)
}

func TestSdJwtVcdmStore_KeyBindingMismatch(t *testing.T) {
	env := newVcdmTestEnv(t)
	parsed := env.parse(t, newRawVcdm(t))

	err := env.service.Store([]*ParsedCredential{parsed}, "config-id", env.issuerMetadata(),
		true,                              // requireCryptographicKeyBinding
		[]models.PublicHolderBindingKey{}, // zero keys for one credential
	)
	require.Error(t, err)

	batches, err := env.store.ListBatches()
	require.NoError(t, err)
	assert.Empty(t, batches)
}

// The holder binding key is linked to the VCDM instance, and deleting the
// credential deletes the key with it.
func TestSdJwtVcdmStore_LinksAndDeletesHolderBindingKey(t *testing.T) {
	env := newVcdmTestEnv(t)
	parsed := env.parse(t, newRawVcdm(t))

	thumbprintBytes, err := testdata.ParseHolderPubJwk().Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	thumbprint := hex.EncodeToString(thumbprintBytes)
	key := &models.HolderBindingKey{
		Algorithm:           models.KeyAlgorithmECDSA,
		PublicKeyThumbprint: datatypes.NullString{V: thumbprint, Valid: true},
		PrivateKey:          []byte("not-a-real-key"),
		ECDSA:               &models.ECDSAKeyMetadata{CurveName: "P-256"},
	}
	require.NoError(t, env.keys.StoreKey(key))

	require.NoError(t, env.service.Store([]*ParsedCredential{parsed}, "config-id", env.issuerMetadata(),
		true, []models.PublicHolderBindingKey{{ID: key.ID, PublicKeyThumbprint: &thumbprint}}))

	batches, err := env.store.ListBatches()
	require.NoError(t, err)
	require.Len(t, batches, 1)
	instance, err := env.store.GetUnusedInstance(batches[0].ID)
	require.NoError(t, err)
	require.NotNil(t, instance.HolderBindingKey)
	assert.Equal(t, key.ID, instance.HolderBindingKey.ID)

	require.NoError(t, env.service.DeleteByHash(batches[0].Hash))
	_, err = env.keys.GetByID(key.ID)
	require.ErrorIs(t, err, db.ErrNotFound)
}

func TestSdJwtVcdmList_SubjectRootedAttributes(t *testing.T) {
	env := newVcdmTestEnv(t)
	parsed := env.parse(t, newRawVcdm(t, sdjwt.SdClaim("given_name", "Alice")))
	require.NoError(t, env.service.Store([]*ParsedCredential{parsed}, "config-id", env.issuerMetadata(), false, nil))

	list, err := env.service.List()
	require.NoError(t, err)
	require.Len(t, list, 1)

	cred := list[0]
	assert.Equal(t, testVcdmTypeIdentity, cred.CredentialId)
	assert.Equal(t, map[clientmodels.CredentialFormat]string{clientmodels.Format_SdJwtVcdm: cred.Hash}, cred.CredentialInstanceIds)
	assert.True(t, cred.Issuer.Verified)

	// Attributes are the credentialSubject tree with document-rooted paths; the
	// VCDM envelope properties are not attributes.
	paths := make([][]any, len(cred.Attributes))
	for i, a := range cred.Attributes {
		paths[i] = a.ClaimPath
	}
	assert.ElementsMatch(t, [][]any{
		{vcdm.CredentialSubjectKey, "id"},
		{vcdm.CredentialSubjectKey, "given_name"},
	}, paths)
}

func TestVcdmDocumentName(t *testing.T) {
	doc := vcdm.Document{vcdm.NameKey: []any{
		map[string]any{"@value": "Alumni card", "@language": "en-GB"},
		map[string]any{"@value": "Alumnikaart", "@language": "nl-NL"},
	}}
	require.Equal(t, "Alumnikaart", VcdmDocumentName(doc, "nl"), "region tags resolve by base language")
	require.Equal(t, "Alumni card", VcdmDocumentName(doc, "de"), "unknown locale falls back to English")

	plain := vcdm.Document{vcdm.NameKey: "Alumni card"}
	require.Equal(t, "Alumni card", VcdmDocumentName(plain, "nl"), "a plain string is used for every locale")

	require.Empty(t, VcdmDocumentName(vcdm.Document{}, "en"))
}

func TestResolveVcdmDisplay_FallsBackToDocumentName(t *testing.T) {
	batch := &models.VcdmBatch{
		CredentialIssuer: testVcdmIssuer,
		ProcessedPayload: datatypes.JSON(`{"name": "Alumni card"}`),
	}
	require.Equal(t, "Alumni card", ResolveVcdmDisplay(batch, "en").CredentialName)

	batch.CredentialMetadata = datatypes.JSON(`{"display": [{"name": "Diploma", "locale": "en"}]}`)
	require.Equal(t, "Diploma", ResolveVcdmDisplay(batch, "en").CredentialName, "issuer metadata takes precedence")
}

// failingStoreBatch is a VcdmStore whose StoreBatch fails, as a write can.
type failingStoreBatch struct {
	db.VcdmStore
}

func (failingStoreBatch) StoreBatch(*models.VcdmBatch) error {
	return errors.New("disk full")
}

// A re-issuance replaces the stored batch with the same content. When storing
// the new batch fails, the old one must still be there: the user would
// otherwise lose the credential they had.
func TestSdJwtVcdmStore_FailedReissuanceKeepsTheStoredCredential(t *testing.T) {
	env := newVcdmTestEnv(t)
	raw := newRawVcdm(t, sdjwt.SdClaim("given_name", "Alice"))
	require.NoError(t, env.service.Store([]*ParsedCredential{env.parse(t, raw)}, "config-id", env.issuerMetadata(), false, nil))

	failing := NewSdJwtVcdmCredentialService(failingStoreBatch{env.store}, env.keys, filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()), nil, clientmodels.NewCurrentLocale("en"))
	err := failing.Store([]*ParsedCredential{env.parse(t, raw)}, "config-id", env.issuerMetadata(), false, nil)
	require.ErrorContains(t, err, "disk full")

	batches, err := env.store.ListBatches()
	require.NoError(t, err)
	require.Len(t, batches, 1, "the stored credential must survive a re-issuance that failed to store")
}

// The wallet records the credential's own dates, the JWT nbf and exp, as
// SD-JWT VC does. The document's validFrom/validUntil are the validity of the
// data, which is for a verifier to judge; they stand in only when the JWT has
// no such claim.
func TestVcdmIssuanceValidity(t *testing.T) {
	const (
		day1 = int64(1577836800) // 2020-01-01
		day2 = day1 + 86400
		day3 = day2 + 86400
		day4 = day3 + 86400
	)
	stamp := func(unix int64) string { return time.Unix(unix, 0).UTC().Format(time.RFC3339) }
	ptr := func(v int64) *int64 { return &v }

	cases := map[string]struct {
		nbf, exp              *int64
		validFrom, validUntil string
		wantNotBefore         *int64
		wantExpires           *int64
	}{
		"exp before validUntil": {exp: ptr(day2), validUntil: stamp(day4), wantExpires: ptr(day2)},
		"exp after validUntil":  {exp: ptr(day4), validUntil: stamp(day2), wantExpires: ptr(day4)},
		"only validUntil":       {validUntil: stamp(day3), wantExpires: ptr(day3)},
		"nbf before validFrom":  {nbf: ptr(day1), validFrom: stamp(day3), wantNotBefore: ptr(day1)},
		"only validFrom":        {validFrom: stamp(day3), wantNotBefore: ptr(day3)},
		"neither":               {},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			document := vcdm.Document{}
			if c.validFrom != "" {
				document[vcdm.ValidFromKey] = c.validFrom
			}
			if c.validUntil != "" {
				document[vcdm.ValidUntilKey] = c.validUntil
			}
			_, expiresAt, notBefore := VcdmIssuanceValidity(&vcdmsdjwt.VerifiedSdJwtVcdm{
				Document:         document,
				RegisteredClaims: sdjwt.RegisteredClaims{NotBefore: c.nbf, Expiry: c.exp},
			})
			assert.Equal(t, c.wantExpires, expiresAt)
			assert.Equal(t, c.wantNotBefore, notBefore)
		})
	}
}
