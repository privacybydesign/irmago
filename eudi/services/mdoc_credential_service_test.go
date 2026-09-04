package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const (
	testMdocDocType   = "eu.europa.ec.av.1"
	testMdocIssuerURL = "https://av-issuer.example.com"
)

type mdocTestEnv struct {
	db       *gorm.DB
	store    db.MdocStore
	keys     db.MdocDeviceKeyStore
	service  *mdocCredentialService
	keyMint  *MdocKeyService
	issuer   *stdmdoc.Issuer
	parser   CredentialFormatParser
	metadata metadata.CredentialIssuerMetadata
}

func newMdocTestEnv(t *testing.T) *mdocTestEnv {
	t.Helper()
	d := newTestHolderDB(t)
	store := db.NewMdocStore(d)
	keys := db.NewMdocDeviceKeyStore(d)
	issuer, err := stdmdoc.NewIssuer()
	require.NoError(t, err)

	en := "en"
	return &mdocTestEnv{
		db:      d,
		store:   store,
		keys:    keys,
		service: NewMdocCredentialService(store, keys, filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()), clientmodels.NewCurrentLocale("en")),
		keyMint: NewMdocKeyService(keys),
		issuer:  issuer,
		parser:  NewMdocCredentialFormatParser(stdmdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})),
		metadata: metadata.CredentialIssuerMetadata{
			CredentialIssuer: testMdocIssuerURL,
			Display:          metadata.CredentialIssuerDisplays{{Display: metadata.Display{Name: "AV Issuer", Locale: &en}}},
			CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{
				"proof_of_age": {
					Format:  metadata.CredentialFormatIdentifier_MsoMdoc,
					Doctype: testMdocDocType,
					CredentialMetadata: &metadata.CredentialMetadata{
						Display: metadata.CredentialDisplays{{Display: metadata.Display{Name: "Proof of Age", Locale: &en}}},
						Claims: []metadata.ClaimsDescription{{
							Path:    metadata.ClaimsPathPointer{testMdocDocType, "age_over_18"},
							Display: []metadata.Display{{Name: "Older than 18", Locale: &en}},
						}},
					},
				},
			},
		},
	}
}

// issueBoundTo issues one mdoc with the given elements, bound to the device key
// stored under thumbprint, and runs it through the production parser.
func (e *mdocTestEnv) issueBoundTo(t *testing.T, thumbprint string, elements map[string]any) *ParsedCredential {
	t.Helper()
	stored, err := e.keys.GetByThumbprint(thumbprint)
	require.NoError(t, err)
	priv, err := decodePKCS8PrivateKey(stored.PrivateKey)
	require.NoError(t, err)
	return e.issueFor(t, &priv.PublicKey, elements)
}

func (e *mdocTestEnv) issueFor(t *testing.T, devicePub *ecdsa.PublicKey, elements map[string]any) *ParsedCredential {
	t.Helper()
	issued, err := e.issuer.Issue(testMdocDocType, testMdocDocType, elements, devicePub)
	require.NoError(t, err)
	raw, err := cbor.Marshal(issued)
	require.NoError(t, err)
	parsed, err := e.parser.ParseAndVerify(base64.RawURLEncoding.EncodeToString(raw), testMdocIssuerURL, true)
	require.NoError(t, err)
	return parsed
}

// The mdoc store matches issued documents to minted device keys by the thumbprint
// of the device public key in the MSO, whatever binding method the proof used —
// including the DID methods that used to make the shared key table fail with
// "no matching holder binding key found".
func TestMdocCredentialService_StoreLinksDeviceKeysByThumbprint(t *testing.T) {
	for _, method := range []proofs.CryptographicBindingMethod{
		proofs.CryptographicBindingMethod_JWK,
		proofs.CryptographicBindingMethod_DID_KEY,
		proofs.CryptographicBindingMethod_DID_JWK,
	} {
		t.Run(string(method), func(t *testing.T) {
			env := newMdocTestEnv(t)
			identifiers, _, err := env.keyMint.CreateKeyPairsWithProofs(2, testProofBuilder(method))
			require.NoError(t, err)

			parsed := []*ParsedCredential{
				env.issueBoundTo(t, *identifiers[0].PublicKeyThumbprint, map[string]any{"age_over_18": true}),
				env.issueBoundTo(t, *identifiers[1].PublicKeyThumbprint, map[string]any{"age_over_18": true}),
			}

			require.NoError(t, env.service.Store(parsed, "proof_of_age", env.metadata, true, identifiers))

			batches, err := env.store.ListBatches()
			require.NoError(t, err)
			require.Len(t, batches, 1)
			batch := batches[0]
			assert.Equal(t, testMdocDocType, batch.DocType)
			assert.Equal(t, testMdocIssuerURL, batch.CredentialIssuer)
			assert.Equal(t, uint(2), batch.BatchSize)
			assert.Equal(t, uint(2), batch.RemainingCount)
			assert.True(t, batch.IssuerVerified)
			assert.Equal(t, true, batch.Namespaces[testMdocDocType]["age_over_18"])
			assert.WithinDuration(t, parsed[0].Mdoc.ValidityInfo.ValidUntil, batch.ValidUntil, time.Second)

			// Every minted key is now bound to the instance whose MSO carries it.
			for _, id := range identifiers {
				key, err := env.keys.GetByThumbprint(*id.PublicKeyThumbprint)
				require.NoError(t, err)
				require.NotNil(t, key.MdocBatchInstanceID, "the device key must be linked to its instance")
			}
			inst, err := env.store.GetUnusedInstance(batch.ID)
			require.NoError(t, err)
			require.NotNil(t, inst.DeviceKey)
		})
	}
}

// A credential bound to a key the wallet did not mint aborts the issuance, and
// the keys that were minted for it are removed rather than left orphaned.
func TestMdocCredentialService_StoreRefusesUnmatchedDeviceKeyAndCleansUp(t *testing.T) {
	env := newMdocTestEnv(t)
	identifiers, _, err := env.keyMint.CreateKeyPairsWithProofs(1, testProofBuilder(proofs.CryptographicBindingMethod_JWK))
	require.NoError(t, err)

	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	parsed := []*ParsedCredential{env.issueFor(t, &stranger.PublicKey, map[string]any{"age_over_18": true})}

	err = env.service.Store(parsed, "proof_of_age", env.metadata, true, identifiers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no matching device key")

	batches, err := env.store.ListBatches()
	require.NoError(t, err)
	require.Empty(t, batches, "nothing is stored on a key mismatch")
	_, err = env.keys.GetByThumbprint(*identifiers[0].PublicKeyThumbprint)
	require.ErrorIs(t, err, db.ErrNotFound, "the minted keys are cleaned up")
}

func TestMdocCredentialService_StoreRejectsOtherFormats(t *testing.T) {
	env := newMdocTestEnv(t)
	err := env.service.Store([]*ParsedCredential{{Format: models.CredentialFormatSdJwtVc}}, "x", env.metadata, false, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an mdoc")
	require.NoError(t, env.service.Store(nil, "x", env.metadata, false, nil), "nothing to store is not an error")
}

// The display metadata is snapshotted as the issuer published it, and read back
// into the credential list: name, issuer name, claim labels.
func TestMdocCredentialService_StoreSnapshotsDisplayMetadataAndListRendersIt(t *testing.T) {
	env := newMdocTestEnv(t)
	identifiers, _, err := env.keyMint.CreateKeyPairsWithProofs(1, testProofBuilder(proofs.CryptographicBindingMethod_JWK))
	require.NoError(t, err)
	parsed := []*ParsedCredential{env.issueBoundTo(t, *identifiers[0].PublicKeyThumbprint, map[string]any{"age_over_18": true, "age_over_21": false})}
	require.NoError(t, env.service.Store(parsed, "proof_of_age", env.metadata, true, identifiers))

	batch, err := env.store.ListBatches()
	require.NoError(t, err)
	require.JSONEq(t, `[{"name":"AV Issuer","locale":"en"}]`, string(batch[0].IssuerDisplay))
	cm := MdocCredentialMetadata(batch[0])
	require.NotNil(t, cm)
	require.Equal(t, "Proof of Age", cm.Display[0].Name)

	creds, err := env.service.List()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	c := creds[0]
	assert.Equal(t, testMdocDocType, c.CredentialId)
	assert.Equal(t, batch[0].Hash, c.Hash)
	assert.Equal(t, "Proof of Age", c.Name)
	assert.Equal(t, "AV Issuer", c.Issuer.Name)
	assert.Equal(t, testMdocIssuerURL, c.Issuer.Id)
	assert.True(t, c.Issuer.Verified)
	assert.False(t, c.DisplayIsFallback)
	assert.Equal(t, map[clientmodels.CredentialFormat]string{clientmodels.Format_MsoMdoc: batch[0].Hash}, c.CredentialInstanceIds)
	assert.Nil(t, c.BatchInstanceCountsRemaining[clientmodels.Format_MsoMdoc], "a batch of one is reusable")
	require.NotNil(t, c.IssuanceDate)
	require.NotNil(t, c.ExpiryDate)
	assert.False(t, c.Revoked)
	assert.False(t, c.RevocationSupported)

	labels := map[string]string{}
	for _, attr := range c.Attributes {
		require.Len(t, attr.ClaimPath, 2)
		require.NotNil(t, attr.DisplayName)
		labels[attr.ClaimPath[1].(string)] = *attr.DisplayName
	}
	assert.Equal(t, map[string]string{"age_over_18": "Older than 18", "age_over_21": "Age Over 21"}, labels)
}

// Re-issuance of identical content replaces a batch the wallet can no longer
// present and is refused while it still can, the same rule as for SD-JWT VC.
func TestMdocCredentialService_ReissuanceRefusedWhileBatchUsable(t *testing.T) {
	env := newMdocTestEnv(t)
	mint := func(n uint) []models.PublicHolderBindingKey {
		ids, _, err := env.keyMint.CreateKeyPairsWithProofs(n, testProofBuilder(proofs.CryptographicBindingMethod_JWK))
		require.NoError(t, err)
		return ids
	}
	issue := func(ids []models.PublicHolderBindingKey) []*ParsedCredential {
		out := make([]*ParsedCredential, len(ids))
		for i, id := range ids {
			out[i] = env.issueBoundTo(t, *id.PublicKeyThumbprint, map[string]any{"age_over_18": true})
		}
		return out
	}

	first := mint(2)
	require.NoError(t, env.service.Store(issue(first), "proof_of_age", env.metadata, true, first))

	// Same claims, same issuer: refused while two instances are unspent.
	second := mint(2)
	err := env.service.Store(issue(second), "proof_of_age", env.metadata, true, second)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already held")

	// Spend the batch, then the same re-issuance replaces it.
	batches, err := env.store.ListBatches()
	require.NoError(t, err)
	for range 2 {
		inst, err := env.store.GetUnusedInstance(batches[0].ID)
		require.NoError(t, err)
		require.NoError(t, env.store.MarkInstanceUsed(inst.ID))
	}
	third := mint(2)
	require.NoError(t, env.service.Store(issue(third), "proof_of_age", env.metadata, true, third))

	batches, err = env.store.ListBatches()
	require.NoError(t, err)
	require.Len(t, batches, 1, "the spent batch was replaced, not duplicated")
	assert.Equal(t, uint(2), batches[0].RemainingCount)
}

func TestMdocCredentialService_DeleteByHash(t *testing.T) {
	env := newMdocTestEnv(t)
	ids, _, err := env.keyMint.CreateKeyPairsWithProofs(1, testProofBuilder(proofs.CryptographicBindingMethod_JWK))
	require.NoError(t, err)
	require.NoError(t, env.service.Store([]*ParsedCredential{env.issueBoundTo(t, *ids[0].PublicKeyThumbprint, map[string]any{"age_over_18": true})}, "proof_of_age", env.metadata, true, ids))

	batches, err := env.store.ListBatches()
	require.NoError(t, err)
	require.NoError(t, env.service.DeleteByHash(batches[0].Hash))
	require.ErrorIs(t, env.service.DeleteByHash(batches[0].Hash), db.ErrNotFound)

	var keys int64
	require.NoError(t, env.db.Model(&models.MdocDeviceKey{}).Count(&keys).Error)
	assert.Zero(t, keys, "deleting the batch cascades to its device keys")
}

// --- the credential list's labelling, ported from the shared-table days ---

// storedMdoc writes an mdoc batch with the given namespace values and claim
// metadata straight into the store, bypassing issuance.
func storedMdoc(t *testing.T, env *mdocTestEnv, elements map[string]any, claims []metadata.ClaimsDescription) {
	t.Helper()
	en := "en"
	cm, err := json.Marshal(&metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{{Display: metadata.Display{Name: "Proof of Age", Locale: &en}}},
		Claims:  claims,
	})
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, env.store.StoreBatch(&models.MdocBatch{
		DocType:            testMdocDocType,
		CredentialIssuer:   testMdocIssuerURL,
		Hash:               "seeded",
		Namespaces:         models.MdocNamespaces{testMdocDocType: elements},
		SignedAt:           now,
		ValidFrom:          now,
		ValidUntil:         now.Add(24 * time.Hour),
		BatchSize:          1,
		RemainingCount:     1,
		CredentialMetadata: datatypes.JSON(cm),
		Instances:          []models.MdocBatchInstance{{IssuerSigned: []byte{0xa0}}},
	}))
}

func claim(name string, path ...any) metadata.ClaimsDescription {
	en := "en"
	return metadata.ClaimsDescription{Path: metadata.ClaimsPathPointer(path), Display: []metadata.Display{{Name: name, Locale: &en}}}
}

func listedLabels(t *testing.T, env *mdocTestEnv) map[string]*string {
	t.Helper()
	result, err := env.service.List()
	require.NoError(t, err)
	require.Len(t, result, 1)
	labels := map[string]*string{}
	for _, attr := range result[0].Attributes {
		require.Len(t, attr.ClaimPath, 2, "an mdoc attribute path is [namespace, elementIdentifier]")
		require.Equal(t, testMdocDocType, attr.ClaimPath[0])
		require.NotNil(t, attr.Value, "the value has to be shown alongside the label")
		labels[attr.ClaimPath[1].(string)] = attr.DisplayName
	}
	return labels
}

// Both elements are listed at their real mdoc claim path and both carry a label,
// whichever form the issuer published.
func TestMdocList_LabelsBareElementClaims(t *testing.T) {
	env := newMdocTestEnv(t)
	storedMdoc(t, env, map[string]any{"age_over_18": true, "age_over_21": true}, []metadata.ClaimsDescription{
		claim("Older than 18", "age_over_18"),
		claim("Older than 21", testMdocDocType, "age_over_21"),
	})

	labels := listedLabels(t, env)
	require.NotNil(t, labels["age_over_18"])
	require.NotNil(t, labels["age_over_21"])
	assert.Equal(t, "Older than 18", *labels["age_over_18"])
	assert.Equal(t, "Older than 21", *labels["age_over_21"])
}

// The credential list labels a threshold the issuer never advertised the same
// way the disclosure screen does, and does not disturb the ones it did. An
// element nothing names falls back to its own identifier rather than nothing.
func TestMdocList_LabelsUnadvertisedAgeOver(t *testing.T) {
	env := newMdocTestEnv(t)
	storedMdoc(t, env, map[string]any{"age_over_18": true, "age_over_35": true, "issuing_country": "NL"}, []metadata.ClaimsDescription{
		claim("Older than 18", testMdocDocType, "age_over_18"),
	})

	labels := listedLabels(t, env)
	require.NotNil(t, labels["age_over_18"])
	assert.Equal(t, "Older than 18", *labels["age_over_18"], "published text is not displaced by the derived name")
	require.NotNil(t, labels["age_over_35"], "an unadvertised threshold must still be labelled")
	assert.Equal(t, "Age Over 35", *labels["age_over_35"])
	require.NotNil(t, labels["issuing_country"], "an element no metadata names must not render without a label")
	assert.Equal(t, "issuing_country", *labels["issuing_country"])
}

// An element the issuer signed into the namespace but never declared in its
// metadata is stored and disclosable, so it has to appear in the list, named
// after itself.
func TestMdocList_NamesUndeclaredElement(t *testing.T) {
	env := newMdocTestEnv(t)
	storedMdoc(t, env, map[string]any{"age_over_18": true, "email": "holder@example.com"}, []metadata.ClaimsDescription{
		claim("Older than 18", testMdocDocType, "age_over_18"),
	})

	labels := listedLabels(t, env)
	require.Contains(t, labels, "email")
	require.NotNil(t, labels["email"])
	assert.Equal(t, "email", *labels["email"])
	require.NotNil(t, labels["age_over_18"])
	assert.Equal(t, "Older than 18", *labels["age_over_18"])
}

// The read side the activity log and logo backfill use: displays per docType,
// preferring a batch with metadata, and logo URIs per batch.
func TestMdocDisplaySource(t *testing.T) {
	env := newMdocTestEnv(t)
	storedMdoc(t, env, map[string]any{"age_over_18": true}, nil)

	displays := newMdocDisplaySource(env.store).LiveDisplaysByType("en")
	require.Contains(t, displays, testMdocDocType)
	assert.Equal(t, "Proof of Age", displays[testMdocDocType].CredentialName)
	assert.Equal(t, testMdocIssuerURL, displays[testMdocDocType].IssuerId)

	issuer, credential := newMdocDisplaySource(env.store).LogoURIs("en")
	assert.Equal(t, []string{""}, issuer, "one entry per batch, empty when no logo is published")
	assert.Equal(t, []string{""}, credential)
}
