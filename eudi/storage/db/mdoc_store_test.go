package db

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func newMdocTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	d, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("super-secret-key-123"))}, &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, d.AutoMigrate(
		&models.MdocBatch{},
		&models.MdocBatchInstance{},
		&models.MdocDeviceKey{},
	))
	return d
}

func newMdocBatch(hash string, instances int) *models.MdocBatch {
	now := time.Now().UTC().Truncate(time.Second)
	b := &models.MdocBatch{
		DocType:          "eu.europa.ec.av.1",
		CredentialIssuer: "https://issuer.example.com",
		Hash:             hash,
		Namespaces: models.MdocNamespaces{
			"eu.europa.ec.av.1": {"age_over_18": true, "age_over_21": false},
		},
		SignedAt:       now,
		ValidFrom:      now,
		ValidUntil:     now.Add(90 * 24 * time.Hour),
		BatchSize:      uint(instances),
		RemainingCount: uint(instances),
		IssuerVerified: true,
		IssuerDisplay:  datatypes.JSON(`[{"name":"Issuer","locale":"en"}]`),
	}
	for i := 0; i < instances; i++ {
		b.Instances = append(b.Instances, models.MdocBatchInstance{
			IssuerSigned: []byte{0xa2, byte(i)},
		})
	}
	return b
}

func newDeviceKey(thumbprint string) models.MdocDeviceKey {
	return models.MdocDeviceKey{
		PublicKeyThumbprint: thumbprint,
		PrivateKey:          []byte("pkcs8-" + thumbprint),
		Curve:               "P-256",
	}
}

// --- schema ---

func TestMdocSchema_TablesAndConstraints(t *testing.T) {
	d := newMdocTestDB(t)

	var tables []string
	require.NoError(t, d.Raw(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`).Scan(&tables).Error)
	require.Subset(t, tables, []string{"mdoc_batches", "mdoc_batch_instances", "mdoc_device_keys"})

	// The MSO's validity window is mandatory in ISO 18013-5, so the columns are
	// NOT NULL — unlike the SD-JWT batch's optional iat/nbf/exp.
	type col struct {
		Name    string
		NotNull int
	}
	var cols []col
	require.NoError(t, d.Raw(`SELECT name, "notnull" AS not_null FROM pragma_table_info('mdoc_batches')`).Scan(&cols).Error)
	notNull := map[string]bool{}
	for _, c := range cols {
		notNull[c.Name] = c.NotNull == 1
	}
	for _, c := range []string{"doc_type", "credential_issuer", "hash", "namespaces", "signed_at", "valid_from", "valid_until", "batch_size", "remaining_count"} {
		assert.True(t, notNull[c], "mdoc_batches.%s must be NOT NULL", c)
	}
	_, hasFormat := notNull["format"]
	assert.False(t, hasFormat, "an mdoc table needs no format discriminator: the table is the format")
}

func TestMdocSchema_HashIsUnique(t *testing.T) {
	store := NewMdocStore(newMdocTestDB(t))
	require.NoError(t, store.StoreBatch(newMdocBatch("same", 1)))
	require.Error(t, store.StoreBatch(newMdocBatch("same", 1)))
}

func TestMdocSchema_ThumbprintIsUnique(t *testing.T) {
	keys := NewMdocDeviceKeyStore(newMdocTestDB(t))
	require.NoError(t, keys.StoreKeys([]models.MdocDeviceKey{newDeviceKey("tp")}))
	require.Error(t, keys.StoreKeys([]models.MdocDeviceKey{newDeviceKey("tp")}))
}

// --- MdocBatch validation ---

func TestMdocBatch_Validation(t *testing.T) {
	cases := map[string]func(*models.MdocBatch){
		"missing doc type":          func(b *models.MdocBatch) { b.DocType = "" },
		"missing credential issuer": func(b *models.MdocBatch) { b.CredentialIssuer = "" },
		"missing hash":              func(b *models.MdocBatch) { b.Hash = "" },
		"empty namespaces":          func(b *models.MdocBatch) { b.Namespaces = nil },
		"zero signed_at":            func(b *models.MdocBatch) { b.SignedAt = time.Time{} },
		"zero valid_from":           func(b *models.MdocBatch) { b.ValidFrom = time.Time{} },
		"zero valid_until":          func(b *models.MdocBatch) { b.ValidUntil = time.Time{} },
		"zero batch size":           func(b *models.MdocBatch) { b.BatchSize = 0 },
		"remaining exceeds size":    func(b *models.MdocBatch) { b.RemainingCount = b.BatchSize + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			store := NewMdocStore(newMdocTestDB(t))
			b := newMdocBatch("h", 1)
			mutate(b)
			require.Error(t, store.StoreBatch(b))
		})
	}
}

// --- MdocStore ---

func TestMdocStore_StoreBatch_RejectsNilAndEmpty(t *testing.T) {
	store := NewMdocStore(newMdocTestDB(t))
	require.Error(t, store.StoreBatch(nil))
	b := newMdocBatch("h", 1)
	b.Instances = nil
	require.Error(t, store.StoreBatch(b))
}

func TestMdocStore_StoreBatch_AssignsIDsAndRoundTripsNamespaces(t *testing.T) {
	store := NewMdocStore(newMdocTestDB(t))
	b := newMdocBatch("h", 2)
	require.NoError(t, store.StoreBatch(b))
	require.False(t, b.ID.IsNil())
	for _, inst := range b.Instances {
		require.False(t, inst.ID.IsNil())
		require.Equal(t, b.ID, inst.MdocBatchID)
	}

	got, err := store.GetBatchByHash("h")
	require.NoError(t, err)
	assert.Equal(t, "eu.europa.ec.av.1", got.DocType)
	assert.Equal(t, true, got.Namespaces["eu.europa.ec.av.1"]["age_over_18"])
	assert.Equal(t, false, got.Namespaces["eu.europa.ec.av.1"]["age_over_21"])
	assert.True(t, got.IssuerVerified)
	assert.JSONEq(t, `[{"name":"Issuer","locale":"en"}]`, string(got.IssuerDisplay))
	assert.Empty(t, got.CredentialMetadata)
	assert.WithinDuration(t, b.ValidUntil, got.ValidUntil, time.Second)
	assert.Nil(t, got.Instances, "batch lookups do not load instances")
}

func TestMdocStore_ListBatches(t *testing.T) {
	store := NewMdocStore(newMdocTestDB(t))
	empty, err := store.ListBatches()
	require.NoError(t, err)
	require.Empty(t, empty)

	require.NoError(t, store.StoreBatch(newMdocBatch("a", 1)))
	require.NoError(t, store.StoreBatch(newMdocBatch("b", 1)))
	all, err := store.ListBatches()
	require.NoError(t, err)
	require.Len(t, all, 2)
}

func TestMdocStore_GetBatchByHash_NotFoundAndEmpty(t *testing.T) {
	store := NewMdocStore(newMdocTestDB(t))
	_, err := store.GetBatchByHash("nope")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = store.GetBatchByHash("")
	require.Error(t, err)
}

func TestMdocStore_GetBatchesByDocType(t *testing.T) {
	store := NewMdocStore(newMdocTestDB(t))
	av1 := newMdocBatch("av-1", 1)
	av2 := newMdocBatch("av-2", 1)
	pid := newMdocBatch("pid", 1)
	pid.DocType = "eu.europa.ec.eudi.pid.1"
	pid.Namespaces = models.MdocNamespaces{"eu.europa.ec.eudi.pid.1": {"family_name": "Doe"}}
	for _, b := range []*models.MdocBatch{av1, av2, pid} {
		require.NoError(t, store.StoreBatch(b))
	}

	got, err := store.GetBatchesByDocType("eu.europa.ec.av.1")
	require.NoError(t, err)
	require.Len(t, got, 2)

	got, err = store.GetBatchesByDocType("org.iso.18013.5.1.mDL")
	require.NoError(t, err)
	require.Empty(t, got)

	_, err = store.GetBatchesByDocType("")
	require.Error(t, err)
}

func TestMdocStore_GetUnusedInstance(t *testing.T) {
	d := newMdocTestDB(t)
	store := NewMdocStore(d)
	keys := NewMdocDeviceKeyStore(d)

	_, err := store.GetUnusedInstance(datatypes.UUID{})
	require.Error(t, err)
	_, err = store.GetUnusedInstance(datatypes.NewUUIDv4())
	require.ErrorIs(t, err, ErrNotFound)

	b := newMdocBatch("h", 2)
	require.NoError(t, store.StoreBatch(b))
	require.NoError(t, keys.StoreKeys([]models.MdocDeviceKey{newDeviceKey("tp-0"), newDeviceKey("tp-1")}))
	k0, err := keys.GetByThumbprint("tp-0")
	require.NoError(t, err)
	require.NoError(t, keys.LinkToInstance(k0.ID, b.Instances[0].ID))

	inst, err := store.GetUnusedInstance(b.ID)
	require.NoError(t, err)
	require.False(t, inst.Used)
	if inst.ID == b.Instances[0].ID {
		require.NotNil(t, inst.DeviceKey, "the bound device key is preloaded")
		require.Equal(t, "tp-0", inst.DeviceKey.PublicKeyThumbprint)
	}
}

func TestMdocStore_MarkInstanceUsed(t *testing.T) {
	d := newMdocTestDB(t)
	store := NewMdocStore(d)

	require.Error(t, store.MarkInstanceUsed(datatypes.UUID{}))
	require.ErrorIs(t, store.MarkInstanceUsed(datatypes.NewUUIDv4()), ErrNotFound)

	b := newMdocBatch("h", 2)
	require.NoError(t, store.StoreBatch(b))
	id := b.Instances[0].ID

	require.NoError(t, store.MarkInstanceUsed(id))
	var inst models.MdocBatchInstance
	require.NoError(t, d.First(&inst, "id = ?", id).Error)
	require.True(t, inst.Used)
	got, err := store.GetBatchByHash("h")
	require.NoError(t, err)
	require.Equal(t, uint(1), got.RemainingCount)

	// Marking the same instance twice is a no-op reported as not found, and does
	// not decrement again.
	require.ErrorIs(t, store.MarkInstanceUsed(id), ErrNotFound)
	got, err = store.GetBatchByHash("h")
	require.NoError(t, err)
	require.Equal(t, uint(1), got.RemainingCount)

	require.NoError(t, store.MarkInstanceUsed(b.Instances[1].ID))
	_, err = store.GetUnusedInstance(b.ID)
	require.ErrorIs(t, err, ErrNotFound)
	got, err = store.GetBatchByHash("h")
	require.NoError(t, err)
	require.Equal(t, uint(0), got.RemainingCount)
}

func TestMdocStore_DeleteBatch_CascadesToInstancesAndDeviceKeys(t *testing.T) {
	d := newMdocTestDB(t)
	store := NewMdocStore(d)
	keys := NewMdocDeviceKeyStore(d)

	b := newMdocBatch("h", 2)
	require.NoError(t, store.StoreBatch(b))
	require.NoError(t, keys.StoreKeys([]models.MdocDeviceKey{newDeviceKey("tp-0"), newDeviceKey("tp-1"), newDeviceKey("unbound")}))
	for i, tp := range []string{"tp-0", "tp-1"} {
		k, err := keys.GetByThumbprint(tp)
		require.NoError(t, err)
		require.NoError(t, keys.LinkToInstance(k.ID, b.Instances[i].ID))
	}

	require.NoError(t, store.DeleteBatchByHash("h"))

	var instances, deviceKeys int64
	require.NoError(t, d.Model(&models.MdocBatchInstance{}).Count(&instances).Error)
	require.NoError(t, d.Model(&models.MdocDeviceKey{}).Count(&deviceKeys).Error)
	assert.Zero(t, instances)
	assert.Equal(t, int64(1), deviceKeys, "only the key bound to no instance survives")

	require.ErrorIs(t, store.DeleteBatchByHash("h"), ErrNotFound)
	require.ErrorIs(t, store.DeleteBatch(datatypes.NewUUIDv4()), ErrNotFound)
	require.Error(t, store.DeleteBatch(datatypes.UUID{}))
}

// --- MdocDeviceKeyStore ---

func TestMdocDeviceKeyStore_Validation(t *testing.T) {
	keys := NewMdocDeviceKeyStore(newMdocTestDB(t))
	require.Error(t, keys.StoreKeys(nil))
	for name, k := range map[string]models.MdocDeviceKey{
		"missing thumbprint":  {PrivateKey: []byte("x"), Curve: "P-256"},
		"missing private key": {PublicKeyThumbprint: "tp", Curve: "P-256"},
		"missing curve":       {PublicKeyThumbprint: "tp", PrivateKey: []byte("x")},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, keys.StoreKeys([]models.MdocDeviceKey{k}))
		})
	}
}

func TestMdocDeviceKeyStore_StoreGetLinkDelete(t *testing.T) {
	d := newMdocTestDB(t)
	keys := NewMdocDeviceKeyStore(d)
	store := NewMdocStore(d)

	minted := []models.MdocDeviceKey{newDeviceKey("a"), newDeviceKey("b")}
	require.NoError(t, keys.StoreKeys(minted))
	require.False(t, minted[0].ID.IsNil())
	require.False(t, minted[0].CreatedAt.IsZero())

	got, err := keys.GetByThumbprint("a")
	require.NoError(t, err)
	assert.Equal(t, []byte("pkcs8-a"), got.PrivateKey)
	assert.Nil(t, got.MdocBatchInstanceID, "a freshly minted key is bound to nothing")

	_, err = keys.GetByThumbprint("zzz")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = keys.GetByThumbprint("")
	require.Error(t, err)

	b := newMdocBatch("h", 1)
	require.NoError(t, store.StoreBatch(b))
	require.NoError(t, keys.LinkToInstance(got.ID, b.Instances[0].ID))
	got, err = keys.GetByThumbprint("a")
	require.NoError(t, err)
	require.NotNil(t, got.MdocBatchInstanceID)
	assert.Equal(t, b.Instances[0].ID, *got.MdocBatchInstanceID)

	require.ErrorIs(t, keys.LinkToInstance(datatypes.NewUUIDv4(), b.Instances[0].ID), ErrNotFound)
	require.Error(t, keys.LinkToInstance(datatypes.UUID{}, b.Instances[0].ID))

	// Rolling back a failed issuance deletes exactly the minted keys; unknown ids
	// are ignored.
	require.NoError(t, keys.DeleteKeys([]datatypes.UUID{minted[1].ID, datatypes.NewUUIDv4()}))
	_, err = keys.GetByThumbprint("b")
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, keys.DeleteKeys(nil))

	require.NoError(t, keys.DeleteAll())
	var n int64
	require.NoError(t, d.Model(&models.MdocDeviceKey{}).Count(&n).Error)
	assert.Zero(t, n)
}
