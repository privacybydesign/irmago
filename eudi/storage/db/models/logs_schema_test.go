package models_test

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

// legacyEudiLogEntry is EudiLogEntry as it stood before RequestorVerified was
// added, and builds the schema an already-installed wallet has. It has to name
// the table explicitly, since GORM derives that from the struct name.
type legacyEudiLogEntry struct {
	ID            datatypes.UUID `gorm:"type:uuid;primaryKey"`
	Type          string
	Protocol      string
	CreatedAt     time.Time `gorm:"index"`
	RequestorId   string
	RequestorName datatypes.JSON `gorm:"type:json"`
}

func (legacyEudiLogEntry) TableName() string { return "eudi_log_entries" }

// TestAutoMigrateAddsRequestorVerifiedToPopulatedLogTable runs the upgrade an
// existing wallet performs: a log table without RequestorVerified, holding
// entries, migrated by the AutoMigrate that runs on every startup.
//
// This is the case an empty-schema test cannot reach. AutoMigrate is the only
// schema mechanism the holder database has, so a new column arrives as an
// ALTER TABLE ADD COLUMN, and SQLite refuses that for a NOT NULL column once the
// table holds rows — which would leave every wallet with an activity log unable
// to open its database at all. TestAutoMigrateOverPopulatedDatabase pins the
// same property for credential_batches; this is its counterpart for the table
// this column was actually added to.
func TestAutoMigrateAddsRequestorVerifiedToPopulatedLogTable(t *testing.T) {
	d := openHolderDB(t)
	require.NoError(t, d.AutoMigrate(&legacyEudiLogEntry{}))

	var columns []string
	require.NoError(t, d.Raw(
		`SELECT name FROM pragma_table_info('eudi_log_entries')`,
	).Scan(&columns).Error)
	require.NotContains(t, columns, "requestor_verified",
		"the pre-upgrade schema must not already have the column, or this test proves nothing")

	existing := &legacyEudiLogEntry{
		ID:            datatypes.NewUUIDv4(),
		Type:          "disclosure",
		Protocol:      "openid4vp",
		CreatedAt:     time.Now().UTC().Truncate(time.Second),
		RequestorId:   "verifier-serial-1",
		RequestorName: datatypes.JSON(`{"en":"Existing Verifier"}`),
	}
	require.NoError(t, d.Create(existing).Error)

	// The upgrade path: the same AutoMigrate the wallet runs on every startup.
	require.NoError(t, d.AutoMigrate(&models.EudiLogEntry{}, &models.EudiLogCredential{}),
		"AutoMigrate must succeed against a log table that already holds entries")

	require.NoError(t, d.Raw(
		`SELECT name FROM pragma_table_info('eudi_log_entries')`,
	).Scan(&columns).Error)
	require.Contains(t, columns, "requestor_verified")

	// An entry written before the column existed reads back unverified, and the
	// rest of it survives the migration.
	var migrated models.EudiLogEntry
	require.NoError(t, d.Where("requestor_id = ?", "verifier-serial-1").First(&migrated).Error)
	require.False(t, migrated.RequestorVerified)
	require.JSONEq(t, `{"en":"Existing Verifier"}`, string(migrated.RequestorName))

	// And an entry written after it round-trips the flag, so the column is
	// readable as well as present.
	verified := &models.EudiLogEntry{
		ID:                datatypes.NewUUIDv4(),
		Type:              "disclosure",
		Protocol:          "openid4vp",
		CreatedAt:         time.Now().UTC().Truncate(time.Second),
		RequestorId:       "verifier-serial-2",
		RequestorName:     datatypes.JSON(`{"en":"Authenticated Verifier"}`),
		RequestorVerified: true,
	}
	require.NoError(t, d.Create(verified).Error)

	var reread models.EudiLogEntry
	require.NoError(t, d.Where("requestor_id = ?", "verifier-serial-2").First(&reread).Error)
	require.True(t, reread.RequestorVerified)
}
