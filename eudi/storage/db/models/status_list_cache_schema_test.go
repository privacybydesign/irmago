package models_test

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
)

// TestStatusListCacheKeepsLegacyRawJwtColumn pins the column backing
// StatusListCacheEntry.RawToken to its deployed name raw_jwt. The field was
// renamed when CWT tokens started landing in it; see
// TestCredentialBatchKeepsLegacyClaimsColumn for why the column cannot follow.
func TestStatusListCacheKeepsLegacyRawJwtColumn(t *testing.T) {
	d := openHolderDB(t)
	require.NoError(t, d.AutoMigrate(&models.StatusListCacheEntry{}))

	columnTypes, err := d.Migrator().ColumnTypes(&models.StatusListCacheEntry{})
	require.NoError(t, err)
	var columns []string
	for _, c := range columnTypes {
		columns = append(columns, c.Name())
	}

	require.Contains(t, columns, "raw_jwt",
		"the token column must stay named raw_jwt; AutoMigrate cannot rename it "+
			"and would try to add a new NOT NULL column instead")
	require.NotContains(t, columns, "raw_token")
}
