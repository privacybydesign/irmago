package models_test

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// openHolderDB opens an encrypted in-memory holder database.
func openHolderDB(t *testing.T) *gorm.DB {
	t.Helper()
	d, err := gorm.Open(
		sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("test-key-123"))},
		&gorm.Config{},
	)
	require.NoError(t, err)
	return d
}
