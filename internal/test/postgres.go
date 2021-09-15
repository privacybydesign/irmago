package test

import (
	"database/sql"
	"io/ioutil"
	"testing"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/stretchr/testify/require"
)

const PostgresTestUrl = "postgresql://testuser:testpassword@localhost:5432/test"

func RunScriptOnDB(t *testing.T, filename string, allowErr bool) {
	db, err := sql.Open("pgx", PostgresTestUrl)
	require.NoError(t, err)
	defer common.Close(db)
	scriptData, err := ioutil.ReadFile(filename)
	require.NoError(t, err)
	_, err = db.Exec(string(scriptData))
	if !allowErr {
		require.NoError(t, err)
	}
}
