package testissuer_test

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc/testissuer"
)

// -update-fixtures causes TestDumpFixtures to (re)write the testdata
// directory. Committed fixtures let other packages and external tools inspect
// a concrete AV credential without having to execute the issuer.
var updateFixtures = flag.Bool("update-fixtures", false,
	"regenerate the testdata/ fixture files under eudi/credentials/mdoc/testissuer")

func TestDumpFixtures(t *testing.T) {
	if !*updateFixtures {
		t.Skip("pass -update-fixtures to regenerate testdata")
	}

	cred, err := testissuer.BuildAVCredential(testissuer.AVRequest{
		AgeOver18: true,
		AgeOverNN: map[int]bool{21: true},
	})
	require.NoError(t, err)

	dir := "testdata"
	require.NoError(t, os.MkdirAll(dir, 0o755))

	writes := []struct {
		name string
		blob []byte
	}{
		{"issuer_signed.cbor", cred.IssuerSignedCBOR},
		{"iaca.pem", certPEM(cred.IACACert)},
		{"iaca.key.pem", mustKeyPEM(t, cred.IACAKey)},
		{"ds.pem", certPEM(cred.DSCert)},
		{"ds.key.pem", mustKeyPEM(t, cred.DSKey)},
		{"device.key.pem", mustKeyPEM(t, cred.DeviceKey)},
	}
	for _, w := range writes {
		require.NoError(t, os.WriteFile(filepath.Join(dir, w.name), w.blob, 0o644))
	}
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func mustKeyPEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
