package sdjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestJwtCreator returns a JwtCreator backed by a freshly generated
// ephemeral key. These tests only decode/manipulate the JWT payload — they
// never verify a signature — so an ephemeral key is sufficient.
func newTestJwtCreator(t *testing.T) JwtCreator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return NewJwtCreator(key)
}
