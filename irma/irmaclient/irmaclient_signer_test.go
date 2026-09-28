package irmaclient

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/privacybydesign/gabi/signed"
	"github.com/privacybydesign/irmago/internal/jose"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestSignerJWT(t *testing.T) {
	signer := test.NewSigner(t)

	jwtt, err := SignerCreateJWT(signer, "keyname", map[string]any{"foo": "bar"})
	require.NoError(t, err)

	pkbts, err := signer.PublicKey("keyname")
	require.NoError(t, err)
	pk, err := signed.UnmarshalPublicKey(pkbts)
	require.NoError(t, err)

	claims := map[string]any{}
	require.NoError(t, jose.Verify(jwtt, &claims, jose.StaticKey(jwa.ES256(), pk)))
	require.Contains(t, claims, "foo")
	require.Equal(t, claims["foo"], "bar")
}
