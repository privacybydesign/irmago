package proofs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/stretchr/testify/require"
)

// TestBuildWithES256Signer proves the WSCA issuance path: an OpenID4VCI proof
// JWT assembled by BuildWithES256Signer and signed by an external signer is a
// valid ES256 JWS that verifies against the supplied public key, with the
// expected header (jwk) and payload (aud/iss/iat/nonce).
func TestBuildWithES256Signer(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	nonce := "c-nonce-123"
	b := NewJwtProofBuilder(
		"https://wallet.example",       // issuer
		"https://issuer.example",       // audience
		jwa.ES256(),                    // alg
		&nonce,                         // nonce
		eudi_jwt.NewSystemClock(),      // clock
		CryptographicBindingMethod_JWK, // method
	)

	// External signer: signs the JWS signing input, returns raw r||s.
	sign := func(signingInput []byte) ([]byte, error) {
		digest := sha256.Sum256(signingInput)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			return nil, err
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out, nil
	}

	proof, err := b.BuildWithES256Signer(&priv.PublicKey, sign)
	require.NoError(t, err)

	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3)

	// Header
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var hdr map[string]any
	require.NoError(t, json.Unmarshal(hdrBytes, &hdr))
	require.Equal(t, "ES256", hdr["alg"])
	require.Equal(t, "openid4vci-proof+jwt", hdr["typ"])
	require.Contains(t, hdr, "jwk")

	// Payload
	plBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var pl map[string]any
	require.NoError(t, json.Unmarshal(plBytes, &pl))
	require.Equal(t, "https://issuer.example", pl["aud"]) // flattened to a string
	require.Equal(t, "https://wallet.example", pl["iss"])
	require.Equal(t, nonce, pl["nonce"])
	require.Contains(t, pl, "iat")

	// Signature verifies against the public key.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, sig, 64)
	signingInput := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signingInput)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	require.True(t, ecdsa.Verify(&priv.PublicKey, digest[:], r, s))
}
