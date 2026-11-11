package proofs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/stretchr/testify/require"
)

func proofHeader(t *testing.T, proof string) map[string]any {
	t.Helper()
	part, _, _ := strings.Cut(proof, ".")
	raw, err := base64.RawURLEncoding.DecodeString(part)
	require.NoError(t, err)
	var hdr map[string]any
	require.NoError(t, json.Unmarshal(raw, &hdr))
	return hdr
}

func TestJwtProofBuilderKeyAttestation(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sign := func(input []byte) ([]byte, error) {
		digest := sha256.Sum256(input)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			return nil, err
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out, nil
	}
	newBuilder := func() *JwtProofBuilder {
		return NewJwtProofBuilder("wallet", "https://issuer.example", jwa.ES256(), nil, eudi_jwt.NewSystemClock(), CryptographicBindingMethod_JWK)
	}
	attestSigningKey := func(key *ecdsa.PublicKey) (string, error) {
		require.True(t, key.Equal(&priv.PublicKey), "the attested key is the key that signs the proof")
		return "ka.jwt.sig", nil
	}

	t.Run("Build", func(t *testing.T) {
		proof, err := newBuilder().WithKeyAttestation(attestSigningKey).Build(priv)
		require.NoError(t, err)
		require.Equal(t, "ka.jwt.sig", proofHeader(t, proof.(string))[keyAttestationHeader])
	})

	t.Run("BuildWithES256Signer", func(t *testing.T) {
		proof, err := newBuilder().WithKeyAttestation(attestSigningKey).BuildWithES256Signer(&priv.PublicKey, sign)
		require.NoError(t, err)
		require.Equal(t, "ka.jwt.sig", proofHeader(t, proof)[keyAttestationHeader])
	})

	t.Run("no key attestation", func(t *testing.T) {
		none := func(*ecdsa.PublicKey) (string, error) { return "", nil }
		proof, err := newBuilder().WithKeyAttestation(none).BuildWithES256Signer(&priv.PublicKey, sign)
		require.NoError(t, err)
		require.NotContains(t, proofHeader(t, proof), keyAttestationHeader)

		plain, err := newBuilder().Build(priv)
		require.NoError(t, err)
		require.NotContains(t, proofHeader(t, plain.(string)), keyAttestationHeader)
	})

	t.Run("attester fails", func(t *testing.T) {
		failing := func(*ecdsa.PublicKey) (string, error) { return "", errors.New("hsm down") }
		_, err := newBuilder().WithKeyAttestation(failing).Build(priv)
		require.ErrorContains(t, err, "hsm down")
		_, err = newBuilder().WithKeyAttestation(failing).BuildWithES256Signer(&priv.PublicKey, sign)
		require.ErrorContains(t, err, "hsm down")
	})
}
