package wallet

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/stretchr/testify/require"
)

// TestSignerKeyBinder_ProducesVerifiableKbJwt proves the HolderSigner seam: a
// KB-JWT created through signerKeyBinder is a valid ES256 JWS that verifies
// against the public key CreateKeyPairs handed back. A WSCA-backed HolderSigner
// plugs into exactly this path.
func TestSignerKeyBinder_ProducesVerifiableKbJwt(t *testing.T) {
	signer := NewSoftwareHolderSigner()
	binder := newSignerKeyBinder(signer)

	keys, err := binder.CreateKeyPairs(1)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	holderKey := keys[0]

	const (
		hash  = "abc123sdhash"
		nonce = "nonce-xyz"
		aud   = "https://verifier.example"
	)
	kb, err := binder.CreateKeyBindingJwt(hash, holderKey, nonce, aud)
	require.NoError(t, err)

	parts := strings.Split(string(kb), ".")
	require.Len(t, parts, 3, "kb-jwt must be a compact JWS with 3 parts")

	// Header: typ=kb+jwt, alg=ES256.
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var hdr map[string]any
	require.NoError(t, json.Unmarshal(hdrBytes, &hdr))
	require.Equal(t, sdjwtvc.KbJwtTyp, hdr["typ"])
	require.Equal(t, "ES256", hdr["alg"])

	// Payload: sd_hash / nonce / aud round-trip.
	plBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var pl sdjwtvc.KeyBindingJwtPayload
	require.NoError(t, json.Unmarshal(plBytes, &pl))
	require.Equal(t, hash, pl.IssuerSignedJwtHash)
	require.Equal(t, nonce, pl.Nonce)
	require.Equal(t, aud, pl.Audience)
	require.NotZero(t, pl.IssuedAt)

	// Signature verifies against the holder public key over sha256(signingInput).
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.Len(t, sig, 64, "ES256 raw signature must be 64 bytes (r||s)")

	var pub ecdsa.PublicKey
	require.NoError(t, jwk.Export(holderKey, &pub))

	signingInput := []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(signingInput)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	require.True(t, ecdsa.Verify(&pub, digest[:], r, s), "KB-JWT signature must verify against the holder key")
}

// TestSoftwareHolderSigner_ReferenceRoundTrip checks that a generated key's
// public JWK resolves back to the same reference used to sign — the mapping the
// presentation path relies on to find the right key from a credential's cnf.
func TestSoftwareHolderSigner_ReferenceRoundTrip(t *testing.T) {
	signer := NewSoftwareHolderSigner()
	refs, pubs, err := signer.GenerateKeys(2)
	require.NoError(t, err)
	require.Len(t, refs, 2)

	for i, pub := range pubs {
		k, err := jwk.Import(pub)
		require.NoError(t, err)
		pubJwk, err := k.PublicKey()
		require.NoError(t, err)
		ref, err := signer.Reference(pubJwk)
		require.NoError(t, err)
		require.Equal(t, refs[i], ref)

		// And it can sign under that reference.
		_, err = signer.SignES256(ref, []byte("header.payload"))
		require.NoError(t, err)
	}
}
