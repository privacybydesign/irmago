package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

// A stored holder binding key carries either a thumbprint or a DID URL, never
// both — keybinder_service records the DID from the proof JWT's kid whenever the
// credential configuration's binding method is did:key or did:jwk. A format that
// embeds a bare public key rather than a cnf claim (mso_mdoc) can only compute a
// thumbprint from it, so before the matcher learned to derive the DID forms,
// mdoc issuance against any DID-binding issuer failed outright with "no matching
// holder binding key found" — after the credential had been issued.
//
// These tests pin that all three binding methods now match, and that the DID
// URLs the matcher derives are byte-identical to the ones JwtProofBuilder puts
// in the proof — which is what makes the lookup work at all.

func testECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// didUrlFromProof reproduces what keybinder_service stores: the kid of a proof
// JWT built for the given binding method.
func didUrlFromProof(t *testing.T, privKey *ecdsa.PrivateKey, method proofs.CryptographicBindingMethod) string {
	t.Helper()
	nonce := "nonce-123"
	builder := proofs.NewJwtProofBuilder(
		"https://wallet.example.com",
		"https://issuer.example.com",
		jwa.ES256(),
		&nonce,
		jwt.ClockFunc(func() time.Time { return time.Unix(1_760_000_000, 0) }),
		method,
	)
	proof, err := builder.Build(privKey)
	require.NoError(t, err)
	proofStr, ok := proof.(string)
	require.True(t, ok, "expected the proof builder to return a string")
	didUrl := extractDidUrlFromProof(&proofStr)
	require.NotNil(t, didUrl, "binding method %s should produce a DID kid", method)
	return *didUrl
}

func TestMatchHolderBindingKey_MdocAgainstDidBoundKey(t *testing.T) {
	for _, method := range []proofs.CryptographicBindingMethod{
		proofs.CryptographicBindingMethod_DID_JWK,
		proofs.CryptographicBindingMethod_DID_KEY,
	} {
		t.Run(string(method), func(t *testing.T) {
			privKey := testECDSAKey(t)
			storedDidUrl := didUrlFromProof(t, privKey, method)

			// The stored key: DID URL only, no thumbprint — mutually exclusive per
			// models.HolderBindingKey.
			keyID := datatypes.NewUUIDv4()
			stored := []models.PublicHolderBindingKey{{ID: keyID, DidUrl: &storedDidUrl}}

			// What the mdoc parser produces: the device key out of the MSO, plus its
			// thumbprint. No DID, because an mdoc carries none.
			thumbprint, err := jwkThumbprintFromECDSAPublicKey(&privKey.PublicKey)
			require.NoError(t, err)
			parsed := []*ParsedCredential{{
				Format:                     models.CredentialFormatMsoMdoc,
				HolderBindingKeyThumbprint: &thumbprint,
				HolderBindingKeyPublicKey:  &privKey.PublicKey,
			}}

			matched, err := matchAllHolderBindingKeys(parsed, stored)
			require.NoError(t, err, "mdoc issuance must match a DID-bound holder binding key")
			require.Equal(t, []datatypes.UUID{keyID}, matched)
		})
	}
}

func TestMatchHolderBindingKey_MdocAgainstThumbprintBoundKey(t *testing.T) {
	privKey := testECDSAKey(t)

	pubJwk, err := jwk.Import(&privKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pubJwk.Set(jwk.KeyUsageKey, jwk.ForSignature))

	thumbprint, err := jwkThumbprintFromECDSAPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	keyID := datatypes.NewUUIDv4()
	stored := []models.PublicHolderBindingKey{{ID: keyID, PublicKeyThumbprint: &thumbprint}}

	parsed := []*ParsedCredential{{
		Format:                     models.CredentialFormatMsoMdoc,
		HolderBindingKeyThumbprint: &thumbprint,
		HolderBindingKeyPublicKey:  &privKey.PublicKey,
	}}

	matched, err := matchAllHolderBindingKeys(parsed, stored)
	require.NoError(t, err)
	require.Equal(t, []datatypes.UUID{keyID}, matched)
}

func TestMatchHolderBindingKey_MdocAgainstUnrelatedKeyStillFails(t *testing.T) {
	credentialKey := testECDSAKey(t)
	otherKey := testECDSAKey(t)

	// A stored key belonging to a different key pair must not match, whichever
	// identifier form it took — otherwise the derivation would be matching on
	// something other than the key itself.
	otherDidUrl := didUrlFromProof(t, otherKey, proofs.CryptographicBindingMethod_DID_JWK)
	otherThumbprint, err := jwkThumbprintFromECDSAPublicKey(&otherKey.PublicKey)
	require.NoError(t, err)

	thumbprint, err := jwkThumbprintFromECDSAPublicKey(&credentialKey.PublicKey)
	require.NoError(t, err)
	parsed := []*ParsedCredential{{
		Format:                     models.CredentialFormatMsoMdoc,
		HolderBindingKeyThumbprint: &thumbprint,
		HolderBindingKeyPublicKey:  &credentialKey.PublicKey,
	}}

	for name, stored := range map[string][]models.PublicHolderBindingKey{
		"did-bound":        {{ID: datatypes.NewUUIDv4(), DidUrl: &otherDidUrl}},
		"thumbprint-bound": {{ID: datatypes.NewUUIDv4(), PublicKeyThumbprint: &otherThumbprint}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := matchAllHolderBindingKeys(parsed, stored)
			require.Error(t, err, "a credential must not match another key pair's stored key")
		})
	}
}

func TestMatchHolderBindingKey_NoKeyBindingDataIsRejected(t *testing.T) {
	parsed := []*ParsedCredential{{Format: models.CredentialFormatMsoMdoc}}
	_, err := matchAllHolderBindingKeys(parsed, nil)
	require.ErrorContains(t, err, "carries no key-binding data")
}

// TestDerivedDidUrlsMatchProofBuilder is the assumption the fix rests on: the
// identifiers holderBindingKeyIdentifiers derives from a public key are exactly
// the strings JwtProofBuilder writes into the proof's kid. If the two ever drift
// — a changed JWK field, a different DID method — issuance breaks again, and
// this fails rather than the integration test.
func TestDerivedDidUrlsMatchProofBuilder(t *testing.T) {
	privKey := testECDSAKey(t)

	_, derived := holderBindingKeyIdentifiers(&ParsedCredential{
		HolderBindingKeyPublicKey: &privKey.PublicKey,
	})

	for _, method := range []proofs.CryptographicBindingMethod{
		proofs.CryptographicBindingMethod_DID_JWK,
		proofs.CryptographicBindingMethod_DID_KEY,
	} {
		fromProof := didUrlFromProof(t, privKey, method)
		require.Contains(t, derived, fromProof,
			"holderBindingKeyIdentifiers must derive the same %s URL the proof builder uses", method)
	}
}
