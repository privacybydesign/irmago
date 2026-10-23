package vcdmsdjwt

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/stretchr/testify/require"
)

const (
	presentationAudience = "decentralized_identifier:did:jwk:verifier"
	presentationNonce    = "presentation-nonce"
)

// issueHolderBoundSdJwtVcdm issues a VCDM credential bound to a fresh holder
// key of keyBinder, and returns it with only given_name disclosed.
func issueHolderBoundSdJwtVcdm(t *testing.T, keyBinder sdjwt.KeyBinder) (sdjwt.SdJwt, jwk.Key) {
	t.Helper()
	holderKeys, err := keyBinder.CreateKeyPairs(1)
	require.NoError(t, err)
	cnf, err := sdjwt.HolderKeyClaim(holderKeys[0])
	require.NoError(t, err)

	claims := vcdmClaims(t, "2024-01-01T00:00:00Z", "2034-01-01T00:00:00Z")
	claims[len(claims)-1] = cnf

	full, err := NewSdJwtVcdmBuilder().
		WithPayload(claims...).
		WithIssuerCertificateChain(testX5c(t)).
		Build(sdjwt.NewJwtCreator(testIssuerKey(t)))
	require.NoError(t, err)

	selected, err := sdjwt.CreatePresentation(sdjwt.SdJwt(full), [][]any{{vcdm.CredentialSubjectKey, "given_name"}})
	require.NoError(t, err)
	return selected, holderKeys[0]
}

// requireEnvelopes asserts the Verifiable Presentation payload envelopes
// exactly the given SD-JWT, bound to the test audience and nonce.
func requireEnvelopes(t *testing.T, vp map[string]any, selected sdjwt.SdJwt) {
	t.Helper()
	require.Equal(t, []any{vcdm.ContextV2}, vp[vcdm.ContextKey])
	require.Equal(t, []any{"VerifiablePresentation"}, vp[vcdm.TypeKey])
	require.Equal(t, presentationAudience, vp["aud"], "aud must be the client_id as a single string")
	require.Equal(t, presentationNonce, vp["nonce"])
	require.NotNil(t, vp["iat"])

	creds, ok := vp["verifiableCredential"].([]any)
	require.True(t, ok)
	require.Len(t, creds, 1)
	cred, ok := creds[0].(map[string]any)
	require.True(t, ok)
	require.Equal(t, []any{vcdm.ContextV2}, cred[vcdm.ContextKey])
	require.Equal(t, "EnvelopedVerifiableCredential", cred[vcdm.TypeKey])
	require.Equal(t, EnvelopedCredentialDataUrlPrefix+string(selected), cred["id"])
}

func TestCreateEnvelopedPresentation_SignedWithHolderKey(t *testing.T) {
	keyBinder := sdjwt.NewDefaultKeyBinderWithInMemoryStorage()
	selected, holderKey := issueHolderBoundSdJwtVcdm(t, keyBinder)

	presentation, err := CreateEnvelopedPresentation(selected, keyBinder, true, presentationNonce, presentationAudience)
	require.NoError(t, err)

	_, err = jws.Verify([]byte(presentation), jws.WithKey(jwa.ES256(), holderKey))
	require.NoError(t, err, "presentation must verify with the holder key from cnf")

	header, vp, err := sdjwt.DecodeJwtWithoutCheckingSignature(presentation)
	require.NoError(t, err)
	require.Equal(t, PresentationTyp, header["typ"])
	require.Equal(t, "vp", header["cty"])
	require.Equal(t, "ES256", header["alg"])

	// The jwk header carries the holder public key, so a verifier can check the
	// signature without resolving anything.
	headerJwk, ok := header["jwk"].(map[string]any)
	require.True(t, ok, "jwk header should be an object")
	require.Equal(t, "EC", headerJwk["kty"])
	require.NotContains(t, headerJwk, "d", "jwk header must not carry the private key")
	headerJwkJson, err := json.Marshal(headerJwk)
	require.NoError(t, err)
	headerKey, err := jwk.ParseKey(headerJwkJson)
	require.NoError(t, err)
	require.True(t, jwk.Equal(holderKey, headerKey), "jwk header should be the holder public key")

	requireEnvelopes(t, vp, selected)

	// The signed presentation is the holder proof, so the enveloped SD-JWT
	// carries no KB-JWT: it ends in the ~ that closes the last disclosure.
	require.True(t, strings.HasSuffix(string(selected), "~"))
}

func TestCreateEnvelopedPresentation_UnsecuredWithoutHolderBinding(t *testing.T) {
	keyBinder := sdjwt.NewDefaultKeyBinderWithInMemoryStorage()
	selected, _ := issueHolderBoundSdJwtVcdm(t, keyBinder)

	presentation, err := CreateEnvelopedPresentation(selected, keyBinder, false, presentationNonce, presentationAudience)
	require.NoError(t, err)

	parts := strings.Split(presentation, ".")
	require.Len(t, parts, 3)
	require.Empty(t, parts[2], "an unsecured JWT has an empty signature")

	header, vp, err := sdjwt.DecodeJwtWithoutCheckingSignature(presentation)
	require.NoError(t, err)
	require.Equal(t, "none", header["alg"])
	require.Equal(t, PresentationTyp, header["typ"])
	requireEnvelopes(t, vp, selected)
}

func TestCreateEnvelopedPresentation_HolderBindingWithoutCnfFails(t *testing.T) {
	keyBinder := sdjwt.NewDefaultKeyBinderWithInMemoryStorage()
	claims := vcdmClaims(t, "2024-01-01T00:00:00Z", "2034-01-01T00:00:00Z")
	unbound, err := NewSdJwtVcdmBuilder().
		WithPayload(claims[:len(claims)-1]...).
		WithIssuerCertificateChain(testX5c(t)).
		Build(sdjwt.NewJwtCreator(testIssuerKey(t)))
	require.NoError(t, err)

	_, err = CreateEnvelopedPresentation(sdjwt.SdJwt(unbound), keyBinder, true, presentationNonce, presentationAudience)
	require.ErrorContains(t, err, "holder key")
}
