package didjwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/did"
	"github.com/stretchr/testify/require"
)

// encodeDid base64url-encodes the given JWK JSON verbatim into a did:jwk, so tests can
// control the exact serialization the DID is built from.
func encodeDid(jwkJson string) string {
	return Prefix + base64.RawURLEncoding.EncodeToString([]byte(jwkJson))
}

func Test_FromJwk_Given_AsymmetricKeyWithSignatureKeyUsage_Succeeds(t *testing.T) {
	// Arrange
	const expectedDid = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwidXNlIjoic2lnIiwieCI6ImNuS2VLWW1TNEdDS01YNnVieVE0aW1faThab0EzWlZCbVJrR0xxM0RtUDAiLCJ5IjoiNFJrMW9NcFJqUVNMNzVTMkJJNktSRHFtSlRwRVFNM05rdlZKbnFkMnF4NCJ9"
	const expectedKid = expectedDid + "#0"

	// This is a randomly generated key, so it doesn't matter what the exact values are, as long as they are correctly included in the resulting DID Document
	jwkJson := `{
		"crv": "P-256",
		"kty": "EC",
		"use": "sig",
		"x": "cnKeKYmS4GCKMX6ubyQ4im_i8ZoA3ZVBmRkGLq3DmP0",
		"y": "4Rk1oMpRjQSL75S2BI6KRDqmJTpEQM3NkvVJnqd2qx4"
	}`

	key, err := jwk.ParseKey([]byte(jwkJson))
	if err != nil {
		t.Fatalf("failed to parse JWK: %v", err)
	}

	// Act
	b := &DocumentBuilder{}
	doc, err := b.FromJwk(key)

	// Assert
	require.NoError(t, err)

	require.Equal(t, doc.ID, expectedDid)

	require.Len(t, doc.Context, 2)
	require.Contains(t, doc.Context, "https://www.w3.org/ns/did/v1")
	require.Contains(t, doc.Context, "https://w3id.org/security/suites/jws-2020/v1")

	require.Len(t, doc.VerificationMethod, 1)
	require.Equal(t, doc.VerificationMethod[0].ID, expectedKid)
	require.Equal(t, doc.VerificationMethod[0].Type, did.VerificationMethodType_JsonWebKey2020)
	require.Equal(t, doc.VerificationMethod[0].Controller, expectedDid)
	require.NotNil(t, doc.VerificationMethod[0].PublicKeyJwk)

	// The spec says `sig` key usage yields every verification relationship except keyAgreement
	require.Equal(t, []did.VerificationRef{expectedKid}, doc.Authentication)
	require.Equal(t, []did.VerificationRef{expectedKid}, doc.AssertionMethod)
	require.Equal(t, []did.VerificationRef{expectedKid}, doc.CapabilityInvocation)
	require.Equal(t, []did.VerificationRef{expectedKid}, doc.CapabilityDelegation)

	require.Nil(t, doc.KeyAgreement)
}

func Test_FromJwk_Given_AsymmetricKeyWithEncryptionKeyUsage_Succeeds(t *testing.T) {
	// Arrange
	const expectedDid = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwidXNlIjoiZW5jIiwieCI6ImNuS2VLWW1TNEdDS01YNnVieVE0aW1faThab0EzWlZCbVJrR0xxM0RtUDAiLCJ5IjoiNFJrMW9NcFJqUVNMNzVTMkJJNktSRHFtSlRwRVFNM05rdlZKbnFkMnF4NCJ9"
	const expectedKid = expectedDid + "#0"

	// This is a randomly generated key, so it doesn't matter what the exact values are, as long as they are correctly included in the resulting DID Document
	jwkJson := `{
		"crv": "P-256",
		"kty": "EC",
		"use": "enc",
		"x": "cnKeKYmS4GCKMX6ubyQ4im_i8ZoA3ZVBmRkGLq3DmP0",
		"y": "4Rk1oMpRjQSL75S2BI6KRDqmJTpEQM3NkvVJnqd2qx4"
	}`

	key, err := jwk.ParseKey([]byte(jwkJson))
	if err != nil {
		t.Fatalf("failed to parse JWK: %v", err)
	}

	// Act
	b := &DocumentBuilder{}
	doc, err := b.FromJwk(key)

	// Assert
	require.NoError(t, err)

	require.Equal(t, doc.ID, expectedDid)

	require.Len(t, doc.Context, 2)
	require.Contains(t, doc.Context, "https://www.w3.org/ns/did/v1")
	require.Contains(t, doc.Context, "https://w3id.org/security/suites/jws-2020/v1")

	require.Len(t, doc.VerificationMethod, 1)
	require.Equal(t, doc.VerificationMethod[0].ID, expectedKid)
	require.Equal(t, doc.VerificationMethod[0].Type, did.VerificationMethodType_JsonWebKey2020)
	require.Equal(t, doc.VerificationMethod[0].Controller, expectedDid)
	require.NotNil(t, doc.VerificationMethod[0].PublicKeyJwk)

	// The spec says `enc` key usage yields keyAgreement and nothing else
	require.Equal(t, []did.VerificationRef{expectedKid}, doc.KeyAgreement)

	require.Nil(t, doc.Authentication)
	require.Nil(t, doc.AssertionMethod)
	require.Nil(t, doc.CapabilityInvocation)
	require.Nil(t, doc.CapabilityDelegation)
}

func Test_FromJwk_Given_AsymmetricKeyWithoutKeyUsage_IncludesAllVerificationRelationships(t *testing.T) {
	// Arrange
	// A JWK without a `use` member. The spec's DID Document template lists every
	// verification relationship, and only a `use` member narrows that set down.
	jwkJson := `{
		"crv": "P-256",
		"kty": "EC",
		"x": "cnKeKYmS4GCKMX6ubyQ4im_i8ZoA3ZVBmRkGLq3DmP0",
		"y": "4Rk1oMpRjQSL75S2BI6KRDqmJTpEQM3NkvVJnqd2qx4"
	}`

	key, err := jwk.ParseKey([]byte(jwkJson))
	require.NoError(t, err)

	// Act
	doc, err := (&DocumentBuilder{}).FromJwk(key)

	// Assert
	require.NoError(t, err)

	expectedKid := doc.ID + "#0"
	require.Equal(t, []did.VerificationRef{expectedKid}, doc.Authentication)
	require.Equal(t, []did.VerificationRef{expectedKid}, doc.AssertionMethod)
	require.Equal(t, []did.VerificationRef{expectedKid}, doc.CapabilityInvocation)
	require.Equal(t, []did.VerificationRef{expectedKid}, doc.CapabilityDelegation)
	require.Equal(t, []did.VerificationRef{expectedKid}, doc.KeyAgreement)
}

func Test_FromJwk_Given_PrivateKey_ReturnsError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privKey)
	require.NoError(t, err)

	_, err = (&DocumentBuilder{}).FromJwk(key)
	require.ErrorContains(t, err, "cannot contain private key material")
}

func Test_FromJwk_Given_SymmetricKey_ReturnsError(t *testing.T) {
	key, err := jwk.Import([]byte("0123456789abcdef"))
	require.NoError(t, err)

	_, err = (&DocumentBuilder{}).FromJwk(key)
	require.ErrorContains(t, err, "requires an asymmetric public key")
}

func Test_Resolve_Given_OkpPublicKey_Succeeds(t *testing.T) {
	didJwk := encodeDid(`{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)

	key, err := Resolve(didJwk)

	require.NoError(t, err)
	require.Equal(t, "OKP", key.KeyType().String())
}

func Test_Resolve_Given_PrivateKey_ReturnsError(t *testing.T) {
	// The spec: "a JWK for a private key must never be used and must be rejected by all
	// implementations". Without this check the private key would be handed to callers as
	// if it were a legitimately resolved public key.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import(privKey)
	require.NoError(t, err)
	privJson, err := json.Marshal(key)
	require.NoError(t, err)

	_, err = Resolve(encodeDid(string(privJson)))
	require.ErrorContains(t, err, "cannot contain private key material")
}

func Test_Resolve_Given_SymmetricKey_ReturnsError(t *testing.T) {
	didJwk := encodeDid(`{"kty":"oct","k":"MDEyMzQ1Njc4OWFiY2RlZg"}`)

	_, err := Resolve(didJwk)
	require.ErrorContains(t, err, "requires an asymmetric public key")
}

func Test_Resolve_Given_UnknownFragment_ReturnsError(t *testing.T) {
	didJwk := encodeDid(`{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)

	// A did:jwk DID Document only ever holds the verification method "#0", so no other
	// fragment can be dereferenced.
	_, err := Resolve(didJwk + "#1")
	require.ErrorContains(t, err, `invalid did:jwk fragment "1"`)

	_, err = Resolve(didJwk + "#key-1")
	require.ErrorContains(t, err, `invalid did:jwk fragment "key-1"`)

	_, err = Resolve(didJwk + "#0")
	require.NoError(t, err)
}

func Test_ResolveDocument_Given_ForeignMemberOrdering_KeepsTheDidUnchanged(t *testing.T) {
	// A did:jwk minted by another implementation that serializes "kty" first. The spec
	// puts no ordering requirement on the JWK, so this DID is as valid as our own, but
	// re-encoding the parsed key produces a different (member-sorted) DID string.
	didJwk := encodeDid(`{"kty":"EC","crv":"P-256","x":"cnKeKYmS4GCKMX6ubyQ4im_i8ZoA3ZVBmRkGLq3DmP0","y":"4Rk1oMpRjQSL75S2BI6KRDqmJTpEQM3NkvVJnqd2qx4"}`)

	doc, err := ResolveDocument(didJwk)

	require.NoError(t, err)
	require.Equal(t, didJwk, doc.ID)
	require.Len(t, doc.VerificationMethod, 1)
	require.Equal(t, didJwk+"#0", doc.VerificationMethod[0].ID)
	require.Equal(t, didJwk, doc.VerificationMethod[0].Controller)
	require.Equal(t, did.VerificationMethodType_JsonWebKey2020, doc.VerificationMethod[0].Type)
	require.NotNil(t, doc.VerificationMethod[0].PublicKeyJwk)
}

func Test_ResolveDocument_Given_DidWithFragment_KeepsTheDidWithoutFragment(t *testing.T) {
	didJwk := encodeDid(`{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)

	doc, err := ResolveDocument(didJwk + "#0")

	require.NoError(t, err)
	require.Equal(t, didJwk, doc.ID)
	require.Equal(t, didJwk+"#0", doc.VerificationMethod[0].ID)
}

func Test_ResolveDocument_RoundTripsADocumentBuiltFromAJwk(t *testing.T) {
	jwkJson := `{"crv":"P-256","kty":"EC","use":"sig","x":"cnKeKYmS4GCKMX6ubyQ4im_i8ZoA3ZVBmRkGLq3DmP0","y":"4Rk1oMpRjQSL75S2BI6KRDqmJTpEQM3NkvVJnqd2qx4"}`
	key, err := jwk.ParseKey([]byte(jwkJson))
	require.NoError(t, err)

	built, err := (&DocumentBuilder{}).FromJwk(key)
	require.NoError(t, err)

	resolved, err := ResolveDocument(built.ID)
	require.NoError(t, err)

	require.Equal(t, built.ID, resolved.ID)
	require.Equal(t, built.Context, resolved.Context)
	require.Equal(t, built.VerificationMethod[0].ID, resolved.VerificationMethod[0].ID)
	require.Equal(t, built.AssertionMethod, resolved.AssertionMethod)
	require.Equal(t, built.KeyAgreement, resolved.KeyAgreement)
}
