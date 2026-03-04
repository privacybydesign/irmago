package did

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

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
	b := &Builder{}
	doc, err := b.FromJwk(key)

	// Assert
	require.NoError(t, err)

	require.Equal(t, doc.ID, expectedDid)

	require.Len(t, doc.Context, 2)
	require.Contains(t, doc.Context, "https://www.w3.org/ns/did/v1")
	require.Contains(t, doc.Context, "https://w3id.org/security/suites/jws-2020/v1")

	require.Len(t, doc.VerificationMethod, 1)
	require.Equal(t, doc.VerificationMethod[0].ID, expectedKid)
	require.Equal(t, doc.VerificationMethod[0].Type, "JsonWebKey2020")
	require.Equal(t, doc.VerificationMethod[0].Controller, expectedDid)
	require.NotNil(t, doc.VerificationMethod[0].PublicKeyJwk)

	// Validate `sig` key usage results in correct authentication and assertionMethod entries
	require.Len(t, doc.Authentication, 1)
	require.Equal(t, doc.Authentication[0], expectedKid)
	require.Len(t, doc.AssertionMethod, 1)
	require.Equal(t, doc.AssertionMethod[0], expectedKid)

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
	b := &Builder{}
	doc, err := b.FromJwk(key)

	// Assert
	require.NoError(t, err)

	require.Equal(t, doc.ID, expectedDid)

	require.Len(t, doc.Context, 2)
	require.Contains(t, doc.Context, "https://www.w3.org/ns/did/v1")
	require.Contains(t, doc.Context, "https://w3id.org/security/suites/jws-2020/v1")

	require.Len(t, doc.VerificationMethod, 1)
	require.Equal(t, doc.VerificationMethod[0].ID, expectedKid)
	require.Equal(t, doc.VerificationMethod[0].Type, "JsonWebKey2020")
	require.Equal(t, doc.VerificationMethod[0].Controller, expectedDid)
	require.NotNil(t, doc.VerificationMethod[0].PublicKeyJwk)

	// Validate `enc` key usage results in correct keyAgreement entry
	require.Len(t, doc.KeyAgreement, 1)
	require.Equal(t, doc.KeyAgreement[0], expectedKid)

	require.Nil(t, doc.Authentication)
	require.Nil(t, doc.AssertionMethod)
}
