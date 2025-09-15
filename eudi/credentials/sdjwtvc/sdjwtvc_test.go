package sdjwtvc

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// is `iss` field is required
func TestNoIssuerLinkIsErr(t *testing.T) {
	payload := IssuerSignedJwtPayload{
		Subject:                  "subject",
		VerifiableCredentialType: "pbdf.sidn-pbdf.email",
		Expiry:                   0,
		IssuedAt:                 0,
		Issuer:                   "",
	}

	_, err := IssuerSignedJwtPayload_ToJson(payload)
	require.Error(t, err)
}

// the `iss` field of the issuer signed jwt is required to have a valid https link
func TestNoHttpsIssuerIsErr(t *testing.T) {
	payload := IssuerSignedJwtPayload{
		Subject:                  "subject",
		VerifiableCredentialType: "pbdf.sidn-pbdf.email",
		Expiry:                   0,
		IssuedAt:                 0,
		Issuer:                   "http://invalid.com",
	}

	_, err := IssuerSignedJwtPayload_ToJson(payload)
	require.Error(t, err)
}

func TestIssuerSignedJwtPayloadToJson(t *testing.T) {
	payload := IssuerSignedJwtPayload{
		Subject:                  "subject",
		VerifiableCredentialType: "pbdf.sidn-pbdf.email",
		Expiry:                   0,
		IssuedAt:                 0,
		Issuer:                   "https://example.com",
	}

	json, err := IssuerSignedJwtPayload_ToJson(payload)

	require.NoError(t, err)

	values := jsonToMap(t, json)

	require.Equal(t, values[Key_Subject], "subject")
	require.Equal(t, values[Key_VerifiableCredentialType], "pbdf.sidn-pbdf.email")
	require.Equal(t, values[Key_Issuer], "https://example.com")

	require.NotContains(t, values, Key_Sd)
	require.NotContains(t, values, Key_SdAlg)
	require.NotContains(t, values, Key_Confirmationkey)
}

func TestDisclosuresSaltBasicRequirements(t *testing.T) {
	numDisclosures := 1000
	// 128bit == 16 bytes, *4/3 for base64 encoding, rounded up == 22 characters
	expectedSaltLen := 22

	for range numDisclosures {
		disc, err := NewDisclosureContent("name", "Bert")
		require.NoError(t, err)
		require.Len(t, disc.Salt, expectedSaltLen)
	}
}

func TestCreateMultipleDisclosures(t *testing.T) {
	disclosures, err := MultipleNewDisclosureContents(map[string]string{
		"name":     "Yivi",
		"location": "Utrecht",
		"country":  "Netherlands",
	})

	require.NoError(t, err)
	require.Len(t, disclosures, 3)
}

func TestCreateSdJwtVcWithSingleDisclosuresAndWithoutKbJwt(t *testing.T) {
	issuer := "https://example.com"
	disclosures, err := MultipleNewDisclosureContents(map[string]string{"family": "Yivi"})
	require.NoError(t, err)

	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()

	sdjwt, err := NewSdJwtVcBuilder().
		WithIssuerUrl(issuer).
		WithVerifiableCredentialType("pbdf.pbdf.email").
		WithDisclosures(disclosures).
		WithHashingAlgorithm(HashAlg_Sha256).
		Build(jwtCreator)

	require.NoError(t, err)

	require.True(t, strings.HasSuffix(string(sdjwt), "~"), "sdjwt expected to end with ~ but doesn't: %v", sdjwt)

	if num := strings.Count(string(sdjwt), "~"); num != 2 {
		t.Fatalf("sdjwt expected have 2 ~ but has: %v (%v)", num, sdjwt)
	}
}

func TestCreateSdJwtVcWithDisclosuresAndKbJwt(t *testing.T) {
	keyBinder := NewDefaultKeyBinderWithInMemoryStorage()
	sdjwt := createDefaultTestingSdJwt(t, keyBinder)
	kbjwt := createKbJwt(t, sdjwt, keyBinder)
	fullSdjwt := AddKeyBindingJwtToSdJwtVc(sdjwt, kbjwt)

	if numTildes := strings.Count(string(fullSdjwt), "~"); numTildes != 3 {
		t.Fatalf("expected 3 ~, but got %v (%v)", numTildes, fullSdjwt)
	}
}

func TestGetKeysShouldReturnAllKeysFromDisclosureContents(t *testing.T) {
	// Arrange
	dc1, err := NewDisclosureContent("email", "test@gmail.com")
	require.NoError(t, err)
	dc2, err := NewDisclosureContent("domain", "gmail.com")
	require.NoError(t, err)
	dc3, err := NewDisclosureContent("location", "Utrecht")
	require.NoError(t, err)

	disclosureContents := DisclosureContents([]DisclosureContent{dc1, dc2, dc3})

	// Act
	keys := slices.Collect(disclosureContents.Keys())

	// Assert
	require.Len(t, keys, 3)
	require.Equal(t, "email", keys[0])
	require.Equal(t, "domain", keys[1])
	require.Equal(t, "location", keys[2])
}
