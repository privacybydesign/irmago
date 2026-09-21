package sdjwt

import (
	"slices"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/stretchr/testify/require"
)

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

func TestSdJwtWithSingleDisclosureAndWithoutKbJwt(t *testing.T) {
	sdJwt, err := NewBuilder().
		WithPayload(
			Claim(jwt.IssuerKey, "https://example.com"),
			Claim(SdAlgKey, iana.SHA256),
			SdClaim("family", "Yivi"),
		).
		Build(newTestJwtCreator(t))

	require.NoError(t, err)

	require.True(t, strings.HasSuffix(string(sdJwt), "~"), "SD-JWT expected to end with ~ but doesn't: %v", sdJwt)

	if num := strings.Count(string(sdJwt), "~"); num != 2 {
		t.Fatalf("SD-JWT expected have 2 ~ but has: %v (%v)", num, sdJwt)
	}
}

func TestSdJwtWithDisclosuresAndKbJwt(t *testing.T) {
	keyBinder := NewDefaultKeyBinderWithInMemoryStorage()
	holderKeys, err := keyBinder.CreateKeyPairs(1)
	require.NoError(t, err)
	holderKeyClaim, err := HolderKeyClaim(holderKeys[0])
	require.NoError(t, err)

	sdJwt, err := NewBuilder().
		WithPayload(
			holderKeyClaim,
			Claim(jwt.IssuerKey, "https://example.com"),
			Claim(SdAlgKey, iana.SHA256),
			SdClaim("family_name", "Yivi"),
			SdClaim("location", "Utrecht"),
		).
		Build(newTestJwtCreator(t))
	require.NoError(t, err)

	kbjwt, err := CreateKbJwt(sdJwt, keyBinder, "nonce", "Verifier")
	require.NoError(t, err)

	fullSdJwt := AddKeyBindingJwt(sdJwt, kbjwt)

	if numTildes := strings.Count(string(fullSdJwt), "~"); numTildes != 3 {
		t.Fatalf("expected 3 ~, but got %v (%v)", numTildes, fullSdJwt)
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

func TestObjectPropertyDecodeDisclosure(t *testing.T) {
	// Arrange
	encodedDisclosure := EncodedDisclosure("WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwiZmFtaWx5X25hbWUiLCJUZXN0Il0")

	// Act
	decodedDisclosure, err := DecodeDisclosure(encodedDisclosure)

	// Assert
	require.NoError(t, err)
	require.Equal(t, "Test", decodedDisclosure.Value)
	require.Equal(t, "family_name", decodedDisclosure.Key)
	require.False(t, decodedDisclosure.isArrayElement)
}

func TestArrayElementDecodeDisclosure(t *testing.T) {
	// Arrange
	encodedDisclosure := EncodedDisclosure("WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ")

	// Act
	decodedDisclosure, err := DecodeDisclosure(encodedDisclosure)

	// Assert
	require.NoError(t, err)
	require.Equal(t, "NL", decodedDisclosure.Value)
	require.Empty(t, decodedDisclosure.Key)
	require.True(t, decodedDisclosure.isArrayElement)
}

func Test_DecodingDisclosure_Succeeds(t *testing.T) {
	content, err := NewDisclosureContent("name", "Yivi")
	require.NoError(t, err)
	d, err := EncodeDisclosure(content)
	require.NoError(t, err)

	decoded, err := DecodeDisclosure(d)
	require.NoError(t, err)

	require.Equal(t, "name", decoded.Key)
	require.Equal(t, "Yivi", decoded.Value)
}
