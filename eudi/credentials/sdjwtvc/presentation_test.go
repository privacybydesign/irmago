package sdjwtvc

import (
	"testing"

	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/stretchr/testify/require"
)

func buildTestSdJwtWithNestedClaims(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "TestCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdClaim("given_name", "Alice"),
			SdClaim("family_name", "Smith"),
			SdObject("address",
				SdClaim("street", "123 Main St"),
				SdClaim("city", "Amsterdam"),
				SdClaim("country", "NL"),
			),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

func TestCreatePresentation_SelectTopLevelClaim(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"given_name"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.NotContains(t, disclosures, "family_name")
	require.NotContains(t, disclosures, "address")
}

func TestCreatePresentation_SelectMultipleTopLevelClaims(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"given_name"}, {"family_name"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.Contains(t, disclosures, "family_name")
	require.NotContains(t, disclosures, "address")
}

func TestCreatePresentation_SelectNestedClaim(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"address", "street"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	// Should include the parent "address" disclosure and the nested "street" disclosure.
	require.Contains(t, disclosures, "address")
	require.Contains(t, disclosures, "street")
	require.NotContains(t, disclosures, "city")
	require.NotContains(t, disclosures, "country")
}

func TestCreatePresentation_SelectMultipleNestedClaims(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{
		{"address", "street"},
		{"address", "city"},
	})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "address")
	require.Contains(t, disclosures, "street")
	require.Contains(t, disclosures, "city")
	require.NotContains(t, disclosures, "country")
}

func TestCreatePresentation_MixTopLevelAndNested(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{
		{"given_name"},
		{"address", "city"},
	})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.Contains(t, disclosures, "address")
	require.Contains(t, disclosures, "city")
	require.NotContains(t, disclosures, "family_name")
	require.NotContains(t, disclosures, "street")
}

func TestCreatePresentation_EmptyPaths_NoDisclosures(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_NonExistentClaim_NoError(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"nonexistent"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_DuplicatePaths_NoDuplicateDisclosures(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithNestedClaims(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{
		{"address", "street"},
		{"address", "street"},
		{"address", "city"},
	})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	// "address" should appear only once even though two paths traverse it.
	count := 0
	for _, k := range disclosures {
		if k == "address" {
			count++
		}
	}
	require.Equal(t, 1, count, "address disclosure should appear exactly once")
}

// --- SD-JWTs with mixed SD and non-SD claims ---

// buildMixedSdJwt has top-level claims where some are SD and some are plaintext.
func buildMixedSdJwt(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "MixedCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdClaim("email", "alice@example.com"),   // SD
			Claim("nickname", "Ali"),                // plaintext (not SD)
			SdClaim("phone_number", "+31612345678"), // SD
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

// buildMixedNestedSdJwt has a non-SD object containing SD sub-claims, and
// an SD object containing a mix of SD and non-SD sub-claims.
func buildMixedNestedSdJwt(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "MixedNestedCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdClaim("given_name", "Bob"),
			// Non-SD object with SD sub-claims: address is always visible,
			// but its children are selectively disclosable.
			Object("address",
				SdClaim("street", "456 Oak Ave"),
				Claim("country", "NL"), // plaintext inside the object
				SdClaim("city", "Rotterdam"),
			),
			// SD object with a mix of SD and non-SD sub-claims.
			SdObject("employment",
				Claim("company", "Acme Corp"), // plaintext inside SD object
				SdClaim("title", "Engineer"),
				SdClaim("salary", "100000"),
			),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

func TestCreatePresentation_Mixed_SelectSdClaim_SkipsPlaintext(t *testing.T) {
	sdJwt := buildMixedSdJwt(t)

	result, err := CreatePresentation(sdJwt, [][]any{{"email"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "email")
	require.NotContains(t, disclosures, "phone_number")
	// "nickname" is plaintext — it should never appear as a disclosure.
	require.NotContains(t, disclosures, "nickname")
}

func TestCreatePresentation_Mixed_SelectPlaintextClaim_NoDisclosure(t *testing.T) {
	sdJwt := buildMixedSdJwt(t)

	// "nickname" is not selectively disclosed; requesting it yields no disclosures.
	result, err := CreatePresentation(sdJwt, [][]any{{"nickname"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_Mixed_SelectAllSdClaims(t *testing.T) {
	sdJwt := buildMixedSdJwt(t)

	result, err := CreatePresentation(sdJwt, [][]any{{"email"}, {"phone_number"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "email")
	require.Contains(t, disclosures, "phone_number")
	require.Len(t, disclosures, 2)
}

func TestCreatePresentation_MixedNested_NonSdParent_SelectSdChild(t *testing.T) {
	sdJwt := buildMixedNestedSdJwt(t)

	// "address" is a non-SD object, so no disclosure for it.
	// "street" inside address is SD.
	result, err := CreatePresentation(sdJwt, [][]any{{"address", "street"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "street")
	// "address" itself is not SD — no disclosure for it.
	require.NotContains(t, disclosures, "address")
	require.NotContains(t, disclosures, "city")
}

func TestCreatePresentation_MixedNested_NonSdParent_SelectPlaintextChild(t *testing.T) {
	sdJwt := buildMixedNestedSdJwt(t)

	// "country" inside "address" is plaintext — no disclosure needed.
	result, err := CreatePresentation(sdJwt, [][]any{{"address", "country"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_MixedNested_SdParent_SelectSdChild(t *testing.T) {
	sdJwt := buildMixedNestedSdJwt(t)

	// "employment" is an SD object, "title" inside it is also SD.
	result, err := CreatePresentation(sdJwt, [][]any{{"employment", "title"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "employment")
	require.Contains(t, disclosures, "title")
	require.NotContains(t, disclosures, "salary")
	require.NotContains(t, disclosures, "company")
}

func TestCreatePresentation_MixedNested_SdParent_SelectPlaintextChild(t *testing.T) {
	sdJwt := buildMixedNestedSdJwt(t)

	// "company" inside "employment" is plaintext, but "employment" itself is SD.
	// Selecting the plaintext child should still include the parent disclosure.
	result, err := CreatePresentation(sdJwt, [][]any{{"employment", "company"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	// The parent "employment" disclosure is needed to reveal the object.
	require.Contains(t, disclosures, "employment")
	// "company" is plaintext — no separate disclosure for it.
	require.NotContains(t, disclosures, "company")
}

func TestCreatePresentation_MixedNested_CombinedPaths(t *testing.T) {
	sdJwt := buildMixedNestedSdJwt(t)

	result, err := CreatePresentation(sdJwt, [][]any{
		{"given_name"},
		{"address", "street"},
		{"address", "city"},
		{"employment", "title"},
	})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.Contains(t, disclosures, "street")
	require.Contains(t, disclosures, "city")
	require.Contains(t, disclosures, "employment")
	require.Contains(t, disclosures, "title")
	require.NotContains(t, disclosures, "family_name")
	require.NotContains(t, disclosures, "salary")
}

// --- SD-JWTs with array claims ---

// buildSdJwtWithArrays has:
//   - "tags": a non-SD array with mixed SD/non-SD items
//   - "roles": an SD array (the array itself is selectively disclosed)
//   - "scores": a plaintext array (non-SD, non-SD items)
func buildSdJwtWithArrays(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "ArrayCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdClaim("name", "Charlie"),
			// Non-SD array containing a mix of SD and non-SD items.
			Array("tags",
				Item("public-tag"),
				SdItem("secret-tag"),
				Item("another-public"),
			),
			// SD array: the entire array is selectively disclosed.
			SdArray("roles",
				Item("admin"),
				Item("editor"),
			),
			// Plaintext array with only non-SD items.
			Array("scores",
				Item(90),
				Item(85),
			),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

// buildSdJwtWithNestedArrayInObject has an object containing an SD array.
func buildSdJwtWithNestedArrayInObject(t *testing.T) SdJwtVc {
	t.Helper()
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "NestedArrayCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdObject("profile",
				SdClaim("username", "charlie"),
				SdArray("permissions",
					Item("read"),
					Item("write"),
				),
			),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

func TestCreatePresentation_SdArray_SelectByKey(t *testing.T) {
	sdJwt := buildSdJwtWithArrays(t)

	// "roles" is an SD array — selecting it should include its disclosure.
	result, err := CreatePresentation(sdJwt, [][]any{{"roles"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "roles")
	require.NotContains(t, disclosures, "name")
}

func TestCreatePresentation_NonSdArray_NotDisclosed(t *testing.T) {
	sdJwt := buildSdJwtWithArrays(t)

	// "tags" is a non-SD array — selecting it yields no disclosures for the array itself.
	// (The SD items inside have no key, so they can't be selected by path.)
	result, err := CreatePresentation(sdJwt, [][]any{{"tags"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.NotContains(t, disclosures, "tags")
}

func TestCreatePresentation_PlaintextArray_NotDisclosed(t *testing.T) {
	sdJwt := buildSdJwtWithArrays(t)

	// "scores" is fully plaintext — no disclosures at all.
	result, err := CreatePresentation(sdJwt, [][]any{{"scores"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Empty(t, disclosures)
}

func TestCreatePresentation_SdArrayAndSdClaim_Combined(t *testing.T) {
	sdJwt := buildSdJwtWithArrays(t)

	result, err := CreatePresentation(sdJwt, [][]any{{"name"}, {"roles"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "name")
	require.Contains(t, disclosures, "roles")
	require.Len(t, disclosures, 2)
}

func TestCreatePresentation_NestedSdArrayInSdObject(t *testing.T) {
	sdJwt := buildSdJwtWithNestedArrayInObject(t)

	// Select the nested SD array "permissions" inside the SD object "profile".
	result, err := CreatePresentation(sdJwt, [][]any{{"profile", "permissions"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	// Both the parent "profile" and nested "permissions" disclosures should be included.
	require.Contains(t, disclosures, "profile")
	require.Contains(t, disclosures, "permissions")
	require.NotContains(t, disclosures, "username")
}

func TestCreatePresentation_NestedSdClaim_AlongsideSdArray(t *testing.T) {
	sdJwt := buildSdJwtWithNestedArrayInObject(t)

	// Select both a scalar SD claim and an SD array from the same parent.
	result, err := CreatePresentation(sdJwt, [][]any{
		{"profile", "username"},
		{"profile", "permissions"},
	})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "profile")
	require.Contains(t, disclosures, "username")
	require.Contains(t, disclosures, "permissions")

	// "profile" should appear only once.
	count := 0
	for _, k := range disclosures {
		if k == "profile" {
			count++
		}
	}
	require.Equal(t, 1, count)
}

func buildTestSdJwtWithoutSdAlg(t *testing.T) SdJwtVc {
	t.Helper()
	// Build an SD-JWT without _sd_alg. Per SD-JWT spec Section 4.1.1,
	// the holder MUST default to sha-256 when _sd_alg is absent.
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_VerifiableCredentialType, "TestCredential"),
			Claim(Key_IssuedAt, 1700000000),
			SdClaim("given_name", "Alice"),
			SdClaim("email", "alice@example.com"),
		).
		Build(NewEcdsaJwtCreatorWithIssuerTestkey())
	require.NoError(t, err)
	return sdJwt
}

func TestCreatePresentation_MissingSdAlg_DefaultsToSha256(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithoutSdAlg(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"given_name"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.NotContains(t, disclosures, "email")
}

func TestCreatePresentation_MissingSdAlg_AllClaims(t *testing.T) {
	fullSdJwt := buildTestSdJwtWithoutSdAlg(t)

	result, err := CreatePresentation(fullSdJwt, [][]any{{"given_name"}, {"email"}})

	require.NoError(t, err)
	disclosures := extractDisclosureKeys(t, result)
	require.Contains(t, disclosures, "given_name")
	require.Contains(t, disclosures, "email")
}

// extractDisclosureKeys splits the SD-JWT result and returns the keys of all included disclosures.
func extractDisclosureKeys(t *testing.T, sdJwt SdJwtVc) []string {
	t.Helper()
	_, disclosures, err := splitSdJwtVc(sdJwt)
	require.NoError(t, err)
	var keys []string
	for _, d := range disclosures {
		decoded, err := DecodeDisclosure(d)
		require.NoError(t, err)
		keys = append(keys, decoded.Key)
	}
	return keys
}
