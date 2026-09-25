package sdjwt

import (
	"encoding/json"
	"testing"

	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/stretchr/testify/require"
)

// ========================== Base Processor Tests ================================
// fails for:
// - [x] flat SD-JWT: _sd field is present but empty
// - [x] flat SD-JWT: _sd field is not an array
// - [x] flat SD-JWT: _sd field contains non-string values
// - [x] flat SD-JWT: disclosure contains an _sd field
// - [x] flat SD-JWT: disclosure contains an ... field
// - [x] flat SD-JWT: disclosure already contains a fieldname at the same level
// - [x] flat SD-JWT: invalid digest element in array
// - [x] flat SD-JWT: disclosures that are not in the _sd field
// - [x] flat SD-JWT: digest is processed multiple times (single _sd field)
// - [x] flat SD-JWT: digest is processed multiple times (in single array)
// - [x] flat SD-JWT: digest is processed multiple times (in multiple array)
// - [x] structured SD-JWT: disclosure structures, digest is processed multiple times

// success for:
// - [x] flat SD-JWT: disclosures for non-array claims
// - [x] flat SD-JWT: disclosures for array claims
// - [x] flat SD-JWT: non-array permanent disclosure element stays after processing
// - [x] flat SD-JWT: array with disclosures and permanently disclosed values in the array
// - [x] flat SD-JWT: array with disclosures and decoy digests in the array
// - [x] structured SD-JWT: without array
// - [x] structured SD-JWT: with array, containing decoy digests
// - [x] structured SD-JWT: with recursive disclosure structures

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_EmptySdField_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{}
	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{},
	}

	// Act
	_, _, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "when the _sd field is present it may not be empty")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_SdFieldIsNotAnArray_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{}
	issuerSignedJwtPayload := map[string]any{
		SdKey: 42,
	}

	// Act
	_, _, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "failed to convert _sd field to []any")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_NonStringSdField_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{}
	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{42},
	}

	// Act
	_, _, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "failed to convert value in _sd array to string")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_DisclosureContainsSdField_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","_sd","test"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwiX3NkIiwidGVzdCJd",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			"uaqRlJ33nALYusFITW0nuk67ZynCsLdwTI4EymZB5Rw",
		},
	}

	// Act
	_, _, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "has an `_sd` field, which is not allowed")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_DisclosureContainsEllipsisField_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","...","test"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwiLi4uIiwidGVzdCJd",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			"YRYvIY_GmMyi58Byf6JCg3CZvC7D6MGmKOaEx2plM1k",
		},
	}

	// Act
	_, _, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "has an `...` field, which is not allowed")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_AlreadyContainsFieldnameAtSameLevel_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","name","Alpha"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwibmFtZSIsIkFscGhhIl0",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			"c3DYrtRZ3zLEKH2fcTrkRymiT4T5ZkwQuFfj3TlnRQQ",
		},
		"name": "Bravo",
	}

	// Act
	_, _, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "embedded disclosure key \"name\" already exists at this level")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_DisclosuresThatAreNotInSdField_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","family_name","T"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwiZmFtaWx5X25hbWUiLCJUIl0",
		// disclosure: ["OKyl8ky692IYD_W9OPP8xg","given_name","T"]
		"WyJPS3lsOGt5NjkySVlEX1c5T1BQOHhnIiwiZ2l2ZW5fbmFtZSIsIlQiXQ",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			"dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU",
		},
	}

	// Act
	_, _, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "one or more disclosures were not referenced in the issuer signed jwt")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_DigigestIsProcessedMultipleTimes_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","family_name","T"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwiZmFtaWx5X25hbWUiLCJUIl0",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			"dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU",
			"dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU",
		},
	}

	// Act
	_, _, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "digest dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU has been referenced multiple time in the SD-JWT")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_DigigestIsProcessedMultipleTimesInSingleArrays_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",[{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"},{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiYjdNVFhSWm1NeUUyMl9aeWlOdkFwNmh5Z0k1WThFeTZLTnVLVWFINmxpbyJ9LHsiLi4uIjoiYjdNVFhSWm1NeUUyMl9aeWlOdkFwNmh5Z0k1WThFeTZLTnVLVWFINmxpbyJ9XV0",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			// Hash for array (NOT the array element)
			"VSrHGnWHF4kq8bqP8PXoWCKa-hMkyfiJP8yUiACwNcM",
		},
	}

	// Act
	_, _, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "digest b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio has been referenced multiple time in the SD-JWT")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_DigigestIsProcessedMultipleTimesInMultipleArrays_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",[{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiYjdNVFhSWm1NeUUyMl9aeWlOdkFwNmh5Z0k1WThFeTZLTnVLVWFINmxpbyJ9XV0",
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","countries",[{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwiY291bnRyaWVzIixbeyIuLi4iOiJiN01UWFJabU15RTIyX1p5aU52QXA2aHlnSTVZOEV5NktOdUtVYUg2bGlvIn1dXQ",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			// Hash for arrays (NOT the array element)
			"3KpnrnSJV9ING3MqFexvxLLkAEQDs4suq3MgG0RnE54",
			"qt0kqMISbwENMMG5np5ABItPxlRMr4Wo3GhaIFdgE8A",
		},
	}

	// Act
	_, _, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "digest b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio has been referenced multiple time in the SD-JWT")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_StructuredSdJwt_DigigestIsProcessedMultipleTimes_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","family_name","T"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwiZmFtaWx5X25hbWUiLCJUIl0",
	}

	issuerSignedJwtPayload := `{
		"_sd": [
			"dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU"
		],
		"name": {
			"_sd": [
				"dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU"
			]
		}
	}`

	var issuerSignedJwtPayloadFromJson map[string]any
	err := json.Unmarshal([]byte(issuerSignedJwtPayload), &issuerSignedJwtPayloadFromJson)
	require.NoError(t, err)

	// Act
	_, _, err = VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayloadFromJson, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "digest dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU has been referenced multiple time in the SD-JWT")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_ContainsNoArrays_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","family_name","T"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwiZmFtaWx5X25hbWUiLCJUIl0",
		// disclosure: ["OKyl8ky692IYD_W9OPP8xg","given_name","T"]
		"WyJPS3lsOGt5NjkySVlEX1c5T1BQOHhnIiwiZ2l2ZW5fbmFtZSIsIlQiXQ",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			"dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU",
			"K4oRic8I4m2y8lMUAN7MttLYrynKgocsENANMvPoHYQ",
		},
	}

	// Act
	_, disclosures, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload[SdKey]
	require.False(t, ok)

	// Check the claims are present/replaced correctly
	_, ok = issuerSignedJwtPayload["family_name"]
	require.True(t, ok)
	_, ok = issuerSignedJwtPayload["given_name"]
	require.True(t, ok)
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_SingleDisclosure_TestDifferentHashes_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// disclosure: ["_3JoPNqbcqtsdax9J0xMvA","family_name","T"]
		"WyJfM0pvUE5xYmNxdHNkYXg5SjB4TXZBIiwiZmFtaWx5X25hbWUiLCJUIl0",
	}
	hashesToTest := map[iana.HashingAlgorithm]string{
		iana.SHA256:     "dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU",
		iana.SHA384:     "jq03BsgTeA0UuE5s7EMnSdXHP35d1DROgK9C1FAT_aV9GCqmW6HEqsEBCSp7jBFt",
		iana.SHA512:     "4xoBB4X6C56fq2Vkz5J_xl_RS8c-CMOOJkWwlCgHxum3w2AFlEEd6PnqGE6BNBv1JBuQt7Cv21l6nfVsVWJ1tA",
		iana.SHA3_224:   "KttLY32VE3PowLQLwhI0xy19JggL1ql_rnZw4g",
		iana.SHA3_256:   "xcIlD3Mz0Mb3xUq0nKv0kozqQoa-H5Y_xJo-qi5QD2M",
		iana.SHA3_384:   "69Yq7MXjvlhddV-iYYicC_dy1IqmqjS2dVZcfV4da6C2tHPPBcG16_lEsIBUJV7n",
		iana.SHA3_512:   "3O8jzRqGPYewnc9O7T3KwSNpnRWnD0FSigT0A_x7hOhsrQ1457FERQbNqMDt73iSgBDCYvIOBwNWESmqftTmxA",
		iana.SHA256_128: "dUbKLep3EvcBWZm6Y30WAg",
		iana.SHA256_120: "dUbKLep3EvcBWZm6Y30W",
		iana.SHA256_96:  "dUbKLep3EvcBWZm6",
		iana.SHA256_64:  "dUbKLep3Evc",
		iana.SHA256_32:  "dUbKLQ",
	}

	for hashAlg, expectedDigest := range hashesToTest {
		t.Run(string(hashAlg), func(t *testing.T) {
			// Arrange
			issuerSignedJwtPayload := map[string]any{
				SdKey: []any{
					expectedDigest,
				},
			}

			// Act
			_, disclosures, err := VerifyAndProcessDisclosures(hashAlg, &issuerSignedJwtPayload, encodedDisclosures)

			// Assert
			require.NoError(t, err)
			require.Len(t, disclosures, 1)

			// Check that _sd field is removed from issuer signed jwt payload
			_, ok := issuerSignedJwtPayload[SdKey]
			require.False(t, ok)

			// Check the claims are present/replaced correctly
			_, ok = issuerSignedJwtPayload["family_name"]
			require.True(t, ok)
		})
	}
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_ContainsAnArray_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",[{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiYjdNVFhSWm1NeUUyMl9aeWlOdkFwNmh5Z0k1WThFeTZLTnVLVWFINmxpbyJ9XV0",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			// Hash for array (NOT the array element)
			"3KpnrnSJV9ING3MqFexvxLLkAEQDs4suq3MgG0RnE54",
		},
	}

	// Act
	_, disclosures, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload[SdKey]
	require.False(t, ok)

	arrVal, ok := issuerSignedJwtPayload["nationalities"]
	require.True(t, ok)
	require.NotNil(t, arrVal)

	// The array should now contain 1 element
	arr, ok := arrVal.([]any)
	require.True(t, ok)
	require.Len(t, arr, 1)
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_WithPermanentDisclosure_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// flat object: ["2GLC42sKQveCfGfryNRN9w", "street_address", "Schulstr. 12"]
		"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			"9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
		},
		"country": "DE",
	}

	// Act
	_, disclosures, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 1)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload[SdKey]
	require.False(t, ok)

	// Map should now contain the permanently disclosed value + the selectively disclosed value
	require.Len(t, issuerSignedJwtPayload, 2)

	arrVal, ok := issuerSignedJwtPayload["street_address"]
	require.True(t, ok)
	require.Equal(t, arrVal, "Schulstr. 12")

	// The array should now contain 1 element
	arrVal, ok = issuerSignedJwtPayload["country"]
	require.True(t, ok)
	require.Equal(t, arrVal, "DE")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_ContainsAnArray_WithPermanentlyDisclosedValues_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",["DE","FR",{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsWyJERSIsIkZSIix7Ii4uLiI6ImI3TVRYUlptTXlFMjJfWnlpTnZBcDZoeWdJNVk4RXk2S051S1VhSDZsaW8ifV1d",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			// Hash for array
			"bH_IUnOFqaa2MAX1YNxrSyYv4OzPFC9cWwEMI3gn72w",
		},
	}

	// Act
	_, disclosures, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload[SdKey]
	require.False(t, ok)

	arrVal, ok := issuerSignedJwtPayload["nationalities"]
	require.True(t, ok)
	require.NotNil(t, arrVal)

	// The array should now contain 3 elements: "DE", "FR", and the disclosed object
	arr, ok := arrVal.([]any)
	require.True(t, ok)
	require.Len(t, arr, 3)
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_ContainsAnArray_GivenInvalidDigestElement_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// valid array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// invalid array element digest (extra field): ["invalid_extra_element_in_digest_element", "dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJpbnZhbGlkX2V4dHJhX2VsZW1lbnRfaW5fZGlnZXN0X2VsZW1lbnQiLCAiZEl2ZnBhaW9pVGVwNW9yejZlRVp4dyIsIk5MIl0",
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",[{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"},{"...":"h-CQlbsh70pquZdVagjwYSojWUT41ZzXfvr3FLCo4Ks"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiYjdNVFhSWm1NeUUyMl9aeWlOdkFwNmh5Z0k1WThFeTZLTnVLVWFINmxpbyJ9LHsiLi4uIjoiaC1DUWxic2g3MHBxdVpkVmFnandZU29qV1VUNDFaelhmdnIzRkxDbzRLcyJ9XV0",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			// Hash for array (NOT the array element)
			"3mhS5a0J_TxEK5ZHlES0_MRx7qV7FERCHbX2lSEz94Q",
		},
	}

	// Act
	_, disclosures, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.Error(t, err)
	require.ErrorContains(t, err, "is expected to be an array element, but is not")
	require.Nil(t, disclosures)
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_ContainsAnArray_WithDecoyDigests_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		// array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// array with valid element (element 0) and one decoy digest (element 1, which is a hash over a 'secure random' value)
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",[{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"},{"...":"wBIalkzxNqdBbT-eotJFegKmirdUPyyXLxIbtFugdsI"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiYjdNVFhSWm1NeUUyMl9aeWlOdkFwNmh5Z0k1WThFeTZLTnVLVWFINmxpbyJ9LHsiLi4uIjoid0JJYWxrenhOcWRCYlQtZW90SkZlZ0ttaXJkVVB5eVhMeElidEZ1Z2RzSSJ9XV0",
	}

	issuerSignedJwtPayload := map[string]any{
		SdKey: []any{
			// Hash for array (NOT the array element)
			"FxetI8EvzLU8v49U8JdbN0FsQs4UtwudaT7xdPLYU3g",
		},
	}

	// Act
	_, disclosures, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload[SdKey]
	require.False(t, ok)

	arrVal, ok := issuerSignedJwtPayload["nationalities"]
	require.True(t, ok)
	require.NotNil(t, arrVal)

	// The array should only contain the valid element, the decoy digest should be ignored
	arr, ok := arrVal.([]any)
	require.True(t, ok)
	require.Len(t, arr, 1)
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_StructuredSdJwt_ContainsNoArrays_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
		"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0",
		"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd",
		"WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ",
	}

	issuerSignedJwtPayload := `{
		"address": {
			"_sd": [
				"6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0",
				"9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
				"KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88",
				"WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM"
			]
		}
	}`

	var issuerSignedJwtPayloadFromJson map[string]any
	err := json.Unmarshal([]byte(issuerSignedJwtPayload), &issuerSignedJwtPayloadFromJson)
	require.NoError(t, err)

	// Act
	_, disclosures, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayloadFromJson, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 4)

	addr, ok := issuerSignedJwtPayloadFromJson["address"]
	require.True(t, ok)
	require.NotNil(t, addr)

	addrMap, ok := addr.(map[string]any)
	require.True(t, ok)

	// Check that _sd field is removed from `address` field in the issuer signed jwt payload
	_, ok = addrMap[SdKey]
	require.False(t, ok)

	// The object should contain 4 fields now: street_address, locality, region, country
	require.Len(t, addrMap, 4)
	require.Contains(t, addrMap["street_address"], "Schulstr. 12")
	require.Contains(t, addrMap["locality"], "Schulpforta")
	require.Contains(t, addrMap["region"], "Sachsen-Anhalt")
	require.Contains(t, addrMap["country"], "DE")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_StructuredSdJwt_ContainsArraysWithDecoyDigest_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
		"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0",
		"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd",
		"WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ",
		// array element: ["dIvfpaioiTep5orz6eEZxw","NL"]
		"WyJkSXZmcGFpb2lUZXA1b3J6NmVFWnh3IiwiTkwiXQ",
		// array with valid element (element 0) and one decoy digest (element 1, which is a hash over a 'secure random' value)
		// array: ["PW8uSwHPfOh3fENJGCeEBQ","nationalities",[{"...":"b7MTXRZmMyE22_ZyiNvAp6hygI5Y8Ey6KNuKUaH6lio"},{"...":"wBIalkzxNqdBbT-eotJFegKmirdUPyyXLxIbtFugdsI"}]]
		"WyJQVzh1U3dIUGZPaDNmRU5KR0NlRUJRIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiYjdNVFhSWm1NeUUyMl9aeWlOdkFwNmh5Z0k1WThFeTZLTnVLVWFINmxpbyJ9LHsiLi4uIjoid0JJYWxrenhOcWRCYlQtZW90SkZlZ0ttaXJkVVB5eVhMeElidEZ1Z2RzSSJ9XV0",
	}

	issuerSignedJwtPayload := `{
		"address": {
			"_sd": [
				"6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0",
				"9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
				"KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88",
				"WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM",
				"FxetI8EvzLU8v49U8JdbN0FsQs4UtwudaT7xdPLYU3g"
			]
		}
	}`

	var issuerSignedJwtPayloadFromJson map[string]any
	err := json.Unmarshal([]byte(issuerSignedJwtPayload), &issuerSignedJwtPayloadFromJson)
	require.NoError(t, err)

	// Act
	_, disclosures, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayloadFromJson, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 6)

	addr, ok := issuerSignedJwtPayloadFromJson["address"]
	require.True(t, ok)
	require.NotNil(t, addr)

	addrMap, ok := addr.(map[string]any)
	require.True(t, ok)

	// Check that _sd field is removed from `address` field in the issuer signed jwt payload
	_, ok = addrMap[SdKey]
	require.False(t, ok)

	// The object should contain 5 fields now: street_address, locality, region, country, nationalities
	require.Len(t, addrMap, 5)
	require.Contains(t, addrMap["street_address"], "Schulstr. 12")
	require.Contains(t, addrMap["locality"], "Schulpforta")
	require.Contains(t, addrMap["region"], "Sachsen-Anhalt")
	require.Contains(t, addrMap["country"], "DE")

	natVal, ok := addrMap["nationalities"]
	require.True(t, ok)
	require.NotNil(t, natVal)

	// The array should only contain the valid element, the decoy digest should be ignored
	natArr, ok := natVal.([]any)
	require.True(t, ok)
	require.Len(t, natArr, 1)
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_RecursiveDisclosures_Succeeds(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{
		"WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImV4dGVuc2lvbiIsICJiaXMiXQ", // extension disclosure
		"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgIm51bWJlciIsICIxMiJd",       // number disclosure
		"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImhvdXNlbnVtYmVyIiwgeyJfc2QiOlsiMW9mOW82ZXRjNWdTWkpXQmVERHl3eGI1RVcwbE14Z2diWUdHQ1RiWG9VNCIsIjExZEZzM0ZVWTdUa0hDdmIwZDU2T2p6bU5yZVJWMl9pdDVwNXZtS0FXY0UiXX1d", // housenumber disclosure
		"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInN0cmVldCIsICJTY2h1bHN0ci4iXQ", // street disclosure
		"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInN0cmVldF9hZGRyZXNzIiwgeyJfc2QiOlsic1BTT1VmTkVJSW5FUE14cTlrVC1YU0ptT0tyRkpVTC0yZElQektPcmNhVSIsIndQNG9kbFJDUzlybmlZZjJ6UTNjNEVrU2JySUpKTHdTR21MY0ZrWDVKNVkiXX1d", // street_address disclosure
	}

	// Format:
	// {
	//   "address": {
	//     "street_address": {
	//       "street": "Schulstr."
	//     	 "housenumber": {
	//			"number": "12"
	//		    "extension": "bis"
	//		 }
	//     }
	// 	 }
	// }
	// Where the address only contains a pointer to the street_address disclosure, which will need to (recursively) build the full structure
	issuerSignedJwtPayload := `{
		"address": {
			"_sd": [
				"2c7XHh7XAUa0NknanfXW1vTWsJ7tqgOnDzsnZGEFtl4"
			]
		}
	}`

	var issuerSignedJwtPayloadFromJson map[string]any
	err := json.Unmarshal([]byte(issuerSignedJwtPayload), &issuerSignedJwtPayloadFromJson)
	require.NoError(t, err)

	// Act
	_, disclosures, err := VerifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayloadFromJson, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 5)

	addr, ok := issuerSignedJwtPayloadFromJson["address"]
	require.True(t, ok)
	require.NotNil(t, addr)

	addrMap, ok := addr.(map[string]any)
	require.True(t, ok)

	// Check that _sd field is removed from `address` field in the issuer signed jwt payload
	_, ok = addrMap[SdKey]
	require.False(t, ok)

	// The object should contain 1 field now: street_address
	require.Len(t, addrMap, 1)

	streetAddrVal, ok := addrMap["street_address"]
	require.True(t, ok)
	require.NotNil(t, streetAddrVal)

	streetAddrMap, ok := streetAddrVal.(map[string]any)
	require.True(t, ok)

	// The street_address object should contain 2 fields now: street, housenumber
	require.Len(t, streetAddrMap, 2)
	require.Contains(t, streetAddrMap["street"], "Schulstr.")

	housenumberVal, ok := streetAddrMap["housenumber"]
	require.True(t, ok)
	require.NotNil(t, housenumberVal)

	housenumberMap, ok := housenumberVal.(map[string]any)
	require.True(t, ok)

	// The housenumber object should contain 2 fields now: number, extension
	require.Len(t, housenumberMap, 2)
	require.Contains(t, housenumberMap["number"], "12")
	require.Contains(t, housenumberMap["extension"], "bis")
}
