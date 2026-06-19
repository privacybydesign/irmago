package sdjwtvc

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/testdata"
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
		"_sd": []any{},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "when the _sd field is present it may not be empty")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_SdFieldIsNotAnArray_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{}
	issuerSignedJwtPayload := map[string]any{
		"_sd": 42,
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.ErrorContains(t, err, "failed to convert _sd field to []any")
}

func Test_SdJwtProcessor_VerifyAndProcessPayloadDisclosures_FlatSdJwt_NonStringSdField_Fails(t *testing.T) {
	// Arrange
	encodedDisclosures := []EncodedDisclosure{}
	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{42},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

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
		"_sd": []any{
			"uaqRlJ33nALYusFITW0nuk67ZynCsLdwTI4EymZB5Rw",
		},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

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
		"_sd": []any{
			"YRYvIY_GmMyi58Byf6JCg3CZvC7D6MGmKOaEx2plM1k",
		},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

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
		"_sd": []any{
			"c3DYrtRZ3zLEKH2fcTrkRymiT4T5ZkwQuFfj3TlnRQQ",
		},
		"name": "Bravo",
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

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
		"_sd": []any{
			"dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU",
		},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

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
		"_sd": []any{
			"dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU",
			"dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU",
		},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

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
		"_sd": []any{
			// Hash for array (NOT the array element)
			"VSrHGnWHF4kq8bqP8PXoWCKa-hMkyfiJP8yUiACwNcM",
		},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

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
		"_sd": []any{
			// Hash for arrays (NOT the array element)
			"3KpnrnSJV9ING3MqFexvxLLkAEQDs4suq3MgG0RnE54",
			"qt0kqMISbwENMMG5np5ABItPxlRMr4Wo3GhaIFdgE8A",
		},
	}

	// Act
	_, _, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

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
	_, _, err = verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayloadFromJson, encodedDisclosures)

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
		"_sd": []any{
			"dUbKLep3EvcBWZm6Y30WAp9EHEMcxPUwiA6yy6LYSwU",
			"K4oRic8I4m2y8lMUAN7MttLYrynKgocsENANMvPoHYQ",
		},
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload["_sd"]
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
				"_sd": []any{
					expectedDigest,
				},
			}

			// Act
			_, disclosures, err := verifyAndProcessDisclosures(hashAlg, &issuerSignedJwtPayload, encodedDisclosures)

			// Assert
			require.NoError(t, err)
			require.Len(t, disclosures, 1)

			// Check that _sd field is removed from issuer signed jwt payload
			_, ok := issuerSignedJwtPayload["_sd"]
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
		"_sd": []any{
			// Hash for array (NOT the array element)
			"3KpnrnSJV9ING3MqFexvxLLkAEQDs4suq3MgG0RnE54",
		},
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload["_sd"]
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
		"_sd": []any{
			"9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
		},
		"country": "DE",
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 1)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload["_sd"]
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
		"_sd": []any{
			// Hash for array
			"bH_IUnOFqaa2MAX1YNxrSyYv4OzPFC9cWwEMI3gn72w",
		},
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload["_sd"]
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
	payload := IssuerSignedJwtPayload{
		SdAlg: "sha-256",
	}

	issuerSignedJwtPayload := map[string]any{
		"_sd": []any{
			// Hash for array (NOT the array element)
			"3mhS5a0J_TxEK5ZHlES0_MRx7qV7FERCHbX2lSEz94Q",
		},
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures(payload.SdAlg, &issuerSignedJwtPayload, encodedDisclosures)

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
		"_sd": []any{
			// Hash for array (NOT the array element)
			"FxetI8EvzLU8v49U8JdbN0FsQs4UtwudaT7xdPLYU3g",
		},
	}

	// Act
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayload, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 2)

	// Check that _sd field is removed from issuer signed jwt payload
	_, ok := issuerSignedJwtPayload["_sd"]
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
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayloadFromJson, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 4)

	addr, ok := issuerSignedJwtPayloadFromJson["address"]
	require.True(t, ok)
	require.NotNil(t, addr)

	addrMap, ok := addr.(map[string]any)
	require.True(t, ok)

	// Check that _sd field is removed from `address` field in the issuer signed jwt payload
	_, ok = addrMap["_sd"]
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
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayloadFromJson, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 6)

	addr, ok := issuerSignedJwtPayloadFromJson["address"]
	require.True(t, ok)
	require.NotNil(t, addr)

	addrMap, ok := addr.(map[string]any)
	require.True(t, ok)

	// Check that _sd field is removed from `address` field in the issuer signed jwt payload
	_, ok = addrMap["_sd"]
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
	_, disclosures, err := verifyAndProcessDisclosures("sha-256", &issuerSignedJwtPayloadFromJson, encodedDisclosures)

	// Assert
	require.NoError(t, err)
	require.Len(t, disclosures, 5)

	addr, ok := issuerSignedJwtPayloadFromJson["address"]
	require.True(t, ok)
	require.NotNil(t, addr)

	addrMap, ok := addr.(map[string]any)
	require.True(t, ok)

	// Check that _sd field is removed from `address` field in the issuer signed jwt payload
	_, ok = addrMap["_sd"]
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

// ======================= Holder verification tests ==============================
// fails for:
// - [x] invalid jwt as the issuer signed jwt
// - [x] issuer signed jwt with key binding jwt
// - [x] typ in issuer signed jwt is not vc+sd-jwt or dc+sd-jwt
// - [x] invalid sd-jwt (missing trailing ~)
// - [x] iss link missing
// - [x] valid self-signed x509 certificate that doesn't match a trusted certificate
// - [x] missing vct link
// - [x] clock.now + skew is before iat
// - [x] clock.now + skew is before nbf
// - [x] clock.now - skew is after exp
// - [x] empty but not missing _sd field
// - [x] unsupported _sd_alg
// - [x] failing to get issuer metadata fails the verification
// - [x] no iss value provided
// - [x] invalid disclosures (different than in _sd field)

// success for
// - [x] iss link is non-https, but is accepted (for testing purposes)
// - [x] missing _sd_alg claim, falls back to sha-256
// - [x] valid SD-JWT, no disclosures, no KB-JWT
// - [x] valid SD-JWT, with disclosures, no KB-JWT
// - [x] baseline generated valid sd-jwt vc with disclosures, issuer signed jwt and x5c
// - [x] less disclosures than are in the _sd field
// - [x] different orders for disclosures
// - [x] issuer signed jwt doesn't contain any sd's
// - [x] valid self-signed x509 certificate with DNS/URI value that matches `iss` value
// - [x] valid x509 certificate chain with DNS/URI value that matches `iss` value
// - [x] clock.now - 1 minute is before iat (valid because of skew)
// - [x] clock.now - 1 minute is before nbf (valid because of skew)
// - [x] clock.now + 1 minute is after exp (valid because of skew)

func Test_HolderVerificationProcessor_InvalidJwtForIssuerSignedJwt_Fails(t *testing.T) {
	sdJwt := SdJwtVc("slkjfaslkgdjaglj")
	context := CreateTestVerificationContext()

	holderVerifier := NewHolderVerificationProcessor(context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdJwt))

	require.Error(t, err)
}

func Test_HolderVerificationProcessor_MissingSdAlg_FallbackToSha256_Succeeds(t *testing.T) {
	missingSdAlgField := newWorkingSdJwtVcTestConfig()
	missingSdAlgField.sdAlg = nil
	noErrorTestCaseHolder(t, missingSdAlgField, "missing _sd_alg field falls back to sha-256")
}

func Test_HolderVerificationProcessor_IssuerSignedJwt_WithKeyBindingJwt_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	holderVerifier := NewHolderVerificationProcessor(context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(validSdJwtVc_VcTypHeader_WithKbJwt))

	require.Error(t, err, "failed to parse JWT: jwt.Parse: failed to parse token: jws.Verify: key provider 0 failed: invalid 'typ' header: jwt")
}

func Test_HolderVerificationProcessor_IssuerSignedJwt_WithInvalidTypHeader_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	holderVerifier := NewHolderVerificationProcessor(context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(wrongIssuerSignedJwtTypHeader))

	require.Error(t, err, "failed to parse JWT: jwt.Parse: failed to parse token: jws.Verify: key provider 0 failed: invalid 'typ' header: jwt")
}

func Test_HolderVerificationProcessor_BothX5cAndKidHeaders_Fails(t *testing.T) {
	// A JWT carrying both x5c and kid must be rejected: if both were accepted the kid
	// branch would overwrite the x5c key provider and the X.509 trust/CRL check would be
	// silently skipped, allowing a forged credential to verify against the kid-resolved key.
	bothKeyReferences := newWorkingSdJwtVcTestConfig().
		withKidHeader("did:jwk:attacker#0")
	errorTestCaseHolder(t, bothKeyReferences, "both 'x5c' and 'kid' headers are present")
}

func Test_HolderVerificationProcessor_InvalidSdJwtVc_MissingTrailingTilde_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(invalidSdJwtVc_MissingTrailingTilde))
	require.Error(t, err)
}

func Test_HolderVerificationProcessor_MissingIssuerUrl_Fails(t *testing.T) {
	missingIssuerUrl := newWorkingSdJwtVcTestConfig()
	missingIssuerUrl.issuerUrl = nil
	errorTestCaseHolder(t, missingIssuerUrl, "missing iss field")
}

func Test_HolderVerificationProcessor_ValidButUntrusted_SelfSigned_X509Cert_Fails(t *testing.T) {
	runCertChainTestCase(t, x509TestConfig{
		IssuerCert: testdata.IssuerCert_irma_app_Bytes,
		IssUrl:     "https://irma.app",
		ShouldFail: true,
	})
}

func Test_HolderVerificationProcessor_MissingVct_Fails(t *testing.T) {
	missingVct := newWorkingSdJwtVcTestConfig()
	missingVct.vct = nil
	errorTestCaseHolder(t, missingVct, "missing vct field")
}

func Test_HolderVerificationProcessor_IatIsAfterVerification_Fails(t *testing.T) {
	now := time.Now().Unix()
	iat := now + ClockSkewInSeconds + 100

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&iat)

	context := SdJwtVcVerificationContext{
		Clock:       &testClock{time: now},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.Error(t, err)
}

func Test_HolderVerificationProcessor_VerificationIsAfterExp_Fails(t *testing.T) {
	now := time.Now().Unix()
	exp := now - ClockSkewInSeconds - 100

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&now).
		withExpiryTime(&exp)

	context := SdJwtVcVerificationContext{
		Clock:       &testClock{time: now},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.Error(t, err)
}

func Test_HolderVerificationProcessor_VerificationIsBeforeNotBefore_Fails(t *testing.T) {
	now := time.Now().Unix()
	nbf := now + ClockSkewInSeconds + 50
	exp := int64(100)

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&now).
		withExpiryTime(&exp).
		withNotBefore(&nbf)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(),
		},
		Clock:       &testClock{time: now},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.Error(t, err)
}

func Test_HolderVerificationProcessor_EmptyButNotMissingSdField_Fails(t *testing.T) {
	emptyNotMissingSdField := newWorkingSdJwtVcTestConfig().
		withSdClaims([]DisclosureContent{}, iana.SHA256).
		withDisclosures([]DisclosureContent{})
	errorTestCaseHolder(t, emptyNotMissingSdField, "failed to parse sd field: when the _sd field is present it may not be empty")
}

func Test_HolderVerificationProcessor_UnsupportedSdAlg_Fails(t *testing.T) {
	wrongSdAlgField := newWorkingSdJwtVcTestConfig().withSdAlg("SHA-null")
	errorTestCaseHolder(t, wrongSdAlgField, "unsupported _sd_alg: SHA-null")
}

func Test_HolderVerificationProcessor_ValidSdJwtVc_NoDisclosures_NoKbJwt_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	holderVerifier := NewHolderVerificationProcessor(context)

	verifiedSdJwtVc, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(validSdJwtVc_NoDisclosuresNoKbjwt))
	require.NoError(t, err)

	require.Len(t, verifiedSdJwtVc.Disclosures, 0)
	require.Nil(t, verifiedSdJwtVc.KeyBindingJwt)
}

func Test_HolderVerificationProcessor_BaselineGeneratedSdJwtVc_Succeeds(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig()
	noErrorTestCaseHolder(t, config, "default working test sdjwtvc creator is valid")
}

func Test_HolderVerificationProcessor_StatusClaim_RoundtripsThroughPayload(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig().
		withStatusListReference("https://issuer.example/sl/1", 42)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
	require.NotNil(t, verified.IssuerSignedJwtPayload.Status)
	require.NotNil(t, verified.IssuerSignedJwtPayload.Status.StatusList)
	require.Equal(t, "https://issuer.example/sl/1", verified.IssuerSignedJwtPayload.Status.StatusList.URI)
	require.Equal(t, uint64(42), verified.IssuerSignedJwtPayload.Status.StatusList.Index)
}

func Test_HolderVerificationProcessor_StatusClaim_AbsentLeavesPayloadStatusNil(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig() // no status reference
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)

	verified, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
	require.Nil(t, verified.IssuerSignedJwtPayload.Status)
}

func Test_HolderVerificationProcessor_StatusCheck_ValidList_Accepts(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://openid4vc.staging.yivi.app",
		Bits:     1,
		Statuses: map[uint64]uint8{7: 0}, // Valid at idx 7
	})

	config := newWorkingSdJwtVcTestConfig().withStatusListReference(srv.URL(), 7)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.StatusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_StatusCheck_InvalidList_Rejects(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://openid4vc.staging.yivi.app",
		Bits:     1,
		Statuses: map[uint64]uint8{7: 1}, // Invalid at idx 7
	})

	config := newWorkingSdJwtVcTestConfig().withStatusListReference(srv.URL(), 7)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.StatusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.ErrorContains(t, err, "credential status is invalid")
}

func Test_HolderVerificationProcessor_StatusCheck_UnreachableURI_FailsClosed(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	config := newWorkingSdJwtVcTestConfig().withStatusListReference("http://127.0.0.1:0/nope", 0)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.StatusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.ErrorContains(t, err, "status list check failed")
}

func Test_HolderVerificationProcessor_StatusCheck_NilCheckerLeavesClaimUnverified(t *testing.T) {
	// Even with a status reference present, a nil StatusChecker
	// must not reject the credential — this is the back-compat path
	// for callers that haven't opted into status checks.
	config := newWorkingSdJwtVcTestConfig().withStatusListReference("https://issuer.example/sl/1", 0)
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	// context.StatusChecker is nil.

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_StatusCheck_NoStatusClaim_PassesWithCheckerConfigured(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	config := newWorkingSdJwtVcTestConfig() // no status reference
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.StatusChecker = statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	_, err := NewHolderVerificationProcessor(context).ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_FewerDisclosuresThanSdHashes_Succeeds(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig()
	config.disclosures = []DisclosureContent{
		config.disclosures[1],
	}
	noErrorTestCaseHolder(t, config, "fewer disclosures than _sd field hashes is valid")
}

func Test_HolderVerificationProcessor_DifferentOrderDisclosures_Succeeds(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig()
	config.disclosures = []DisclosureContent{
		config.disclosures[1],
		config.disclosures[0],
	}
	noErrorTestCaseHolder(t, config, "different order disclosures than _sd field hashes is valid")
}

func Test_HolderVerificationProcessor_NoSdsAtAll_Succeeds(t *testing.T) {
	config := newWorkingSdJwtVcTestConfig()

	config.sdClaims = nil
	config.disclosures = []DisclosureContent{}

	noErrorTestCaseHolder(t, config, "no _sd claims at all is valid (if no disclosures either)")
}

func Test_HolderVerificationProcessor_ValidLeafCertOnly_Succeeds(t *testing.T) {
	runCertChainTestCase(t, x509TestConfig{
		IssuerCert:                     testdata.IssuerCert_irma_app_Bytes,
		VerifierTrustedIssuerCertChain: testdata.IssuerCert_irma_app_Bytes,
		IssUrl:                         "https://irma.app",
		ShouldFail:                     false,
	})
}

func Test_HolderVerificationProcessor_Valid_X509Chain_Succeeds(t *testing.T) {
	runCertChainTestCase(t, x509TestConfig{
		IssuerCert:                     testdata.IssuerCert_irma_app_Bytes,
		VerifierTrustedIssuerCertChain: testdata.IssuerCertChain_irma_app_Bytes,
		IssUrl:                         "https://irma.app",
		ShouldFail:                     false,
	})
}

func Test_HolderVerificationProcessor_VerificationMinusOneMinuteIsBeforeIat_GivenClockSkew_Success(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcTestConfig().withIssuedAt(&now)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_VerificationPlusOneMinuteIsAfterExp_GivenClockSkew_Success(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&now).
		withExpiryTime(&now)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now + 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_VerificationMinusOneMinuteIsBeforeNotBefore_GivenClockSkew_Success(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&now).
		withNotBefore(&now)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now - 60},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}

func Test_HolderVerificationProcessor_TimeFieldsAreParsedCorrectly(t *testing.T) {
	now := time.Now().Unix()
	exp := now + 86400 // 1 day from now
	nbf := now - 60

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(&now).
		withExpiryTime(&exp).
		withNotBefore(&nbf)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	result, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)

	require.Equal(t, now, *result.IssuerSignedJwtPayload.IssuedAt, "IssuedAt should match the iat claim")
	require.Equal(t, exp, *result.IssuerSignedJwtPayload.Expiry, "Expiry should match the exp claim")
	require.Equal(t, nbf, *result.IssuerSignedJwtPayload.NotBefore, "NotBefore should match the nbf claim")
}

func Test_HolderVerificationProcessor_MissingTimeFieldsAreParsedCorrectly(t *testing.T) {
	now := time.Now().Unix()

	config := newWorkingSdJwtVcTestConfig().
		withIssuedAt(nil).
		withExpiryTime(nil).
		withNotBefore(nil)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now},
		JwtVerifier: NewJwxJwtVerifier(),
	}

	sdjwtvc := createTestSdJwtVc(t, config)
	holderVerifier := NewHolderVerificationProcessor(context)

	result, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)

	require.Nil(t, result.IssuerSignedJwtPayload.IssuedAt, "IssuedAt should be nil")
	require.Nil(t, result.IssuerSignedJwtPayload.Expiry, "Expiry should be nil")
	require.Nil(t, result.IssuerSignedJwtPayload.NotBefore, "NotBefore should be nil")
}

func Test_HolderVerificationProcessor_ProcessedSdJwtPayload_ContainsDisclosedClaims(t *testing.T) {
	// Arrange: build a credential with two selective-disclosure claims (email + domain),
	// matching what an OpenID4VCI issuer would produce.
	now := time.Now().Unix()
	exp := now + 86400

	disclosures, err := MultipleNewDisclosureContents(map[string]string{
		"email":  "holder@example.com",
		"domain": "example.com",
	})
	require.NoError(t, err)

	config := newWorkingSdJwtVcTestConfig().
		withVct("test.test.email").
		withIssuedAt(&now).
		withExpiryTime(&exp).
		withSdClaims(disclosures, iana.SHA256).
		withDisclosures(disclosures)

	sdjwtvc := createTestSdJwtVc(t, config)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: newWorkingVerifyOptions(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes),
		},
		Clock:       &testClock{time: now},
		JwtVerifier: NewJwxJwtVerifier(),
	}
	holderVerifier := NewHolderVerificationProcessor(context)

	// Act
	result, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))

	// Assert
	require.NoError(t, err)

	payload := result.ProcessedSdJwtPayload

	// Standard JWT claims must be present
	require.Equal(t, "https://openid4vc.staging.yivi.app", payload["iss"], "iss claim should be present in processed payload")
	require.Equal(t, "test.test.email", payload["vct"], "vct claim should be present in processed payload")

	// Selectively-disclosed claims must be embedded directly in the processed payload
	require.Equal(t, "holder@example.com", payload["email"], "email disclosure should be embedded in processed payload")
	require.Equal(t, "example.com", payload["domain"], "domain disclosure should be embedded in processed payload")

	// _sd and _sd_alg must be stripped from the processed payload
	_, hasSd := payload["_sd"]
	require.False(t, hasSd, "_sd field should be removed from processed payload")
	_, hasSdAlg := payload["_sd_alg"]
	require.False(t, hasSdAlg, "_sd_alg field should be removed from processed payload")
}

// ======================= Verifier verification tests ==============================
// fails for:
// - [x] required kb-jwt, but missing
// - [x] invalid kb-jwt typ header
// - [x] missing sd_hash in kb-jwt
// - [x] sd_hash in KB-JWT does not match calculated hash
// - [x] missing cnf field in issuer signed JWT, but kb-jwt present
// - [x] kb-jwt nonce does not match expected nonce
// - [x] kb-jwt aud does not match expected audience (client_id)
//
// succeeds for:
// - [x] required kb-jwt, valid sd-jwt, matching hash in kb-jwt
// - [x] non-required kb-jwt, no KB-JWT present
// - [x] kb-jwt nonce matches expected nonce
// - [x] kb-jwt aud matches expected audience (client_id)

func Test_VerifierVerificationProcessor_RequiredKbJwt_NoKbJwtInSdJwt_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	verifierVerificationProcessor := NewVerifierVerificationProcessor(true, context)
	_, err := verifierVerificationProcessor.ParseAndVerifySdJwtVc(SdJwtVcKb(validSdJwtVc_DcTypHeader_WithoutKbJwt))
	require.ErrorContains(t, err, "key binding jwt is required, but not present in sdjwtvc")
}

func Test_VerifierVerificationProcessor_InvalidSdJwtVc_WrongKbJwtTypHeader_Fails(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	holderVerifier := NewVerifierVerificationProcessor(true, context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(invalidSdJwtVC_WrongKbTypHeader))
	require.Error(t, err)
}

func Test_VerifierVerificationProcessor_NoSdHash_Fails(t *testing.T) {
	noHashConfig := newWorkingSdJwtVcKbTestConfig().withoutAnySdHash()
	errorTestCaseVerifier(t, noHashConfig, "issuer signed jwt hash missing in kbjwt")
}

func Test_VerifierVerificationProcessor_RequiredKbJwt_ValidSdJwt_MismatchingHashInKbJwt_Fails(t *testing.T) {
	sdHashMismatchInKb := newWorkingSdJwtVcKbTestConfig().withSdHash("12356")
	errorTestCaseVerifier(t, sdHashMismatchInKb, "issuer signed jwt hash doesn't equal sd_hash found in kbjwt")
}

func Test_VerifierVerificationProcessor_NoCnfFieldInIssuerSignedJwt_WithKbJwt_Fails(t *testing.T) {
	noCnfFieldWithKbJwt := newWorkingSdJwtVcKbTestConfig()
	noCnfFieldWithKbJwt.cnfPubKey = nil
	errorTestCaseVerifier(t, noCnfFieldWithKbJwt, "issuer signed jwt is missing holder key (cnf) required to verify kbjwt signature")
}

func Test_VerifierVerificationProcessor_RequiredKbJwt_WithKbJwtInSdJwt_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	context.ExpectedAudience = "Verifier" // The testdata contains a KB-JWT with aud "Verifier", which would usually be something like "<client_id_prefix>:<orig_client_id>"
	verifierVerificationProcessor := NewVerifierVerificationProcessor(true, context)
	_, err := verifierVerificationProcessor.ParseAndVerifySdJwtVc(SdJwtVcKb(validSdJwtVc_DcTypHeader_WithKbJwt))
	require.NoError(t, err)
}

func Test_VerifierVerificationProcessor_KbJwtNonce_MatchesExpectedNonce_Succeeds(t *testing.T) {
	realNonce := "abc123-real-nonce"

	config := newWorkingSdJwtVcKbTestConfig()
	config.withKbNonce(realNonce)

	sdjwtvc := createTestSdJwtVcKb(t, config)

	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = realNonce
	context.ExpectedAudience = "Verifier" // The testdata contains a KB-JWT with aud "Verifier", which would usually be something like "<client_id_prefix>:<orig_client_id>"

	verifier := NewVerifierVerificationProcessor(true, context)
	_, err := verifier.ParseAndVerifySdJwtVc(sdjwtvc)
	require.NoError(t, err)
}

func Test_VerifierVerificationProcessor_KbJwtNonce_DoesNotMatchExpectedNonce_Fails(t *testing.T) {
	config := newWorkingSdJwtVcKbTestConfig()
	config.withKbNonce("nonce-in-kbjwt")

	sdjwtvc := createTestSdJwtVcKb(t, config)

	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "different-expected-nonce"

	verifier := NewVerifierVerificationProcessor(true, context)
	_, err := verifier.ParseAndVerifySdJwtVc(sdjwtvc)
	require.ErrorContains(t, err, "nonce")
}

func Test_VerifierVerificationProcessor_KbJwtAudience_MatchesExpectedAudience_Succeeds(t *testing.T) {
	// The KB-JWT `aud` must equal the `client_id` from the OpenID4VP authorization request.
	clientID := "x509_san_dns:client.example.org"

	config := newWorkingSdJwtVcKbTestConfig()
	config.withAudience(clientID)

	sdjwtvc := createTestSdJwtVcKb(t, config)

	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	context.ExpectedAudience = clientID

	verifier := NewVerifierVerificationProcessor(true, context)
	_, err := verifier.ParseAndVerifySdJwtVc(sdjwtvc)
	require.NoError(t, err)
}

func Test_VerifierVerificationProcessor_KbJwtAudience_DoesNotMatchExpectedAudience_Fails(t *testing.T) {
	// The KB-JWT `aud` must equal the `client_id` from the OpenID4VP authorization request.
	config := newWorkingSdJwtVcKbTestConfig()
	config.withAudience("x509_san_dns:client.example.org")

	sdjwtvc := createTestSdJwtVcKb(t, config)

	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	context.ExpectedAudience = "x509_san_dns:different-client.example.org"

	verifier := NewVerifierVerificationProcessor(true, context)
	_, err := verifier.ParseAndVerifySdJwtVc(sdjwtvc)
	require.ErrorContains(t, err, "aud")
}

func Test_VerifierVerificationProcessor_NonRequiredKbJwt_NoKbJwtInSdJwt_Succeeds(t *testing.T) {
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	verifierVerificationProcessor := NewVerifierVerificationProcessor(false, context)
	_, err := verifierVerificationProcessor.ParseAndVerifySdJwtVc(SdJwtVcKb(validSdJwtVc_DcTypHeader_WithoutKbJwt))
	require.NoError(t, err)
}

// ================================= Helpers ===================================

func errorTestCaseHolder(t *testing.T, config *testSdJwtVcConfig, message string) {
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	holderVerifier := NewHolderVerificationProcessor(context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.ErrorContains(t, err, message)
}

func noErrorTestCaseHolder(t *testing.T, config *testSdJwtVcConfig, message string) {
	sdjwtvc := createTestSdJwtVc(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	holderVerifier := NewHolderVerificationProcessor(context)
	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err, message)
}

func errorTestCaseVerifier(t *testing.T, config *testSdJwtVcKbConfig, message string) {
	sdjwtvc := createTestSdJwtVcKb(t, config)
	context := CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	context.ExpectedNonce = "nonce"
	verifierVerificationProcessor := NewVerifierVerificationProcessor(true, context)
	_, err := verifierVerificationProcessor.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.ErrorContains(t, err, message)
}

func runCertChainTestCase(t *testing.T, config x509TestConfig) {
	chain, err := utils.ParsePemCertificateChainToX5cFormat(config.IssuerCert)
	require.NoError(t, err)

	creator := NewEcdsaJwtCreatorWithIssuerTestkey()

	sdjwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_ExpiryTime, time.Now().Unix()),
			Claim(Key_Issuer, config.IssUrl),
			Claim(Key_VerifiableCredentialType, "test.test.email"),
			Claim(Key_SdAlg, iana.SHA256),
			SdClaim("email", "test@gmail.com"),
		).
		WithIssuerCertificateChain(chain).Build(creator)

	require.NoError(t, err)

	verifyOpts, err := utils.CreateX509VerifyOptionsFromCertChain(config.VerifierTrustedIssuerCertChain)
	require.NoError(t, err)

	context := SdJwtVcVerificationContext{
		X509VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: *verifyOpts,
		},
		Clock:       eudi_jwt.NewSystemClock(),
		JwtVerifier: NewJwxJwtVerifier(),
	}

	holderVerifier := NewHolderVerificationProcessor(context)
	_, err = holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwt))

	if config.ShouldFail {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
}
