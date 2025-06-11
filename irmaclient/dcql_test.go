package irmaclient

import (
	"encoding/json"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDcqlCandidateSelection(t *testing.T) {
	t.Run("satisfiable single credential single option", testDcqlSatisfiableSingleCredentialSingleOption)
	t.Run("satisfiable single credential multiple options", testDcqlSatisfiableSingleCredentialMultipleOptions)
	t.Run("unsatisfiable single credential", testDcqlUnsatisfiableSingleCredential)
	t.Run("satisfiable multiple credentials single option", testDcqlSatisfiableMultipleCredentialsSingleOption)
	t.Run("unsatisfiable multiple credentials single available", testDcqlUnsatisfiableMultipleCredentialsSingleAvailable)
	t.Run("unsatisfiable multiple credentials none available", testDcqlUnSatisfiableMultipleCredentialsNoneAvailable)
	t.Run("satisfiable multiple attributes single credential", testDcqlSatisfiableMultipleAttributesSingleCredential)
	t.Run("multiple attributes single credential partially available", testDcqlMultpleAttributesSingleCredentialPartiallyAvailable)
}

func testDcqlMultpleAttributesSingleCredentialPartiallyAvailable(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [
				{ "id": "456", "path": ["email"]},
				{ "id": "789", "path": ["domain"]}
			]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{
		"email": "test@gmail.com",
	})

	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &queryResult{
		Satisfiable: false,
		Candidates: [][]DisclosureCandidates{
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type: irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							// even though this one is technically satisfiable it doesn't matter if this hash is valid or not
							CredentialHash: "",
						},
					},
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.domain"),
							CredentialHash: "",
						},
					},
				},
			},
		},
	}

	requireSameCandidates(t, expected, result)
}

func testDcqlSatisfiableMultipleAttributesSingleCredential(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [
				{ "id": "456", "path": ["email"]},
				{ "id": "789", "path": ["domain"]}
			]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	info := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})

	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &queryResult{
		Satisfiable: true,
		Candidates: [][]DisclosureCandidates{
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: info.Hash,
						},
					},
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.domain"),
							CredentialHash: info.Hash,
						},
					},
				},
			},
		},
	}

	requireSameCandidates(t, expected, result)
}

func testDcqlUnSatisfiableMultipleCredentialsNoneAvailable(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "456", "path": ["email"]}]
		}, {
			"id": "789",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["pbdf.sidn-pbdf.mobilenumber"]},
			"claims": [{"id": "191112", "path": ["mobilenumber"]}]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()

	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &queryResult{
		Satisfiable: false,
		Candidates: [][]DisclosureCandidates{
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: "",
						},
					},
				},
			},
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.mobilenumber.mobilenumber"),
							CredentialHash: "",
						},
					},
				},
			},
		},
	}

	requireSameCandidates(t, expected, result)

}

func testDcqlUnsatisfiableMultipleCredentialsSingleAvailable(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "456", "path": ["email"]}]
		}, {
			"id": "789",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["pbdf.sidn-pbdf.mobilenumber"]},
			"claims": [{"id": "191112", "path": ["mobilenumber"]}]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	mobileInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.mobilenumber", map[string]string{"mobilenumber": "+31612345678"})

	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &queryResult{
		Satisfiable: false,
		Candidates: [][]DisclosureCandidates{
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: "",
						},
					},
				},
			},
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.mobilenumber.mobilenumber"),
							CredentialHash: mobileInfo.Hash,
						},
					},
				},
			},
		},
	}

	requireSameCandidates(t, expected, result)
}

func testDcqlSatisfiableMultipleCredentialsSingleOption(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "456", "path": ["email"]}]
		}, {
			"id": "789",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["pbdf.sidn-pbdf.mobilenumber"]},
			"claims": [{"id": "191112", "path": ["mobilenumber"]}]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	emailInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "yivi@test.com"})
	mobileInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.mobilenumber", map[string]string{"mobilenumber": "+31612345678"})

	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &queryResult{
		Satisfiable: true,
		Candidates: [][]DisclosureCandidates{
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: emailInfo.Hash,
						},
					},
				},
			},
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.mobilenumber.mobilenumber"),
							CredentialHash: mobileInfo.Hash,
						},
					},
				},
			},
		},
	}

	requireSameCandidates(t, expected, result)
}

func testDcqlSatisfiableSingleCredentialMultipleOptions(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "identifier",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [{ "id": "email-claim-id", "path": ["email"]}]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()

	info1 := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@email.com"})
	info2 := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test2@email.com"})

	candidates, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &queryResult{
		Candidates: [][]DisclosureCandidates{
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: info1.Hash,
						},
					},
				},
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: info2.Hash,
						},
					},
				},
			},
		},
		Satisfiable: true,
	}

	requireSameCandidates(t, expected, candidates)
}

func testDcqlUnsatisfiableSingleCredential(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "12345",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["pbdf.sidn-pbdf.email"]},
			"claims": [{"id": "9876", "path": ["email"]}]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()

	candidates, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &queryResult{
		Candidates: [][]DisclosureCandidates{
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: "",
						},
					},
				},
			},
		},
		Satisfiable: false,
	}
	requireSameCandidates(t, expected, candidates)
}

func testDcqlSatisfiableSingleCredentialSingleOption(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "12345",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["pbdf.sidn-pbdf.email"]},
			"claims": [{"id": "9876", "path": ["email"]}]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	info := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@email.com"})

	candidates, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &queryResult{
		Candidates: [][]DisclosureCandidates{
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: info.Hash,
						},
					},
				},
			},
		},
		Satisfiable: true,
	}

	requireSameCandidates(t, expected, candidates)
}

// ===========================================================================================

func createSdJwtAndInfo(t *testing.T, credentialId string, attributes map[string]string) (sdjwtvc.SdJwtVc, *irma.CredentialInfo) {
	sdjwt, err := createSdJwtVc(credentialId, "https://openid4vc.staging.yivi.app", attributes)
	require.NoError(t, err)

	info, _, err := createCredentialInfoAndVerifiedSdJwtVc(sdjwt, sdjwtvc.CreateDefaultVerificationContext())
	require.NoError(t, err)

	return sdjwt, info
}

func requireSameCandidates(t *testing.T, expected *queryResult, result *queryResult) {
	if expected.Satisfiable != result.Satisfiable {
		t.Fatalf("'Satisfiable' field doesn't match, expected: %v, received: %v", expected.Satisfiable, result.Satisfiable)
	}

	if !assert.ObjectsAreEqualValues(expected.Candidates, result.Candidates) {
		ex, err := json.MarshalIndent(expected.Candidates, "", "    ")
		require.NoError(t, err)
		res, err := json.MarshalIndent(result.Candidates, "", "    ")
		require.NoError(t, err)

		t.Fatalf("expected:\n%s\n\nresult:\n%s\n", ex, res)
	}
}

func parseTestQuery(t *testing.T, query string) (result dcql.DcqlQuery) {
	require.NoError(t, json.Unmarshal([]byte(query), &result))
	return
}

func createAndStoreSdJwt(t *testing.T, storage SdJwtVcStorage, vct string, claims map[string]string) *irma.CredentialInfo {
	sdjwt, info := createSdJwtAndInfo(t, vct, claims)
	err := storage.StoreCredential(*info, []sdjwtvc.SdJwtVc{sdjwt})
	require.NoError(t, err)

	return info
}
