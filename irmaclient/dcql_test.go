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
	t.Run("satisfiable single credential, single option", testDcqlSatisfiableSingleCredentialSingleOption)
	t.Run("satisfiable single credential, multiple options", testDcqlSatisfiableSingleCredentialMultipleOptions)
	t.Run("unsatisfiable single credential", testDcqlUnsatisfiableSingleCredential)
}

func testDcqlSatisfiableSingleCredentialMultipleOptions(t *testing.T) {
	dcqlQuery := parseQuery(t, `{
		"credentials": [{
			"id": "identifier",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [{ "id": "email-claim-id", "path": ["email"]}]
		}]
	}`)

	storage, err := NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

	sdjwt1, info1 := createSdJwtAndInfo(t, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@email.com"})
	err = storage.StoreCredential(*info1, []sdjwtvc.SdJwtVc{sdjwt1})
	require.NoError(t, err)

	sdjwt2, info2 := createSdJwtAndInfo(t, "pbdf.sidn-pbdf.email", map[string]string{"email": "test2@email.com"})
	err = storage.StoreCredential(*info2, []sdjwtvc.SdJwtVc{sdjwt2})

	candidates, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	requireSameCandidates(t, &queryResult{
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
	},
		candidates,
	)
}

func testDcqlUnsatisfiableSingleCredential(t *testing.T) {
	dcqlQuery := parseQuery(t, `{
		"credentials": [{
			"id": "12345",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["pbdf.sidn-pbdf.email"]},
			"claims": [{"id": "9876", "path": ["email"]}]
		}]
	}`)

	storage, err := NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

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
	dcqlQuery := parseQuery(t, `{
		"credentials": [{
			"id": "12345",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["pbdf.sidn-pbdf.email"]},
			"claims": [{"id": "9876", "path": ["email"]}]
		}]
	}`)

	storage, err := NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

	sdjwt, info := createSdJwtAndInfo(t, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@email.com"})
	err = storage.StoreCredential(*info, []sdjwtvc.SdJwtVc{sdjwt})
	require.NoError(t, err)

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

func parseQuery(t *testing.T, query string) (result dcql.DcqlQuery) {
	require.NoError(t, json.Unmarshal([]byte(query), &result))
	return
}
