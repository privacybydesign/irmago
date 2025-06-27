package irmaclient

import (
	"encoding/json"
	"slices"
	"strings"
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
	t.Run("satisfiable credential sets all required different purpose", testDcqlSatisfiableClaimSetAllRequiedDifferentPurposes)
	t.Run("satisfiable credential set two options for same purpose", testDcqlSatisfiableTwoOptionsSamePurpose)
	t.Run("satisfiable credential set two options multiple claims single candidate each", testDcqlSatisfiableTwoOptionsMultipleClaims)
	t.Run("satisfiable credential set two options multiple claims multiple candidates", testDcqlSatisfiableTwoOptionsMultipleClaimsMultipleCandidates)

	t.Run("multiple credential queries in option in credential set is unsupported", testDcqlMultipleCredentialQueriesInOptionIsUnsupported)
	t.Run("invalid format in credential query is unsupported", testDcqlInvalidFormatInCredentialQueryIsUnsupported)

	t.Run("single satisfiable expected value for claim", testDcqlSingleSatisfiableExpectedValueForClaim)
	t.Run("single unsatisfiable expected value for claim", testDcqlSingleUnsatisfiableExpectedValueForClaim)
	t.Run("multple value options single claim satisfiable", testDcqlMultipleValueOptionsSingleClaimSatisfiable)
	t.Run("multple value options single claim satisfiable multiple options", testDcqlMultipleValueOptionsSingleClaimSatisfiableMultipleOptions)

	t.Run("claim sets two options one satisfiable", testDcqlClaimSetsTwoOptionsOneSatisfiable)
	t.Run("claim sets two options both satisfiable pick first claim", testDcqlClaimSetsTwoOptionsBothSatisfiablePickFirstClaim)
}

func testDcqlClaimSetsTwoOptionsBothSatisfiablePickFirstClaim(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "em", "path": ["email"], "values": ["hello@gmail.com"]}, {"id": "do", "path": ["domain"], "values": ["gmail.com"]}],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})
	infoGmail := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "hello@gmail.com", "domain": "gmail.com"})

	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &DcqlQueryCandidates{
		Satisfiable: true,
		Candidates: [][]DisclosureCandidates{
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: infoGmail.Hash,
						},
						Value: newTranslatedString("hello@gmail.com"),
					},
				},
			},
		},
	}

	requireSameCandidates(t, expected, result)
}

func testDcqlClaimSetsTwoOptionsOneSatisfiable(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "em", "path": ["email"], "values": ["not@available.com"]}, {"id": "do", "path": ["domain"], "values": ["gmail.com"]}],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})
	infoGmail := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "user@gmail.com", "domain": "gmail.com"})

	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &DcqlQueryCandidates{
		Satisfiable: true,
		Candidates: [][]DisclosureCandidates{
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.domain"),
							CredentialHash: infoGmail.Hash,
						},
						Value: newTranslatedString("gmail.com"),
					},
				},
			},
		},
	}

	requireSameCandidates(t, expected, result)
}

func testDcqlMultipleValueOptionsSingleClaimSatisfiableMultipleOptions(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "456", "path": ["email"]}, {"id": "1111", "path": ["domain"], "values": ["gmail.com", "hotmail.com", "yahoo.com"]}]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	infoHotmail := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})
	infoGmail := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "user@gmail.com", "domain": "gmail.com"})

	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &DcqlQueryCandidates{
		Satisfiable: true,
		Candidates: [][]DisclosureCandidates{
			{
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: infoHotmail.Hash,
						},
					},
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.domain"),
							CredentialHash: infoHotmail.Hash,
						},
						Value: newTranslatedString("hotmail.com"),
					},
				},
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: infoGmail.Hash,
						},
					},
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.domain"),
							CredentialHash: infoGmail.Hash,
						},
						Value: newTranslatedString("gmail.com"),
					},
				},
			},
		},
	}

	requireSameCandidates(t, expected, result)
}

func testDcqlMultipleValueOptionsSingleClaimSatisfiable(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "456", "path": ["email"]}, {"id": "1111", "path": ["domain"], "values": ["gmail.com", "hotmail.com", "yahoo.com"]}]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	info := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})
	createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "user@live.com", "domain": "live.com"})

	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &DcqlQueryCandidates{
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
						Value: newTranslatedString("hotmail.com"),
					},
				},
			},
		},
	}

	requireSameCandidates(t, expected, result)
}

func testDcqlSingleUnsatisfiableExpectedValueForClaim(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "456", "path": ["email"]}, {"id": "1111", "path": ["domain"], "values": ["gmail.com"]}]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})
	createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "user@live.com", "domain": "live.com"})

	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &DcqlQueryCandidates{
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

func testDcqlSingleSatisfiableExpectedValueForClaim(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "456", "path": ["email"]}, {"id": "1111", "path": ["domain"], "values": ["gmail.com"]}]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	emailInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@gmail.com", "domain": "gmail.com"})
	createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})

	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expectedValue := "gmail.com"
	expected := &DcqlQueryCandidates{
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
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.domain"),
							CredentialHash: emailInfo.Hash,
						},
						Value: irma.NewTranslatedString(&expectedValue),
					},
				},
			},
		},
	}

	requireSameCandidates(t, expected, result)
}

func testDcqlInvalidFormatInCredentialQueryIsUnsupported(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "idemix",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "em", "path": ["email"]}, {"id": "do", "path": ["domain"]}]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	_, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.Error(t, err)
}

func testDcqlMultipleCredentialQueriesInOptionIsUnsupported(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "456", "path": ["email"]}, {"id": "1111", "path": ["domain"]}]
		}, {
			"id": "phone",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["pbdf.sidn-pbdf.mobilenumber"]},
			"claims": [{"id": "191112", "path": ["mobilenumber"]}]
		}],
		"credential_sets": [{
			"options": [["email", "phone"]]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	_, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.Error(t, err)
}

func testDcqlSatisfiableTwoOptionsMultipleClaimsMultipleCandidates(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "456", "path": ["email"]}, {"id": "1111", "path": ["domain"]}]
		}, {
			"id": "phone",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["pbdf.sidn-pbdf.mobilenumber"]},
			"claims": [{"id": "191112", "path": ["mobilenumber"]}]
		}],
		"credential_sets": [{
			"options": [["email"], ["phone"]]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	emailInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@gmail.com", "domain": "gmail.com"})
	emailInfo2 := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "contact@yivi.app", "domain": "yivi.app"})
	mobileInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.mobilenumber", map[string]string{"mobilenumber": "+1234567"})
	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &DcqlQueryCandidates{
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
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.domain"),
							CredentialHash: emailInfo.Hash,
						},
					},
				},
				{
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
							CredentialHash: emailInfo2.Hash,
						},
					},
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.domain"),
							CredentialHash: emailInfo2.Hash,
						},
					},
				},
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

func testDcqlSatisfiableTwoOptionsMultipleClaims(t *testing.T) {
	dcqlQuery := parseTestQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["pbdf.sidn-pbdf.email"] },
			"claims": [ {"id": "456", "path": ["email"]}, {"id": "1111", "path": ["domain"]}]
		}, {
			"id": "phone",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["pbdf.sidn-pbdf.mobilenumber"]},
			"claims": [{"id": "191112", "path": ["mobilenumber"]}]
		}],
		"credential_sets": [{
			"options": [["email"], ["phone"]]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	emailInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@gmail.com", "domain": "gmail.com"})
	mobileInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.mobilenumber", map[string]string{"mobilenumber": "+1234567"})
	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &DcqlQueryCandidates{
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
					{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.domain"),
							CredentialHash: emailInfo.Hash,
						},
					},
				},
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

func testDcqlSatisfiableTwoOptionsSamePurpose(t *testing.T) {
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
		}],
		"credential_sets": [{
			"options": [["123"], ["789"]]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	emailInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@gmail.com"})
	mobileInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.mobilenumber", map[string]string{"mobilenumber": "+1234567"})
	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &DcqlQueryCandidates{
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

func testDcqlSatisfiableClaimSetAllRequiedDifferentPurposes(t *testing.T) {
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
		}],
		"credential_sets": [{
			"options": [["123"]]
		}, {
			"options": [["789"]]
		}]
	}`)

	storage, _ := NewInMemorySdJwtVcStorage()
	emailInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.email", map[string]string{"email": "test@gmail.com"})
	mobileInfo := createAndStoreSdJwt(t, storage, "pbdf.sidn-pbdf.mobilenumber", map[string]string{"mobilenumber": "+1234567"})
	result, err := getCandidatesForDcqlQuery(storage, dcqlQuery)
	require.NoError(t, err)

	expected := &DcqlQueryCandidates{
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

	expected := &DcqlQueryCandidates{
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

	expected := &DcqlQueryCandidates{
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

	expected := &DcqlQueryCandidates{
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

	expected := &DcqlQueryCandidates{
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

	expected := &DcqlQueryCandidates{
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

	expected := &DcqlQueryCandidates{
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

	expected := &DcqlQueryCandidates{
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

	expected := &DcqlQueryCandidates{
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

func createSdJwtAndInfo(t *testing.T, keyBinder sdjwtvc.KeyBinder, credentialId string, attributes map[string]string) (sdjwtvc.SdJwtVc, *irma.CredentialInfo) {
	sdjwt, err := createTestSdJwtVc(keyBinder, credentialId, "https://openid4vc.staging.yivi.app", attributes)
	require.NoError(t, err)

	info, _, err := createCredentialInfoAndVerifiedSdJwtVc(sdjwt, sdjwtvc.CreateDefaultVerificationContext())
	require.NoError(t, err)

	return sdjwt, info
}

func sortCon(con DisclosureCandidates) DisclosureCandidates {
	slices.SortStableFunc(con, func(a, b *DisclosureCandidate) int {
		return strings.Compare(a.AttributeIdentifier.Type.String(), b.AttributeIdentifier.Type.String())
	})
	return con
}

func sortDisCon(disCon []DisclosureCandidates) []DisclosureCandidates {
	for i := range disCon {
		disCon[i] = sortCon(disCon[i])
	}
	slices.SortStableFunc(disCon, func(a, b DisclosureCandidates) int {
		if len(a) != 0 && len(b) != 0 {
			return strings.Compare(a[0].CredentialHash, b[0].CredentialHash)
		}
		return len(a) - len(b)
	})
	return disCon
}

func sortConDisCon(condiscon [][]DisclosureCandidates) [][]DisclosureCandidates {
	for i := range condiscon {
		condiscon[i] = sortDisCon(condiscon[i])
	}
	slices.SortStableFunc(condiscon, func(a, b []DisclosureCandidates) int {
		return len(a) - len(b)
	})
	return condiscon
}

func sortCandidates(candidates *DcqlQueryCandidates) *DcqlQueryCandidates {
	candidates.Candidates = sortConDisCon(candidates.Candidates)
	return candidates
}

func requireSameCandidates(t *testing.T, expected *DcqlQueryCandidates, result *DcqlQueryCandidates) {
	if expected.Satisfiable != result.Satisfiable {
		t.Fatalf("'Satisfiable' field doesn't match, expected: %v, received: %v", expected.Satisfiable, result.Satisfiable)
	}

	expected = sortCandidates(expected)
	result = sortCandidates(result)

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
	keyBinder := sdjwtvc.NewDefaultKeyBinder()
	sdjwt, info := createSdJwtAndInfo(t, keyBinder, vct, claims)
	err := storage.StoreCredential(*info, []sdjwtvc.SdJwtVc{sdjwt})
	require.NoError(t, err)

	return info
}

func newTranslatedString(value string) irma.TranslatedString {
	return irma.NewTranslatedString(&value)
}
