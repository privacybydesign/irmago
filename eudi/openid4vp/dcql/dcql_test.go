package dcql

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseValidDcqlQuery(t *testing.T) {
	queryJson := `{
		  "credential_sets": [
			{
			  "options": [
				[
				  "32f54163-7166-48f1-93d8-ff217bdb0653"
				]
			  ],
			  "purpose": "We need to verify your identity"
			}
		  ],
		  "credentials": [
			{
			  "claims": [
				{
				  "claim_name": "family_name",
				  "namespace": "eu.europa.ec.eudi.pid.1"
				}
			  ],
			  "format": "dc+sd-jwt",
			  "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
			  "meta": {
				"doctype_value": "eu.europa.ec.eudi.pid.1"
			  }
			}
		  ]
		}`

	dcqlQuery, err := parseDcqlQuery(queryJson)

	require.NoError(t, err)
	require.Len(t, dcqlQuery.Credentials, 1)
	require.Len(t, dcqlQuery.Credentials[0].Claims, 1)
}

func parseDcqlQuery(query string) (DcqlQuery, error) {
	var q DcqlQuery
	err := json.Unmarshal([]byte(query), &q)
	if err != nil {
		return DcqlQuery{}, nil
	}
	return q, nil
}

func TestGetAllClaimPathsShouldReturnAllPathsFromCredentialQuery(t *testing.T) {
	// Arrange
	cq := CredentialQuery{
		Claims: []Claim{
			{
				Id: "1",
				Path: []string{
					"email",
					"domain",
				},
			},
			{
				Id: "2",
				Path: []string{
					"location",
					"country",
				},
			},
		},
	}
	// Act
	paths := slices.Collect(cq.AllClaimPaths())

	// Assert
	require.Len(t, paths, 4)
	require.Equal(t, "email", paths[0])
	require.Equal(t, "domain", paths[1])
	require.Equal(t, "location", paths[2])
	require.Equal(t, "country", paths[3])
}
