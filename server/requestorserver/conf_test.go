package requestorserver

import (
	"encoding/json"
	"testing"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/require"
)

func createCredentialRequest(identifier string, attributes map[string]string) []*irma.CredentialRequest {
	expiry := irma.Timestamp(irma.FloorToEpochBoundary(time.Now().AddDate(1, 0, 0)))

	return []*irma.CredentialRequest{
		{
			Validity:         &expiry,
			CredentialTypeID: irma.NewCredentialTypeIdentifier(identifier),
			Attributes:       attributes,
		},
	}
}

func TestCanIssue(t *testing.T) {
	confJSON := `{
		"requestors": {
			"myapp": {
				"disclose_perms": [ "irma-demo.MijnOverheid.ageLower.over18" ],
				"sign_perms": [ "irma-demo.MijnOverheid.ageLower.*" ],
				"issue_perms": [ "irma-demo.MijnOverheid.ageLower" ],
				"auth_method": "token",
				"key": "eGE2PSomOT84amVVdTU"
			}
		}
	}`

	t.Run("allowed credential request", func(t *testing.T) {
		var conf Configuration
		require.NoError(t, json.Unmarshal([]byte(confJSON), &conf))

		credentialRequest := createCredentialRequest("irma-demo.MijnOverheid.ageLower", map[string]string{"over12": "yes"})
		result, message := conf.CanIssue("myapp", credentialRequest)

		require.True(t, result)
		require.Empty(t, message)
	})

	t.Run("allowed credential request different attribute value", func(t *testing.T) {
		var conf Configuration
		require.NoError(t, json.Unmarshal([]byte(confJSON), &conf))

		credentialRequest := createCredentialRequest("irma-demo.MijnOverheid.ageLower", map[string]string{"over16": "no"})
		result, message := conf.CanIssue("myapp", credentialRequest)

		require.True(t, result)
		require.Empty(t, message)
	})

	t.Run("allowed credential request wrong requestor id", func(t *testing.T) {
		var conf Configuration
		require.NoError(t, json.Unmarshal([]byte(confJSON), &conf))

		credentialRequest := createCredentialRequest("irma-demo.MijnOverheid.ageLower", map[string]string{"over12": "yes"})
		result, message := conf.CanIssue("yourapp", credentialRequest)

		require.False(t, result)
		require.Empty(t, message)
	})

	t.Run("allowed credential request wrong credential identifier", func(t *testing.T) {
		var conf Configuration
		require.NoError(t, json.Unmarshal([]byte(confJSON), &conf))

		credentialRequest := createCredentialRequest("irma-demo.MijnOverheid.ageUpper", map[string]string{"over12": "yes"})
		result, message := conf.CanIssue("myapp", credentialRequest)

		require.False(t, result)
		require.Equal(t, "irma-demo.MijnOverheid.ageUpper", message)
	})

	t.Run("allowed credential request attribute wildcard", func(t *testing.T) {
		var conf Configuration
		require.NoError(t, json.Unmarshal([]byte(confJSON), &conf))

		conf.Requestors["myapp"].Issuing[0] = "irma-demo.MijnOverheid.*"

		credentialRequest := createCredentialRequest("irma-demo.MijnOverheid.ageLower", map[string]string{"over12": "yes"})
		result, message := conf.CanIssue("myapp", credentialRequest)

		require.True(t, result)
		require.Empty(t, message)
	})

	t.Run("allowed credential request issuer wildcard", func(t *testing.T) {
		var conf Configuration
		require.NoError(t, json.Unmarshal([]byte(confJSON), &conf))

		conf.Requestors["myapp"].Issuing[0] = "irma-demo.*"

		credentialRequest := createCredentialRequest("irma-demo.MijnOverheid.ageLower", map[string]string{"over12": "yes"})
		result, message := conf.CanIssue("myapp", credentialRequest)

		require.True(t, result)
		require.Empty(t, message)
	})

	t.Run("allowed credential request single wildcard", func(t *testing.T) {
		var conf Configuration
		require.NoError(t, json.Unmarshal([]byte(confJSON), &conf))

		conf.Requestors["myapp"].Issuing[0] = "*"

		credentialRequest := createCredentialRequest("irma-demo.MijnOverheid.ageLower", map[string]string{"over12": "yes"})
		result, message := conf.CanIssue("myapp", credentialRequest)

		require.True(t, result)
		require.Empty(t, message)
	})
}

func createAttributesConDisCon(identifier string) irma.AttributeConDisCon {
	return irma.AttributeConDisCon{
		{{irma.NewAttributeRequest(identifier)}},
	}
}

func TestCanVerifyOrSign(t *testing.T) {
	confJSON := `{
		"requestors": {
			"myapp": {
				"disclose_perms": [ "irma-demo.MijnOverheid.ageLower.over18" ],
				"sign_perms": [ "irma-demo.MijnOverheid.ageLower.over18" ],
				"issue_perms": [ "irma-demo.MijnOverheid.ageLower" ],
				"auth_method": "token",
				"key": "eGE2PSomOT84amVVdTU"
			}
		}
	}`

	var disclosingCases = []struct {
		description        string
		attributeConDisCon string
		disclosePerm       string
		requestorName      string
		result             bool
		message            string
	}{
		{
			"allowed disclosing request",
			"irma-demo.MijnOverheid.ageLower.over18",
			"irma-demo.MijnOverheid.ageLower.over18",
			"myapp",
			true,
			"",
		},
		{
			"allowed disclosing request incorrect requestor",
			"irma-demo.MijnOverheid.ageLower.over18",
			"irma-demo.MijnOverheid.ageLower.over18",
			"yourapp",
			false,
			"",
		},
		{
			"allowed disclosing request incorrect attribute",
			"irma-demo.MijnOverheid.ageLower.over16",
			"irma-demo.MijnOverheid.ageLower.over18",
			"myapp",
			false,
			"irma-demo.MijnOverheid.ageLower.over16",
		},
		{
			"allowed disclosing single wildcard",
			"irma-demo.MijnOverheid.ageLower.over18",
			"*",
			"myapp",
			true,
			"",
		},
		{
			"allowed disclosing request correct issuer wildcard",
			"irma-demo.MijnOverheid.ageLower.over18",
			"irma-demo.*",
			"myapp",
			true,
			"",
		},
		{
			"allowed disclosing request correct attribute wildcard",
			"irma-demo.MijnOverheid.ageLower.over18",
			"irma-demo.MijnOverheid.*",
			"myapp",
			true,
			"",
		},
		{
			"allowed disclosing request correct attribute value wildcard",
			"irma-demo.MijnOverheid.ageLower.over18",
			"irma-demo.MijnOverheid.ageLower.*",
			"myapp",
			true,
			"",
		},
	}

	for _, action := range []string{"disclosing", "signing"} {
		for _, val := range disclosingCases {
			t.Run(val.description, func(t *testing.T) {
				var conf Configuration
				require.NoError(t, json.Unmarshal([]byte(confJSON), &conf))
				conf.Requestors["myapp"].Disclosing[0] = val.disclosePerm
				conf.Requestors["myapp"].Signing[0] = val.disclosePerm
				requestedAttributes := createAttributesConDisCon(val.attributeConDisCon)
				result, message := conf.CanVerifyOrSign(val.requestorName, irma.Action(action), requestedAttributes)

				require.Equal(t, val.result, result)
				require.Equal(t, val.message, message)
			})
		}
	}
}
