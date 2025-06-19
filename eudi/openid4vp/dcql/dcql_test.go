package dcql

import (
	"encoding/json"
	"testing"
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

	if err != nil {
		t.Fatalf("failed to parse valid dcql query")
	}

	if len(dcqlQuery.Credentials) != 1 {
		t.Fatalf("credentials in dcql query not parsed correctly")
	}
	if len(dcqlQuery.Credentials[0].Claims) != 1 {
		t.Fatalf("credential claim not parsed correctly")
	}
}

func parseDcqlQuery(query string) (DcqlQuery, error) {
	var q DcqlQuery
	err := json.Unmarshal([]byte(query), &q)
	if err != nil {
		return DcqlQuery{}, nil
	}
	return q, nil
}
