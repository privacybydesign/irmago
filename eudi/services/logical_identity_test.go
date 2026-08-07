package services

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/stretchr/testify/require"
)

func mustMap(t *testing.T, js string) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(js), &m))
	return m
}

const testIssuer = "https://issuer.example"

// The same logical credential (same issuer, same subject data) as a nested VCDM
// document and as a flat IETF SD-JWT VC must yield the SAME logical id — that is
// the whole point of #686's cross-data-model grouping. Note the two carry a
// different type identifier (VCDM `type` vs SD-JWT VC `vct`) and a differently
// shaped subject (nested `credentialSubject` vs flat), yet group.
func TestLogicalCredentialID_CrossModelEquality(t *testing.T) {
	vcdmDoc := vcdm.Document(mustMap(t, `{
		"@context": ["https://www.w3.org/ns/credentials/v2", "https://eduwallet.nl/context/academic/v1"],
		"type": ["VerifiableCredential", "AcademicBaseCredential"],
		"issuer": "https://issuer.example",
		"validFrom": "2024-01-01T00:00:00Z",
		"credentialSubject": {
			"id": "did:example:holder",
			"eduperson_unique_id": "b2c3@uni.example",
			"schac_home_organization": "uni.example",
			"given_name": "Alice"
		}
	}`))

	sdJwtVc := mustMap(t, `{
		"iss": "https://issuer.example",
		"sub": "did:example:holder",
		"vct": "https://eduwallet.nl/vct/abc",
		"iat": 1700000000,
		"_sd_alg": "sha-256",
		"eduperson_unique_id": "b2c3@uni.example",
		"schac_home_organization": "uni.example",
		"given_name": "Alice"
	}`)

	vcdmID, err := LogicalCredentialID(testIssuer, VcdmContentClaims(vcdmDoc))
	require.NoError(t, err)
	sdJwtVcID, err := LogicalCredentialID(testIssuer, SdJwtVcContentClaims(sdJwtVc))
	require.NoError(t, err)

	require.Equal(t, vcdmID, sdJwtVcID, "same data across data models must group")
}

func TestVcdmContentClaims_StripsSubjectIdAndEnvelope(t *testing.T) {
	doc := vcdm.Document(mustMap(t, `{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"type": ["VerifiableCredential", "AcademicBaseCredential"],
		"issuer": "https://issuer.example",
		"validFrom": "2024-01-01T00:00:00Z",
		"credentialSubject": {"id": "did:example:holder", "given_name": "Alice"}
	}`))
	content := VcdmContentClaims(doc)
	require.Equal(t, map[string]any{"given_name": "Alice"}, content)
}

func TestSdJwtVcContentClaims_StripsStandardClaims(t *testing.T) {
	payload := mustMap(t, `{
		"iss": "https://issuer.example", "sub": "did:example:holder",
		"vct": "https://eduwallet.nl/vct/abc", "iat": 1700000000,
		"_sd_alg": "sha-256", "status": {"status_list": {"idx": 1, "uri": "x"}},
		"given_name": "Alice"
	}`)
	content := SdJwtVcContentClaims(payload)
	require.Equal(t, map[string]any{"given_name": "Alice"}, content)
}

func TestLogicalCredentialID_DiffersOnContent(t *testing.T) {
	base := map[string]any{"eduperson_unique_id": "b2c3@uni.example", "given_name": "Alice"}
	changed := map[string]any{"eduperson_unique_id": "b2c3@uni.example", "given_name": "Bob"}

	baseID, err := LogicalCredentialID(testIssuer, base)
	require.NoError(t, err)
	changedID, err := LogicalCredentialID(testIssuer, changed)
	require.NoError(t, err)
	require.NotEqual(t, baseID, changedID)
}

// Different subjects (distinct scoped unique id) do not group, even with the
// subject identifier stripped — the content claims carry the distinction.
func TestLogicalCredentialID_DiffersOnSubject(t *testing.T) {
	alice := map[string]any{"eduperson_unique_id": "alice@uni.example", "given_name": "A"}
	bob := map[string]any{"eduperson_unique_id": "bob@uni.example", "given_name": "A"}

	aliceID, err := LogicalCredentialID(testIssuer, alice)
	require.NoError(t, err)
	bobID, err := LogicalCredentialID(testIssuer, bob)
	require.NoError(t, err)
	require.NotEqual(t, aliceID, bobID)
}

// The issuer salt keeps identical content from different issuers apart.
func TestLogicalCredentialID_DiffersOnIssuer(t *testing.T) {
	content := map[string]any{"eduperson_unique_id": "b2c3@uni.example", "given_name": "Alice"}

	idA, err := LogicalCredentialID("https://issuer-a.example", content)
	require.NoError(t, err)
	idB, err := LogicalCredentialID("https://issuer-b.example", content)
	require.NoError(t, err)
	require.NotEqual(t, idA, idB)
}
