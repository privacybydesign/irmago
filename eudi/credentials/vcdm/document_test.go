package vcdm

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// docFromJSON decodes a JSON credential the way a securing layer hands it to
// this package: strings, []any and map[string]any, never Go-native []string.
func docFromJSON(t *testing.T, js string) Document {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(js), &m))
	return Document(m)
}

// A canonical VCDM 2.0 example credential (adapted from the W3C REC examples):
// multi-entry `@context`, array `type`, string `issuer`, nested
// `credentialSubject`, `validFrom`.
const exampleAlumniCredential = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "http://university.example/credentials/1872",
  "type": ["VerifiableCredential", "ExampleAlumniCredential"],
  "issuer": "https://university.example/issuers/565049",
  "validFrom": "2010-01-01T19:23:24Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "alumniOf": {
      "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
      "name": "Example University"
    }
  }
}`

// A VCDM 2.0 credential with an object `issuer`, a validity window, and a
// typed `credentialStatus` extension point (BitstringStatusList).
const exampleStatusCredential = `{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential"],
  "issuer": {"id": "https://issuer.example", "name": "Example Issuer"},
  "validFrom": "2020-01-01T00:00:00Z",
  "validUntil": "2030-01-01T00:00:00Z",
  "credentialSubject": {"id": "did:example:1"},
  "credentialStatus": {
    "id": "https://issuer.example/status/1#7",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "7",
    "statusListCredential": "https://issuer.example/status/1"
  }
}`

func TestValidate_ConformingDocuments(t *testing.T) {
	require.NoError(t, docFromJSON(t, exampleAlumniCredential).Validate())
	require.NoError(t, docFromJSON(t, exampleStatusCredential).Validate())
}

func TestValidate_Rejections(t *testing.T) {
	cases := map[string]string{
		"missing @context": `{
			"type": ["VerifiableCredential"], "issuer": "https://i.example",
			"credentialSubject": {"id": "did:example:1"}}`,
		"@context not an array": `{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type": ["VerifiableCredential"], "issuer": "https://i.example",
			"credentialSubject": {"id": "did:example:1"}}`,
		"wrong base @context": `{
			"@context": ["https://www.w3.org/2018/credentials/v1"],
			"type": ["VerifiableCredential"], "issuer": "https://i.example",
			"credentialSubject": {"id": "did:example:1"}}`,
		"base @context not first": `{
			"@context": ["https://example.com/ctx", "https://www.w3.org/ns/credentials/v2"],
			"type": ["VerifiableCredential"], "issuer": "https://i.example",
			"credentialSubject": {"id": "did:example:1"}}`,
		"missing type": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"issuer": "https://i.example", "credentialSubject": {"id": "did:example:1"}}`,
		"type omits VerifiableCredential": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"type": ["ExampleCredential"], "issuer": "https://i.example",
			"credentialSubject": {"id": "did:example:1"}}`,
		"missing issuer": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"type": ["VerifiableCredential"], "credentialSubject": {"id": "did:example:1"}}`,
		"empty issuer string": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"type": ["VerifiableCredential"], "issuer": "",
			"credentialSubject": {"id": "did:example:1"}}`,
		"issuer object without id": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"type": ["VerifiableCredential"], "issuer": {"name": "no id"},
			"credentialSubject": {"id": "did:example:1"}}`,
		"missing credentialSubject": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"type": ["VerifiableCredential"], "issuer": "https://i.example"}`,
		"credentialSubject is a bare string": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"type": ["VerifiableCredential"], "issuer": "https://i.example",
			"credentialSubject": "did:example:1"}`,
		"credentialSubject empty array": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"type": ["VerifiableCredential"], "issuer": "https://i.example",
			"credentialSubject": []}`,
		"malformed validFrom": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"type": ["VerifiableCredential"], "issuer": "https://i.example",
			"credentialSubject": {"id": "did:example:1"}, "validFrom": "yesterday"}`,
		"validFrom without timezone": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"type": ["VerifiableCredential"], "issuer": "https://i.example",
			"credentialSubject": {"id": "did:example:1"}, "validFrom": "2020-01-01T00:00:00"}`,
		"validUntil before validFrom": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"type": ["VerifiableCredential"], "issuer": "https://i.example",
			"credentialSubject": {"id": "did:example:1"},
			"validFrom": "2030-01-01T00:00:00Z", "validUntil": "2020-01-01T00:00:00Z"}`,
		"credentialStatus without type": `{
			"@context": ["https://www.w3.org/ns/credentials/v2"],
			"type": ["VerifiableCredential"], "issuer": "https://i.example",
			"credentialSubject": {"id": "did:example:1"},
			"credentialStatus": {"id": "https://issuer.example/status/1#7"}}`,
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			err := docFromJSON(t, js).Validate()
			require.Error(t, err)
			require.ErrorIs(t, err, ErrMalformed)
		})
	}
}

func TestAccessors(t *testing.T) {
	doc := docFromJSON(t, exampleAlumniCredential)

	ctx, ok := doc.PrimaryContext()
	require.True(t, ok)
	require.Equal(t, ContextV2, ctx)

	require.ElementsMatch(t, []string{"VerifiableCredential", "ExampleAlumniCredential"}, doc.Types())
	require.True(t, doc.HasType(TypeVerifiableCredential))
	require.False(t, doc.HasType("NopeCredential"))

	iss, err := doc.IssuerID()
	require.NoError(t, err)
	require.Equal(t, "https://university.example/issuers/565049", iss)

	id, ok := doc.ID()
	require.True(t, ok)
	require.Equal(t, "http://university.example/credentials/1872", id)

	subs, err := doc.CredentialSubjects()
	require.NoError(t, err)
	require.Len(t, subs, 1)
	require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subs[0]["id"])

	vf, ok, err := doc.ValidFrom()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 2010, vf.Year())
}

func TestIssuerObjectForm(t *testing.T) {
	iss, err := docFromJSON(t, exampleStatusCredential).IssuerID()
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example", iss)
}

func TestCredentialSubjectArrayForm(t *testing.T) {
	doc := docFromJSON(t, `{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"type": ["VerifiableCredential"], "issuer": "https://i.example",
		"credentialSubject": [{"id": "did:example:1"}, {"id": "did:example:2"}]}`)
	require.NoError(t, doc.Validate())
	subs, err := doc.CredentialSubjects()
	require.NoError(t, err)
	require.Len(t, subs, 2)
}

func TestVerifyValidityPeriod(t *testing.T) {
	doc := docFromJSON(t, exampleStatusCredential) // validFrom 2020, validUntil 2030
	skew := 180 * time.Second

	within := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, doc.VerifyValidityPeriod(within, skew))

	tooEarly := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	require.Error(t, doc.VerifyValidityPeriod(tooEarly, skew))

	tooLate := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	require.Error(t, doc.VerifyValidityPeriod(tooLate, skew))
}
