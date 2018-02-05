package irma

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func parseConfiguration(t *testing.T) *Configuration {
	conf, err := NewConfiguration("testdata/irma_configuration", "")
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())
	return conf
}

// A convenience function for initializing big integers from known correct (10
// base) strings. Use with care, errors are ignored.
func s2big(s string) (r *big.Int) {
	r, _ = new(big.Int).SetString(s, 10)
	return
}

func TestParseInvalidIrmaConfiguration(t *testing.T) {
	// The description.xml of the scheme manager under this folder has been edited
	// to invalidate the scheme manager signature
	conf, err := NewConfiguration("testdata/irma_configuration_invalid", "")
	require.NoError(t, err)

	// Parsing it should return a SchemeManagerError
	err = conf.ParseFolder()
	require.Error(t, err)
	smerr, ok := err.(*SchemeManagerError)
	require.True(t, ok)
	require.Equal(t, SchemeManagerStatusInvalidSignature, smerr.Status)

	// The manager should still be in conf.SchemeManagers, but also in DisabledSchemeManagers
	require.Contains(t, conf.SchemeManagers, smerr.Manager)
	require.Contains(t, conf.DisabledSchemeManagers, smerr.Manager)
	require.Equal(t, SchemeManagerStatusInvalidSignature, conf.SchemeManagers[smerr.Manager].Status)
	require.Equal(t, false, conf.SchemeManagers[smerr.Manager].Valid)
}

func TestParseIrmaConfiguration(t *testing.T) {
	conf := parseConfiguration(t)

	require.Contains(t, conf.SchemeManagers, NewSchemeManagerIdentifier("irma-demo"))
	require.Contains(t, conf.SchemeManagers, NewSchemeManagerIdentifier("test"))

	pk, err := conf.PublicKey(NewIssuerIdentifier("irma-demo.RU"), 0)
	require.NoError(t, err)
	require.NotNil(t, pk)
	require.NotNil(t, pk.N, "irma-demo.RU public key has no modulus")
	require.Equal(t,
		"Irma Demo",
		conf.SchemeManagers[NewSchemeManagerIdentifier("irma-demo")].Name["en"],
		"irma-demo scheme manager has unexpected name")
	require.Equal(t,
		"Radboud University Nijmegen",
		conf.Issuers[NewIssuerIdentifier("irma-demo.RU")].Name["en"],
		"irma-demo.RU issuer has unexpected name")
	require.Equal(t,
		"Student Card",
		conf.CredentialTypes[NewCredentialTypeIdentifier("irma-demo.RU.studentCard")].ShortName["en"],
		"irma-demo.RU.studentCard has unexpected name")

	require.Equal(t,
		"studentID",
		conf.CredentialTypes[NewCredentialTypeIdentifier("irma-demo.RU.studentCard")].Attributes[2].ID,
		"irma-demo.RU.studentCard.studentID has unexpected name")

	// Hash algorithm pseudocode:
	// Base64(SHA256("irma-demo.RU.studentCard")[0:16])
	//require.Contains(t, conf.reverseHashes, "1stqlPad5edpfS1Na1U+DA==",
	//	"irma-demo.RU.studentCard had improper hash")
	//require.Contains(t, conf.reverseHashes, "CLjnADMBYlFcuGOT7Z0xRg==",
	//	"irma-demo.MijnOverheid.root had improper hash")
}

func TestAttributeDisjunctionMarshaling(t *testing.T) {
	conf := parseConfiguration(t)
	disjunction := AttributeDisjunction{}

	var _ json.Unmarshaler = &disjunction
	var _ json.Marshaler = &disjunction

	id := NewAttributeTypeIdentifier("MijnOverheid.ageLower.over18")

	attrsjson := `
	{
		"label": "Over 18",
		"attributes": {
			"MijnOverheid.ageLower.over18": "yes",
			"Thalia.age.over18": "Yes"
		}
	}`
	require.NoError(t, json.Unmarshal([]byte(attrsjson), &disjunction))
	require.True(t, disjunction.HasValues())
	require.Contains(t, disjunction.Attributes, id)
	require.Contains(t, disjunction.Values, id)
	require.Equal(t, disjunction.Values[id], "yes")

	disjunction = AttributeDisjunction{}
	attrsjson = `
	{
		"label": "Over 18",
		"attributes": [
			"MijnOverheid.ageLower.over18",
			"Thalia.age.over18"
		]
	}`
	require.NoError(t, json.Unmarshal([]byte(attrsjson), &disjunction))
	require.False(t, disjunction.HasValues())
	require.Contains(t, disjunction.Attributes, id)

	require.True(t, disjunction.MatchesConfig(conf))

	require.False(t, disjunction.Satisfied())
	disjunction.selected = &disjunction.Attributes[0]
	require.True(t, disjunction.Satisfied())
}

func TestMetadataAttribute(t *testing.T) {
	metadata := NewMetadataAttribute()
	if metadata.Version() != 0x02 {
		t.Errorf("Unexpected metadata version: %d", metadata.Version())
	}

	expiry := metadata.SigningDate().Unix() + int64(metadata.ValidityDuration()*ExpiryFactor)
	if !time.Unix(expiry, 0).Equal(metadata.Expiry()) {
		t.Errorf("Invalid signing date")
	}

	if metadata.KeyCounter() != 0 {
		t.Errorf("Unexpected key counter")
	}
}

func TestMetadataCompatibility(t *testing.T) {
	conf, err := NewConfiguration("testdata/irma_configuration", "")
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())

	// An actual metadata attribute of an IRMA credential extracted from the IRMA app
	attr := MetadataFromInt(s2big("49043481832371145193140299771658227036446546573739245068"), conf)
	require.NotNil(t, attr.CredentialType(), "attr.CredentialType() should not be nil")

	require.Equal(t,
		NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		attr.CredentialType().Identifier(),
		"Metadata credential type was not irma-demo.RU.studentCard",
	)
	require.Equal(t, byte(0x02), attr.Version(), "Unexpected metadata version")
	require.Equal(t, time.Unix(1499904000, 0), attr.SigningDate(), "Unexpected signing date")
	require.Equal(t, time.Unix(1516233600, 0), attr.Expiry(), "Unexpected expiry date")
	require.Equal(t, 2, attr.KeyCounter(), "Unexpected key counter")
}

func TestTimestamp(t *testing.T) {
	mytime := Timestamp(time.Unix(1500000000, 0))
	timestruct := struct{ Time *Timestamp }{Time: &mytime}
	bytes, err := json.Marshal(timestruct)
	require.NoError(t, err)

	timestruct = struct{ Time *Timestamp }{}
	require.NoError(t, json.Unmarshal(bytes, &timestruct))
	require.Equal(t, time.Time(*timestruct.Time).Unix(), int64(1500000000))
}

func TestServiceProvider(t *testing.T) {
	var spjwt ServiceProviderJwt

	var spjson = `{
		"sprequest": {
			"validity": 60,
			"timeout": 60,
			"request": {
				"content": [
					{
						"label": "ID",
						"attributes": ["irma-demo.RU.studentCard.studentID"]
					}
				]
			}
		}
	}`

	require.NoError(t, json.Unmarshal([]byte(spjson), &spjwt))
	require.NotNil(t, spjwt.Request.Request.Content)
	require.NotEmpty(t, spjwt.Request.Request.Content)
	require.NotNil(t, spjwt.Request.Request.Content[0])
	require.NotEmpty(t, spjwt.Request.Request.Content[0])
	require.NotNil(t, spjwt.Request.Request.Content[0].Attributes)
	require.NotEmpty(t, spjwt.Request.Request.Content[0].Attributes)
	require.Equal(t, spjwt.Request.Request.Content[0].Attributes[0].Name(), "studentID")

	require.NotNil(t, spjwt.Request.Request.Content.Find(NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")))
}
