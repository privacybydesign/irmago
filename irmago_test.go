package irmago

import (
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"encoding/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	retCode := m.Run()

	err := os.RemoveAll("testdata/storage/test")
	if err != nil {
		fmt.Println("Could not delete test storage")
		os.Exit(1)
	}

	os.Exit(retCode)
}

type IgnoringKeyshareHandler struct{}

func (i *IgnoringKeyshareHandler) StartKeyshareRegistration(m *SchemeManager, callback func(e, p string)) {
}

func parseMetaStore(t *testing.T) {
	require.NoError(t, MetaStore.ParseFolder("testdata/irma_configuration"), "MetaStore.ParseFolder() failed")
}

func parseStorage(t *testing.T) {
	exists, err := PathExists("testdata/storage/test")
	require.NoError(t, err, "pathexists() failed")
	if !exists {
		require.NoError(t, os.Mkdir("testdata/storage/test", 0755), "Could not create test storage")
	}
	require.NoError(t, Manager.Init("testdata/storage/test", &IgnoringKeyshareHandler{}), "Manager.Init() failed")
}

func teardown(t *testing.T) {
	MetaStore = newConfigurationStore()
	Manager = newCredentialManager()
	assert.NoError(t, os.RemoveAll("testdata/storage/test"))
}

// A convenience function for initializing big integers from known correct (10
// base) strings. Use with care, errors are ignored.
func s2big(s string) (r *big.Int) {
	r, _ = new(big.Int).SetString(s, 10)
	return
}

func parseAndroidStorage(t *testing.T) {
	assert.NoError(t, Manager.ParseAndroidStorage(), "ParseAndroidStorage() failed")
}

func verifyStoreIsUnmarshaled(t *testing.T) {
	cred, err := Manager.credential(NewCredentialTypeIdentifier("irma-demo.RU.studentCard"), 0)
	assert.NoError(t, err, "could not fetch credential")
	assert.NotNil(t, cred, "Credential should exist")
	assert.NotNil(t, cred.Attributes[0], "Metadata attribute of irma-demo.RU.studentCard should not be nil")

	assert.True(t,
		cred.Signature.Verify(cred.PublicKey(), cred.Attributes),
		"Credential should be valid",
	)
}

func verifyPaillierKey(t *testing.T, PrivateKey *paillierPrivateKey) {
	require.NotNil(t, PrivateKey)
	require.NotNil(t, PrivateKey.L)
	require.NotNil(t, PrivateKey.U)
	require.NotNil(t, PrivateKey.PublicKey.N)

	require.Equal(t, big.NewInt(1), new(big.Int).Exp(big.NewInt(2), PrivateKey.L, PrivateKey.N))
	require.Equal(t, PrivateKey.NSquared, new(big.Int).Exp(PrivateKey.N, big.NewInt(2), nil))

	plaintext := "Hello Paillier!"
	ciphertext, err := PrivateKey.Encrypt([]byte(plaintext))
	require.NoError(t, err)
	decrypted, err := PrivateKey.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(decrypted))
}

func verifyKeyshareIsUnmarshaled(t *testing.T) {
	require.NotNil(t, Manager.paillierKeyCache)
	require.NotNil(t, Manager.keyshareServers)
	test := NewSchemeManagerIdentifier("test")
	require.Contains(t, Manager.keyshareServers, test)
	kss := Manager.keyshareServers[test]
	require.NotEmpty(t, kss.Nonce)

	verifyPaillierKey(t, kss.PrivateKey)
	verifyPaillierKey(t, Manager.paillierKeyCache)
}

func TestAndroidParse(t *testing.T) {
	parseMetaStore(t)
	parseStorage(t)
	parseAndroidStorage(t)
	verifyStoreIsUnmarshaled(t)
	verifyKeyshareIsUnmarshaled(t)

	teardown(t)
}

func TestUnmarshaling(t *testing.T) {
	parseMetaStore(t)
	parseStorage(t)
	parseAndroidStorage(t)

	Manager = newCredentialManager()
	err := Manager.Init("testdata/storage/test", nil)
	require.NoError(t, err)

	verifyStoreIsUnmarshaled(t)
	verifyKeyshareIsUnmarshaled(t)

	teardown(t)
}

func TestParseStore(t *testing.T) {
	parseMetaStore(t)

	assert.NotNil(t, MetaStore.Issuers[NewIssuerIdentifier("irma-demo.RU")].CurrentPublicKey().N, "irma-demo.RU public key has no modulus")
	assert.Equal(t,
		"Irma Demo",
		MetaStore.SchemeManagers[NewSchemeManagerIdentifier("irma-demo")].Name["en"],
		"irma-demo scheme manager has unexpected name")
	assert.Equal(t,
		"Radboud Universiteit Nijmegen",
		MetaStore.Issuers[NewIssuerIdentifier("irma-demo.RU")].Name["en"],
		"irma-demo.RU issuer has unexpected name")
	assert.Equal(t,
		"Student Card",
		MetaStore.Credentials[NewCredentialTypeIdentifier("irma-demo.RU.studentCard")].ShortName["en"],
		"irma-demo.RU.studentCard has unexpected name")

	assert.Equal(t,
		"studentID",
		MetaStore.Credentials[NewCredentialTypeIdentifier("irma-demo.RU.studentCard")].Attributes[2].ID,
		"irma-demo.RU.studentCard.studentID has unexpected name")

	// Hash algorithm pseudocode:
	// Base64(SHA256("irma-demo.RU.studentCard")[0:16])
	assert.Contains(t, MetaStore.reverseHashes, "1stqlPad5edpfS1Na1U+DA==",
		"irma-demo.RU.studentCard had improper hash")
	assert.Contains(t, MetaStore.reverseHashes, "CLjnADMBYlFcuGOT7Z0xRg==",
		"irma-demo.MijnOverheid.root had improper hash")

	teardown(t)
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
	parseMetaStore(t)

	// An actual metadata attribute of an IRMA credential extracted from the IRMA app
	attr := MetadataFromInt(s2big("49043481832371145193140299771658227036446546573739245068"))
	assert.NotNil(t, attr.CredentialType(), "attr.CredentialType() should not be nil")

	assert.Equal(t,
		NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		attr.CredentialType().Identifier(),
		"Metadata credential type was not irma-demo.RU.studentCard",
	)
	assert.Equal(t, byte(0x02), attr.Version(), "Unexpected metadata version")
	assert.Equal(t, time.Unix(1499904000, 0), attr.SigningDate(), "Unexpected signing date")
	assert.Equal(t, time.Unix(1516233600, 0), attr.Expiry(), "Unexpected expiry date")
	assert.Equal(t, 2, attr.KeyCounter(), "Unexpected key counter")

	teardown(t)
}

func TestAttributeDisjunctionMarshaling(t *testing.T) {
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

	require.True(t, disjunction.MatchesStore())

	require.False(t, disjunction.Satisfied())
	disjunction.selected = &disjunction.Attributes[0]
	require.True(t, disjunction.Satisfied())
}

func TestCandidates(t *testing.T) {
	parseMetaStore(t)
	parseStorage(t)
	parseAndroidStorage(t)

	attrtype := NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	disjunction := &AttributeDisjunction{
		Attributes: []AttributeTypeIdentifier{attrtype},
	}
	attrs := Manager.Candidates(disjunction)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 1)

	attr := attrs[0]
	require.NotNil(t, attr)
	require.Equal(t, attr.Type, attrtype)

	disjunction = &AttributeDisjunction{
		Attributes: []AttributeTypeIdentifier{attrtype},
		Values:     map[AttributeTypeIdentifier]string{attrtype: "s1234567"},
	}
	attrs = Manager.Candidates(disjunction)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 1)

	disjunction = &AttributeDisjunction{
		Attributes: []AttributeTypeIdentifier{attrtype},
		Values:     map[AttributeTypeIdentifier]string{attrtype: "foobarbaz"},
	}
	attrs = Manager.Candidates(disjunction)
	require.NotNil(t, attrs)
	require.Empty(t, attrs)

	teardown(t)
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
