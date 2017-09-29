package irmago

import (
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"encoding/json"

	"github.com/mhe/gabi"
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

func (i *IgnoringKeyshareHandler) StartRegistration(m *SchemeManager, callback func(e, p string)) {
}

func parseStorage(t *testing.T) {
	exists, err := PathExists("testdata/storage/test")
	require.NoError(t, err, "pathexists() failed")
	if !exists {
		require.NoError(t, os.Mkdir("testdata/storage/test", 0755), "Could not create test storage")
	}
	require.NoError(t, Manager.Init(
		"testdata/storage/test",
		"testdata/irma_configuration",
		&IgnoringKeyshareHandler{},
	), "Manager.Init() failed")
}

func teardown(t *testing.T) {
	MetaStore = newConfigurationStore()
	Manager = newCredentialManager()
	assert.NoError(t, os.RemoveAll("testdata/storage/test"))
	// TODO first RemoveAll?!
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

func verifyManagerIsUnmarshaled(t *testing.T) {
	cred, err := Manager.credential(NewCredentialTypeIdentifier("irma-demo.RU.studentCard"), 0)
	assert.NoError(t, err, "could not fetch credential")
	assert.NotNil(t, cred, "Credential should exist")
	assert.NotNil(t, cred.Attributes[0], "Metadata attribute of irma-demo.RU.studentCard should not be nil")

	cred, err = Manager.credential(NewCredentialTypeIdentifier("test.test.mijnirma"), 0)
	assert.NoError(t, err, "could not fetch credential")
	assert.NotNil(t, cred, "Credential should exist")
	assert.NotNil(t, cred.Signature.KeyshareP)

	assert.NotEmpty(t, Manager.CredentialInfoList())

	assert.True(t,
		cred.Signature.Verify(cred.PublicKey(), cred.Attributes),
		"Credential should be valid",
	)
}

func verifyCredentials(t *testing.T) {
	for credtype, credsmap := range Manager.credentials {
		for index, cred := range credsmap {
			require.True(t,
				cred.Credential.Signature.Verify(cred.PublicKey(), cred.Attributes),
				"Credential %s-%d was invalid", credtype.String(), index,
			)
			require.Equal(t, cred.Attributes[0], Manager.secretkey,
				"Secret key of credential %s-%d unequal to main secret key")
		}
	}
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

func verifyStoreIsLoaded(t *testing.T) {
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
}

func TestAndroidParse(t *testing.T) {
	parseStorage(t)
	verifyStoreIsLoaded(t)

	parseAndroidStorage(t)
	verifyManagerIsUnmarshaled(t)
	verifyCredentials(t)
	verifyKeyshareIsUnmarshaled(t)

	teardown(t)
}

func TestUnmarshaling(t *testing.T) {
	parseStorage(t)
	parseAndroidStorage(t)

	Manager = newCredentialManager()
	err := Manager.Init("testdata/storage/test", "testdata/irma_configuration", nil)
	require.NoError(t, err)

	verifyManagerIsUnmarshaled(t)
	verifyCredentials(t)
	verifyKeyshareIsUnmarshaled(t)

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
	require.NoError(t, MetaStore.ParseFolder("testdata/irma_configuration"))

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
		Values:     map[AttributeTypeIdentifier]string{attrtype: "456"},
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

func TestTransport(t *testing.T) {
	transport := NewHTTPTransport("https://xkcd.com")
	obj := &struct {
		Num   int    `json:"num"`
		Img   string `json:"img"`
		Title string `json:"title"`
	}{}

	err := transport.Get("614/info.0.json", obj)
	if err != nil { // require.NoError() does not work because of the type of err
		t.Fatalf("%+v\n", err)
	}
}

func TestPaillier(t *testing.T) {
	parseStorage(t)
	parseAndroidStorage(t)

	challenge, _ := gabi.RandomBigInt(256)
	comm, _ := gabi.RandomBigInt(1000)
	resp, _ := gabi.RandomBigInt(1000)

	sk := Manager.paillierKey(true)
	bytes, err := sk.Encrypt(challenge.Bytes())
	require.NoError(t, err)
	cipher := new(big.Int).SetBytes(bytes)

	bytes, err = sk.Encrypt(comm.Bytes())
	require.NoError(t, err)
	commcipher := new(big.Int).SetBytes(bytes)

	// [[ c ]]^resp * [[ comm ]]
	cipher.Exp(cipher, resp, sk.NSquared).Mul(cipher, commcipher).Mod(cipher, sk.NSquared)

	bytes, err = sk.Decrypt(cipher.Bytes())
	require.NoError(t, err)
	plaintext := new(big.Int).SetBytes(bytes)
	expected := new(big.Int).Set(challenge)
	expected.Mul(expected, resp).Add(expected, comm)

	require.Equal(t, plaintext, expected)

	teardown(t)
}
