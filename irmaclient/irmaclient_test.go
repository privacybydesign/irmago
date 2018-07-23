package irmaclient

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Create HTTP server for scheme managers
	test.StartSchemeManagerHttpServer()

	test.ClearTestStorage(nil)
	test.CreateTestStorage(nil)
	retCode := m.Run()
	test.ClearTestStorage(nil)

	test.StopSchemeManagerHttpServer()
	os.Exit(retCode)
}

type TestClientHandler struct {
	t *testing.T
	c chan error
}

func (i *TestClientHandler) UpdateConfiguration(new *irma.IrmaIdentifierSet) {}
func (i *TestClientHandler) UpdateAttributes()                               {}
func (i *TestClientHandler) EnrollmentSuccess(manager irma.SchemeManagerIdentifier) {
	select {
	case i.c <- nil: // nop
	default: // nop
	}
}
func (i *TestClientHandler) EnrollmentFailure(manager irma.SchemeManagerIdentifier, err error) {
	select {
	case i.c <- err: // nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ChangePinSuccess(manager irma.SchemeManagerIdentifier) {
	select {
	case i.c <- nil: // nop
	default: // nop
	}
}
func (i *TestClientHandler) ChangePinFailure(manager irma.SchemeManagerIdentifier, err error) {
	select {
	case i.c <- err: //nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ChangePinIncorrect(manager irma.SchemeManagerIdentifier, attempts int) {
	err := errors.New("incorrect pin")
	select {
	case i.c <- err: //nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ChangePinBlocked(manager irma.SchemeManagerIdentifier, timeout int) {
	err := errors.New("blocked account")
	select {
	case i.c <- err: //nop
	default:
		i.t.Fatal(err)
	}
}

func parseStorage(t *testing.T) *Client {
	require.NoError(t, fs.CopyDirectory("../testdata/teststorage", "../testdata/storage/test"))
	manager, err := New(
		"../testdata/storage/test",
		"../testdata/irma_configuration",
		"",
		&TestClientHandler{t: t},
	)
	require.NoError(t, err)
	return manager
}

func verifyClientIsUnmarshaled(t *testing.T, client *Client) {
	cred, err := client.credential(irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"), 0)
	require.NoError(t, err, "could not fetch credential")
	require.NotNil(t, cred, "Credential should exist")
	require.NotNil(t, cred.Attributes[0], "Metadata attribute of irma-demo.RU.studentCard should not be nil")

	cred, err = client.credential(irma.NewCredentialTypeIdentifier("test.test.mijnirma"), 0)
	require.NoError(t, err, "could not fetch credential")
	require.NotNil(t, cred, "Credential should exist")
	require.NotNil(t, cred.Signature.KeyshareP)

	require.NotEmpty(t, client.CredentialInfoList())

	pk, err := cred.PublicKey()
	require.NoError(t, err)
	require.True(t,
		cred.Signature.Verify(pk, cred.Attributes),
		"Credential should be valid",
	)
}

func verifyCredentials(t *testing.T, client *Client) {
	var pk *gabi.PublicKey
	for credtype, credsmap := range client.attributes {
		for index, attrs := range credsmap {
			cred, err := client.credential(attrs.CredentialType().Identifier(), index)
			require.NoError(t, err)
			pk, err = cred.PublicKey()
			require.NoError(t, err)
			require.True(t,
				cred.Credential.Signature.Verify(pk, cred.Attributes),
				"Credential %s-%d was invalid", credtype.String(), index,
			)
			require.Equal(t, cred.Attributes[0], client.secretkey.Key,
				"Secret key of credential %s-%d unequal to main secret key",
				cred.CredentialType().Identifier().String(), index,
			)
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

func verifyKeyshareIsUnmarshaled(t *testing.T, client *Client) {
	require.NotNil(t, client.paillierKeyCache)
	require.NotNil(t, client.keyshareServers)
	testManager := irma.NewSchemeManagerIdentifier("test")
	require.Contains(t, client.keyshareServers, testManager)
	kss := client.keyshareServers[testManager]
	require.NotEmpty(t, kss.Nonce)

	verifyPaillierKey(t, kss.PrivateKey)
	verifyPaillierKey(t, client.paillierKeyCache)
}

func TestStorageDeserialization(t *testing.T) {
	client := parseStorage(t)
	verifyClientIsUnmarshaled(t, client)
	verifyCredentials(t, client)
	verifyKeyshareIsUnmarshaled(t, client)

	test.ClearTestStorage(t)
}

func TestLogging(t *testing.T) {
	client := parseStorage(t)

	logs, err := client.Logs()
	oldLogLength := len(logs)
	require.NoError(t, err)
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	// Do issuance session
	jwt := getCombinedJwt("testip", attrid)
	sessionHelper(t, jwt, "issue", client)

	logs, err = client.Logs()
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+1)

	entry := logs[len(logs)-1]
	require.NotNil(t, entry)
	sessionjwt, err := entry.Jwt()
	require.NoError(t, err)
	require.Equal(t, "testip", sessionjwt.(*irma.IdentityProviderJwt).ServerName)
	require.NoError(t, err)
	issued, err := entry.GetIssuedCredentials(client.Configuration)
	require.NoError(t, err)
	require.NotNil(t, issued)
	disclosed, err := entry.GetDisclosedCredentials(client.Configuration)
	require.NoError(t, err)
	require.NotEmpty(t, disclosed)

	// Do disclosure session
	jwt = getDisclosureJwt("testsp", attrid)
	sessionHelper(t, jwt, "verification", client)
	logs, err = client.Logs()
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+2)

	entry = logs[len(logs)-1]
	require.NotNil(t, entry)
	sessionjwt, err = entry.Jwt()
	require.NoError(t, err)
	require.Equal(t, "testsp", sessionjwt.(*irma.ServiceProviderJwt).ServerName)
	require.NoError(t, err)
	disclosed, err = entry.GetDisclosedCredentials(client.Configuration)
	require.NoError(t, err)
	require.NotEmpty(t, disclosed)

	// Do signature session
	jwt = getSigningJwt("testsigclient", attrid)
	sessionHelper(t, jwt, "signature", client)
	logs, err = client.Logs()
	require.NoError(t, err)
	require.True(t, len(logs) == oldLogLength+3)
	entry = logs[len(logs)-1]
	require.NotNil(t, entry)
	sessionjwt, err = entry.Jwt()
	require.NoError(t, err)
	require.Equal(t, "testsigclient", sessionjwt.(*irma.SignatureRequestorJwt).ServerName)
	require.NoError(t, err)
	sig, err := entry.GetSignedMessage()
	require.NoError(t, err)
	require.NotNil(t, sig)
	status, list := irma.VerifySigWithoutRequest(client.Configuration, sig)
	require.Equal(t, irma.VALID, status)
	require.NotEmpty(t, list)
	require.Contains(t, list[0].Attributes, attrid)
	require.Equal(t, "s1234567", list[0].Attributes[attrid]["en"])

	test.ClearTestStorage(t)
}

// TestCandidates tests the correctness of the function of the client that, given a disjunction of attributes
// requested by the verifier, calculates a list of candidate attributes contained by the client that would
// satisfy the attribute disjunction.
func TestCandidates(t *testing.T) {
	client := parseStorage(t)

	// client contains one instance of the studentCard credential, whose studentID attribute is 456.
	attrtype := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	// If the disjunction contains no required values at all, then our attribute is a candidate
	disjunction := &irma.AttributeDisjunction{
		Attributes: []irma.AttributeTypeIdentifier{attrtype},
	}
	attrs := client.Candidates(disjunction)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 1)
	require.NotNil(t, attrs[0])
	require.Equal(t, attrs[0].Type, attrtype)

	// If the disjunction requires our attribute to have 456 as value, which it does,
	// then our attribute is a candidate
	reqval := "456"
	disjunction = &irma.AttributeDisjunction{
		Attributes: []irma.AttributeTypeIdentifier{attrtype},
		Values:     map[irma.AttributeTypeIdentifier]*string{attrtype: &reqval},
	}
	attrs = client.Candidates(disjunction)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 1)
	require.NotNil(t, attrs[0])
	require.Equal(t, attrs[0].Type, attrtype)

	// If the disjunction requires our attribute to have a different value than it does,
	// then it is NOT a match.
	reqval = "foobarbaz"
	disjunction.Values[attrtype] = &reqval
	attrs = client.Candidates(disjunction)
	require.NotNil(t, attrs)
	require.Empty(t, attrs)

	// A required value of nil counts as no requirement on the value, so our attribute is a candidate
	disjunction.Values[attrtype] = nil
	attrs = client.Candidates(disjunction)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 1)
	require.NotNil(t, attrs[0])
	require.Equal(t, attrs[0].Type, attrtype)

	// This test should be equivalent to the one above
	disjunction = &irma.AttributeDisjunction{}
	json.Unmarshal([]byte(`{"attributes":{"irma-demo.RU.studentCard.studentID":null}}`), &disjunction)
	attrs = client.Candidates(disjunction)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 1)
	require.NotNil(t, attrs[0])
	require.Equal(t, attrs[0].Type, attrtype)

	// A required value of null counts as no requirement on the value, but we must still satisfy the disjunction
	// We do not have an instance of this attribute so we have no candidate
	disjunction = &irma.AttributeDisjunction{}
	json.Unmarshal([]byte(`{"attributes":{"irma-demo.MijnOverheid.ageLower.over12":null}}`), &disjunction)
	attrs = client.Candidates(disjunction)
	require.Empty(t, attrs)

	test.ClearTestStorage(t)
}

func TestPaillier(t *testing.T) {
	client := parseStorage(t)

	challenge, _ := gabi.RandomBigInt(256)
	comm, _ := gabi.RandomBigInt(1000)
	resp, _ := gabi.RandomBigInt(1000)

	sk := client.paillierKey(true)
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

	test.ClearTestStorage(t)
}

func TestCredentialRemoval(t *testing.T) {
	client := parseStorage(t)

	id := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	id2 := irma.NewCredentialTypeIdentifier("test.test.mijnirma")

	cred, err := client.credential(id, 0)
	require.NoError(t, err)
	require.NotNil(t, cred)
	err = client.RemoveCredentialByHash(cred.AttributeList().Hash())
	require.NoError(t, err)
	cred, err = client.credential(id, 0)
	require.NoError(t, err)
	require.Nil(t, cred)

	cred, err = client.credential(id2, 0)
	require.NoError(t, err)
	require.NotNil(t, cred)
	err = client.RemoveCredential(id2, 0)
	require.NoError(t, err)
	cred, err = client.credential(id2, 0)
	require.NoError(t, err)
	require.Nil(t, cred)

	test.ClearTestStorage(t)
}

func TestWrongSchemeManager(t *testing.T) {
	client := parseStorage(t)

	irmademo := irma.NewSchemeManagerIdentifier("irma-demo")
	require.Contains(t, client.Configuration.SchemeManagers, irmademo)
	require.NoError(t, os.Remove("../testdata/storage/test/irma_configuration/irma-demo/index"))

	err := client.Configuration.ParseFolder()
	_, ok := err.(*irma.SchemeManagerError)
	require.True(t, ok)
	require.Contains(t, client.Configuration.DisabledSchemeManagers, irmademo)
	require.Contains(t, client.Configuration.SchemeManagers, irmademo)
	require.NotEqual(t,
		client.Configuration.SchemeManagers[irmademo].Status,
		irma.SchemeManagerStatusValid,
	)

	test.ClearTestStorage(t)
}

func TestDisclosureNewAttributeUpdateSchemeManager(t *testing.T) {
	client := parseStorage(t)

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.False(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	disclosureRequest := irma.DisclosureRequest{
		Content: irma.AttributeDisjunctionList{
			&irma.AttributeDisjunction{
				Label: "foo",
				Attributes: []irma.AttributeTypeIdentifier{
					attrid,
				},
			},
		},
	}

	client.Configuration.Download(&disclosureRequest)
	require.True(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	test.ClearTestStorage(t)
}

func TestIssueNewAttributeUpdateSchemeManager(t *testing.T) {
	client := parseStorage(t)
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")
	require.False(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	issuanceRequest := getIssuanceRequest(true)
	issuanceRequest.Credentials[0].Attributes["newAttribute"] = "foobar"
	client.Configuration.Download(issuanceRequest)
	require.True(t, client.Configuration.CredentialTypes[credid].ContainsAttribute(attrid))

	test.ClearTestStorage(t)
}

func TestIssueOptionalAttributeUpdateSchemeManager(t *testing.T) {
	client := parseStorage(t)
	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level")
	require.False(t, client.Configuration.CredentialTypes[credid].AttributeDescription(attrid).IsOptional())

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	issuanceRequest := getIssuanceRequest(true)
	delete(issuanceRequest.Credentials[0].Attributes, "level")
	client.Configuration.Download(issuanceRequest)
	require.True(t, client.Configuration.CredentialTypes[credid].AttributeDescription(attrid).IsOptional())

	test.ClearTestStorage(t)
}

// Test installing a new scheme manager from a qr, and do a(n issuance) session
// within this manager to test the autmatic downloading of credential definitions,
// issuers, and public keys.
func TestDownloadSchemeManager(t *testing.T) {
	client := parseStorage(t)

	// Remove irma-demo scheme manager as we need to test adding it
	irmademo := irma.NewSchemeManagerIdentifier("irma-demo")
	require.Contains(t, client.Configuration.SchemeManagers, irmademo)
	require.NoError(t, client.Configuration.RemoveSchemeManager(irmademo, true))
	require.NotContains(t, client.Configuration.SchemeManagers, irmademo)

	// Do an add-scheme-manager-session
	qr := &irma.Qr{
		Type: irma.ActionSchemeManager,
		URL:  "http://localhost:48681/irma_configuration/irma-demo",
	}
	c := make(chan *irma.SessionError)
	client.NewSession(qr, TestHandler{t, c, client})
	if err := <-c; err != nil {
		t.Fatal(*err)
	}
	require.Contains(t, client.Configuration.SchemeManagers, irmademo)

	// Do a session to test downloading of cred types, issuers and keys
	jwt := getCombinedJwt("testip", irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))
	sessionHelper(t, jwt, "issue", client)

	require.Contains(t, client.Configuration.SchemeManagers, irmademo)
	require.Contains(t, client.Configuration.Issuers, irma.NewIssuerIdentifier("irma-demo.RU"))
	require.Contains(t, client.Configuration.CredentialTypes, irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"))

	basepath := "../testdata/storage/test/irma_configuration/irma-demo"
	exists, err := fs.PathExists(basepath + "/description.xml")
	require.NoError(t, err)
	require.True(t, exists)
	exists, err = fs.PathExists(basepath + "/RU/description.xml")
	require.NoError(t, err)
	require.True(t, exists)
	exists, err = fs.PathExists(basepath + "/RU/Issues/studentCard/description.xml")
	require.NoError(t, err)
	require.True(t, exists)

	test.ClearTestStorage(t)
}
