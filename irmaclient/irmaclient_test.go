package irmaclient

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Create HTTP server for scheme managers
	test.StartSchemeManagerHttpServer()
	defer test.StopSchemeManagerHttpServer()

	test.CreateTestStorage(nil)
	defer test.ClearTestStorage(nil)

	os.Exit(m.Run())
}

func parseStorage(t *testing.T) *Client {
	test.SetupTestStorage(t)
	require.NoError(t, fs.CopyDirectory(filepath.Join("..", "testdata", "teststorage"),
		filepath.Join("..", "testdata", "storage", "test")))
	client, err := New(
		filepath.Join("..", "testdata", "storage", "test"),
		filepath.Join("..", "testdata", "irma_configuration"),
		&TestClientHandler{t: t},
	)
	require.NoError(t, err)
	return client
}

func testhelper(t *testing.T) (*Client, *irma.DisclosureRequest, *irma.Disclosure) {
	client := parseStorage(t)

	requestJson := `{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"M3LYmTr3CZDYZkMNK2uCCg==","protocolVersion":"2.5","disclose":[[["irma-demo.RU.studentCard.studentID"]]],"labels":{"0":null}}`
	dislosureJson := `{"proofs":[{"c":"l1WDHGtsbEO+rVhVoGBDpzluiU5riCKtgMu6Mn4zxDg=","A":"XRyyZFL5xcvQDrCEoIchQdd1qyGpMIafNoak/8aSZisQ5U7JEa54Yu8nW4L9/4fXqLDK1SyX/CvFXrELbFBX1qf1lJ19jTViU9jIpSOw3D8w/DeY7Kg0evwVKUQrcrJnT3ss8J5gM5eRF1E1AuRHgKywWYvtxFvHQs2ODN2qsWY=","e_response":"m41dWZjTVYN6RqnojdHwgfixZwBJKW189b/ehnG3YTt0dMKDUnrLBYhGyKtmstnLzYTuJaBDX4r8","v_response":"DajHvzCDcmxXvd4sucgnrOkaOyFaF0EcOf23ySy56SAiFzWBW1BkcMQ8AwjwnVzYS5vpHnkUDkgqovOsl74RJQMSdnjzu0URAvGZm7/3pXgBjR5Q0154oMC3+n19pQrX68xgEOK7Am6jflfNufyINIVOAm7SfObsjKRDMQcuHOLgoj5XIHPJ3EBJcFJzizmaaGuGHKEJ0+b4Zi8JCBMaP9mdDhsUJAtm190hYxcMb2CtIIiJqGRk+JcNmusRuJYcT9OLx/Xklj+qm6/5C0+jRQPdYNycVzwKel+HDWZyYymCSpjbR5mUw1IpK1QvszN5NIJXVCeDrMMRZcySfOUA","a_responses":{"0":"xxlDTyJ1xq6TuMYgiyisNJ82tiJsnFdBinGP5ZQtw7rxXcLrO6k7nE88wPDuejzEnF7+LgIes32BMC+Qr/C/qh//x7SuMxDujoY=","2":"8HEFx5JJ24Z/D6MRtE6m7Pyk9T61S7lnxdTaych7wEK3ZO+4qyFYVZwx4NLtTp1MRfTiUq6KhNd7Is2cEBAdZYaL3XBnNRQMNvw=","3":"2BleNpicu21GFR1kYJ6kpFct6pyFSYz8hw5tBHtGz7O54KgHySwZ6lI/J4hp1b5l3RWq6gZzlz/PzOLKxk3E3YOwS7e4hsQ7BFo=","5":"977MbEQ95ieN/lVJSUS5Y80nY5KigNtrId2RW87CIsCZQ892rPljuZ0s/UG16b3oEYFEx+WZPxKvGiQN0dJiB8BK3P8qPZlGIu4="},"a_disclosed":{"1":"AgAJuwB+AALWy2qU9p3l52l9LU1rVT4M","4":"NDU2"}}],"indices":[[{"cred":0,"attr":4}]]}`
	request := &irma.DisclosureRequest{}
	require.NoError(t, json.Unmarshal([]byte(requestJson), request))
	disclosure := &irma.Disclosure{}
	require.NoError(t, json.Unmarshal([]byte(dislosureJson), disclosure))

	return client, request, disclosure
}

func TestVerify(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		client, request, disclosure := testhelper(t)
		attr, status, err := disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusValid, status)
		require.Equal(t, "456", *attr[0][0].RawValue)
	})

	t.Run("invalid", func(t *testing.T) {
		client, request, disclosure := testhelper(t)
		disclosure.Proofs[0].(*gabi.ProofD).AResponses[0] = big.NewInt(100)
		_, status, err := disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusInvalid, status)
	})

	t.Run("wrong attribute", func(t *testing.T) {
		client, request, disclosure := testhelper(t)
		request.Disclose[0][0][0].Type = irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
		_, status, err := disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusMissingAttributes, status)
	})
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

func verifyKeyshareIsUnmarshaled(t *testing.T, client *Client) {
	require.NotNil(t, client.keyshareServers)
	testManager := irma.NewSchemeManagerIdentifier("test")
	require.Contains(t, client.keyshareServers, testManager)
	kss := client.keyshareServers[testManager]
	require.NotEmpty(t, kss.Nonce)
}

func TestStorageDeserialization(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	verifyClientIsUnmarshaled(t, client)
	verifyCredentials(t, client)
	verifyKeyshareIsUnmarshaled(t, client)
}

// TestCandidates tests the correctness of the function of the client that, given a disjunction of attributes
// requested by the verifier, calculates a list of candidate attributes contained by the client that would
// satisfy the attribute disjunction.
func TestCandidates(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	// client contains one instance of the studentCard credential, whose studentID attribute is 456.
	attrtype := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	// If the disjunction contains no required values at all, then our attribute is a candidate
	disjunction := irma.AttributeDisCon{
		irma.AttributeCon{irma.AttributeRequest{Type: attrtype}},
	}
	attrs, missing := client.Candidates(disjunction)
	require.Empty(t, missing)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 1)
	require.NotNil(t, attrs[0])
	require.Equal(t, attrs[0][0].Type, attrtype)

	// If the disjunction requires our attribute to have 456 as value, which it does,
	// then our attribute is a candidate
	reqval := "456"
	disjunction[0][0].Value = &reqval
	attrs, missing = client.Candidates(disjunction)
	require.Empty(t, missing)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 1)
	require.NotNil(t, attrs[0])
	require.Equal(t, attrs[0][0].Type, attrtype)

	// If the disjunction requires our attribute to have a different value than it does,
	// then it is NOT a match.
	reqval = "foobarbaz"
	disjunction[0][0].Value = &reqval
	attrs, missing = client.Candidates(disjunction)
	require.NotEmpty(t, missing)
	require.NotNil(t, attrs)
	require.Empty(t, attrs)

	// A required value of nil counts as no requirement on the value, so our attribute is a candidate
	disjunction[0][0].Value = nil
	attrs, missing = client.Candidates(disjunction)
	require.Empty(t, missing)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 1)
	require.NotNil(t, attrs[0])
	require.Equal(t, attrs[0][0].Type, attrtype)

	// Require an attribute we do not have
	disjunction[0][0] = irma.NewAttributeRequest("irma-demo.MijnOverheid.ageLower.over12")
	attrs, missing = client.Candidates(disjunction)
	require.NotEmpty(t, missing)
	require.Empty(t, attrs)
}

func TestCandidateConjunctionOrder(t *testing.T) {
	client := parseStorage(t)

	j := `[
	  [
	    [
	      "irma-demo.RU.studentCard.level",
	      "test.test.mijnirma.email"
	    ]
	  ]
	]`

	cdc := irma.AttributeConDisCon{}
	require.NoError(t, json.Unmarshal([]byte(j), &cdc))
	assert.Equal(t,
		"irma-demo.RU.studentCard.level",
		cdc[0][0][0].Type.String(),
	)

	for i := 1; i < 20; i++ {
		candidates, missing := client.CheckSatisfiability(cdc)
		require.Empty(t, missing)
		require.Equal(t, "irma-demo.RU.studentCard.level", candidates[0][0][0].Type.String())
	}
}

func TestCredentialRemoval(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

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
}

func TestWrongSchemeManager(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	irmademo := irma.NewSchemeManagerIdentifier("irma-demo")
	require.Contains(t, client.Configuration.SchemeManagers, irmademo)
	require.NoError(t, os.Remove(filepath.Join("..", "testdata", "storage", "test", "irma_configuration", "irma-demo", "index")))

	err := client.Configuration.ParseFolder()
	_, ok := err.(*irma.SchemeManagerError)
	require.True(t, ok)
	require.Contains(t, client.Configuration.DisabledSchemeManagers, irmademo)
	require.Contains(t, client.Configuration.SchemeManagers, irmademo)
	require.NotEqual(t,
		client.Configuration.SchemeManagers[irmademo].Status,
		irma.SchemeManagerStatusValid,
	)
}

func TestCredentialInfoListNewAttribute(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")

	client.Configuration.SchemeManagers[schemeid].URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	require.NoError(t, client.Configuration.UpdateSchemeManager(schemeid, nil))
	require.NoError(t, client.Configuration.ParseFolder())
	require.NotNil(t, client.Configuration.CredentialTypes[credid].AttributeType(attrid))

	// irma-demo.RU.studentCard.newAttribute now exists in the scheme but not in the instance in the teststorage
	for _, credinfo := range client.CredentialInfoList() {
		if credinfo.ID == "studentCard" {
			require.Nil(t, credinfo.Attributes[attrid])
			require.NotEmpty(t, credinfo.Attributes[irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level")])
			return
		}
	}
	require.Fail(t, "studentCard credential not found")
}

// ------

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
