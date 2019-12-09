package irmaclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/fs"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
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
	return parseExistingStorage(t)
}

func parseExistingStorage(t *testing.T) *Client {
	client, err := New(
		filepath.Join("..", "testdata", "tmp", "client"),
		filepath.Join("..", "testdata", "irma_configuration"),
		&TestClientHandler{t: t},
	)
	require.NoError(t, err)
	return client
}

func parseDisclosure(t *testing.T) (*Client, *irma.DisclosureRequest, *irma.Disclosure) {
	client := parseStorage(t)

	requestJson := `{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"zVQJMG6TKZwfcv5TExFVSQ==","protocolVersion":"2.5","disclose":[[["irma-demo.RU.studentCard.studentID"]]],"labels":{"0":null}}`
	dislosureJson := `{"proofs":[{"c":"o21UPItMKWXmXNhBKsCBHDWjfRoy+uDdbDB1yhhpg3k=","A":"Bl68Ut2nu2nwhIweU9QGoNd6TkjUIRbQ6SDg22m8PzMEgca0KA4/Oy1gaJCUHM3FFJ0Gdj0+6/VpcF85JyuQZou93UXXwzN/Y7ohUw+YxVTQ7WcJmZ/VGDh3SME5KJ9aWjGmq61J2LQiiDSq+XrcWFfKPwad6BkDhV2reo4yo68=","e_response":"VD0pWdeDkd3V+R3734xyRcGeWMMTzpB0ZiJhKMzv37DmHN6RpRzTF/0HroAsMIMz8mBWxYPVRBiw","v_response":"3OWsmIDM7v0ByEXax2YZGp3BnJ5nkCLMcT6/ENU0EcpjrOz+rT+NayQSLgMshxAATpgkgAluFQ3owOoQEL8ZAkZTWUDW5j+qy7GDFd22ZOKEZLWf8Q1XRK3x6exV9CIMkcBQrv5W6EI9XB5OKKNB3Z/VTALY3UW8cQQ0DPHj83YBEL3LJQDxwaxvQeHx4nysJjsEoLJE1KPBynXlfxpk17O3HTg+NuX5gj7+ckiHrmXgthJHvqCTnNpEORtXDJTmKJUccUiyWuftA36cIXIxW4N6I88T4BYctwN+T9NY+hcjYESITtxB+r2elB98bzlWgHF8ohpOkkJGuNjTFjw=","a_responses":{"0":"eDQA3Lrh2WC3o/VP6KD/uaMSRy/em3gEfuqXD9tVT+yJFYb7GT91lle5dB6lg235pUSHzYIOET7FYOHwb4/YSAGQiix0IzqFkLo=","2":"kT3kfcIaPy3UBYPX78X10w/R1Cb5rHqoW5OUd06xqC1V9MqVw3zhtc/nBgWmvVwTgJrl2CyuBjjoF10RJz/FEjYZ0JAF57uUXW8=","3":"4oSBcyUT6mOBhk/Szk/5G5QrgaAADW6wSl91hGwTTNDTIUiK01GE11JozbwDeZsLPoFikzikwkPu9ZsOAtOtb/+IcadB6NP0KXA=","5":"OwUSSCBb9NOMOYYSGSYCrdFUNLKJ/b2YP5LlElFG5r4GPR71zTQsZ4QuJiMIt9iFPRP6PQUvMvjWA59UTQ9AlwKc9JcQzbScYBM="},"a_disclosed":{"1":"AwAKOQIBAALWy2qU9p3l52l9LU1rVT4M","4":"aGpt"}}],"indices":[[{"cred":0,"attr":4}]]}`
	request := &irma.DisclosureRequest{}
	require.NoError(t, json.Unmarshal([]byte(requestJson), request))
	disclosure := &irma.Disclosure{}
	require.NoError(t, json.Unmarshal([]byte(dislosureJson), disclosure))

	return client, request, disclosure
}

func TestVerify(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		client, request, disclosure := parseDisclosure(t)
		attr, status, err := disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusValid, status)
		require.Equal(t, "456", *attr[0][0].RawValue)
	})

	t.Run("invalid", func(t *testing.T) {
		client, request, disclosure := parseDisclosure(t)
		disclosure.Proofs[0].(*gabi.ProofD).AResponses[0] = big.NewInt(100)
		_, status, err := disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusInvalid, status)
	})

	t.Run("wrong attribute", func(t *testing.T) {
		client, request, disclosure := parseDisclosure(t)
		request.Disclose[0][0][0].Type = irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
		_, status, err := disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusMissingAttributes, status)
	})

	t.Run("wrong nonce", func(t *testing.T) {
		client, request, disclosure := parseDisclosure(t)
		request.Nonce = big.NewInt(100)
		_, status, err := disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusInvalid, status)
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
		cred.Signature.Verify(pk, cred.Attributes, nil),
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
				cred.Credential.Signature.Verify(pk, cred.Attributes, nil),
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

	// Also check whether credential is removed after reloading the storage
	err = client.storage.db.Close()
	require.NoError(t, err)
	client = parseExistingStorage(t)
	cred, err = client.credential(id2, 0)
	require.NoError(t, err)
	require.Nil(t, cred)
}

func TestWrongSchemeManager(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	irmademo := irma.NewSchemeManagerIdentifier("irma-demo")
	require.Contains(t, client.Configuration.SchemeManagers, irmademo)
	require.NoError(t, os.Remove(filepath.Join("..", "testdata", "tmp", "client", "irma_configuration", "irma-demo", "index")))

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

	// irma-demo.RU.studentCard.newAttribute now exists in the scheme but not in the instance in the testdata folder
	for _, credinfo := range client.CredentialInfoList() {
		if credinfo.ID == "studentCard" {
			require.Nil(t, credinfo.Attributes[attrid])
			require.NotEmpty(t, credinfo.Attributes[irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level")])
			return
		}
	}
	require.Fail(t, "studentCard credential not found")
}

func TestFreshStorage(t *testing.T) {
	test.CreateTestStorage(t)
	defer test.ClearTestStorage(t)

	path := filepath.Join(test.FindTestdataFolder(t), "storage", "test")
	err := fs.EnsureDirectoryExists(path)
	require.NoError(t, err)
	client := parseExistingStorage(t)

	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestKeyshareEnrollmentRemoval(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	err := client.KeyshareRemove(irma.NewSchemeManagerIdentifier("test"))
	require.NoError(t, err)

	err = client.storage.db.Close()
	require.NoError(t, err)
	client = parseExistingStorage(t)

	require.NotContains(t, client.keyshareServers, "test")
}

func TestUpdatePreferences(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	client.SetCrashReportingPreference(!defaultPreferences.EnableCrashReporting)
	client.applyPreferences()

	err := client.storage.db.Close()
	require.NoError(t, err)
	client = parseExistingStorage(t)

	require.NoError(t, err)
	require.Equal(t, false, client.Preferences.EnableCrashReporting)
}

func TestUpdatingStorage(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)
	require.NotNil(t, client)

	// Check whether all update functions succeeded
	for _, u := range client.updates {
		require.Equal(t, true, u.Success)
	}
}

func TestRemoveStorage(t *testing.T) {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	bucketsBefore := map[string]bool{"attrs": true, "sigs": true, "userdata": true, "logs": true}   // Test storage has 1 log
	bucketsAfter := map[string]bool{"attrs": false, "sigs": false, "userdata": true, "logs": false} // Userdata should hold a new secret key

	old_sk := *client.secretkey

	// Check that buckets exist
	for name, exists := range bucketsBefore {
		require.Equal(t, exists, client.storage.BucketExists([]byte(name)), fmt.Sprintf("Bucket \"%s\" exists should be %t", name, exists))
	}

	require.NoError(t, client.RemoveStorage())

	for name, exists := range bucketsAfter {
		require.Equal(t, exists, client.storage.BucketExists([]byte(name)), fmt.Sprintf("Bucket \"%s\" exists should be %t", name, exists))
	}

	// Check that the client has a new secret key
	new_sk := *client.secretkey
	require.NotEqual(t, old_sk, new_sk)
}

// ------

type TestClientHandler struct {
	t *testing.T
	c chan error
}

func (i *TestClientHandler) UpdateConfiguration(new *irma.IrmaIdentifierSet) {}
func (i *TestClientHandler) UpdateAttributes()                               {}
func (i *TestClientHandler) Revoked(cred *irma.CredentialIdentifier)         {}
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
