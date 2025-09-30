package irmaclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/signed"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/concmap"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/sirupsen/logrus"

	"github.com/go-errors/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	irma.Logger.SetLevel(logrus.FatalLevel)
	common.ForceHTTPS = false // globally disable https enforcement

	// Create HTTP server for scheme managers
	test.StartSchemeManagerHttpServer()

	retval := m.Run()

	test.StopSchemeManagerHttpServer()

	os.Exit(retval)
}

func parseStorage(t *testing.T) (*IrmaClient, *TestClientHandler) {
	storage := test.SetupTestStorage(t)
	return parseExistingStorage(t, storage)
}

func parseExistingStorage(t *testing.T, storageFolder string) (*IrmaClient, *TestClientHandler) {
	handler := &TestClientHandler{t: t, c: make(chan error), storage: storageFolder}
	path := test.FindTestdataFolder(t)

	var signer Signer
	bts, err := os.ReadFile(filepath.Join(storageFolder, "client", "ecdsa_sk.pem"))
	if os.IsNotExist(err) {
		signer = test.NewSigner(t)
	} else {
		require.NoError(t, err)
		sk, err := signed.UnmarshalPemPrivateKey(bts)
		require.NoError(t, err)
		signer = test.LoadSigner(t, sk)
	}

	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(path, "irma_configuration")

	if err = common.AssertPathExists(storagePath); err != nil {
		require.NoError(t, err)
	}
	if err = common.AssertPathExists(irmaConfigurationPath); err != nil {
		require.NoError(t, err)
	}

	conf, err := irma.NewConfiguration(
		filepath.Join(storagePath, "irma_configuration"),
		irma.ConfigurationOptions{Assets: irmaConfigurationPath, IgnorePrivateKeys: true},
	)
	require.NoError(t, err)

	storage := NewIrmaStorage(storagePath, conf, aesKey)
	require.NoError(t, storage.Open())
	sdjwtStorage, err := NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()

	x509Options, err := utils.CreateX509VerifyOptionsFromCertChain(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)

	require.NoError(t, err)

	context := sdjwtvc.SdJwtVcVerificationContext{
		VerificationContext: &eudi_jwt.StaticVerificationContext{
			VerifyOpts: *x509Options,
		},
		Clock:       sdjwtvc.NewSystemClock(),
		JwtVerifier: sdjwtvc.NewJwxJwtVerifier(),
	}

	client, _ := NewIrmaClient(
		conf,
		handler,
		signer,
		storage,
		context,
		sdjwtStorage,
		keyBinder,
	)
	require.NoError(t, err)

	client.SetPreferences(Preferences{DeveloperMode: true})
	return client, handler
}

func verifyClientIsUnmarshaled(t *testing.T, client *IrmaClient) {
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

func verifyCredentials(t *testing.T, client *IrmaClient) {
	var pk *gabikeys.PublicKey
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

func verifyKeyshareIsUnmarshaled(t *testing.T, client *IrmaClient) {
	require.NotNil(t, client.keyshareServers)
	testManager := irma.NewSchemeManagerIdentifier("test")
	require.Contains(t, client.keyshareServers, testManager)
	kss := client.keyshareServers[testManager]
	require.NotEmpty(t, kss.Nonce)
}

func TestStorageDeserialization(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()

	verifyClientIsUnmarshaled(t, client)
	verifyCredentials(t, client)
	verifyKeyshareIsUnmarshaled(t, client)
}

// TestCandidates tests the correctness of the function of the client that, given a disjunction of attributes
// requested by the verifier, calculates a list of candidate attributes contained by the client that would
// satisfy the attribute disjunction.
func TestCandidates(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()

	// client contains one instance of the studentCard credential, whose studentID attribute is 456.
	attrtype := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	// If the disjunction contains no required values at all, then our attribute is a candidate
	// but we should also get the option to get another value
	request := irma.NewDisclosureRequest(attrtype)
	disjunction := request.Disclose[0]
	request.ProtocolVersion = &irma.ProtocolVersion{Major: 2, Minor: 8}
	attrs, satisfiable, err := client.candidatesDisCon(request, disjunction)
	require.NoError(t, err)
	require.True(t, satisfiable)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 2)
	require.NotNil(t, attrs[0])
	require.Equal(t, attrs[0][0].Type, attrtype)
	require.True(t, attrs[0][0].Present())
	require.Empty(t, attrs[0][0].Value)
	require.Equal(t, attrs[1][0].Type, attrtype)
	require.False(t, attrs[1][0].Present())
	require.Empty(t, attrs[1][0].Value)

	// If the disjunction requires our attribute to have 456 as value, which it does,
	// then our attribute is a candidate
	reqval := "456"
	disjunction[0][0].Value = &reqval
	attrs, satisfiable, err = client.candidatesDisCon(request, disjunction)
	require.NoError(t, err)
	require.True(t, satisfiable)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 1)
	require.NotNil(t, attrs[0])
	require.Equal(t, attrs[0][0].Type, attrtype)
	require.True(t, attrs[0][0].Present())
	require.NotNil(t, attrs[0][0].Value)
	require.Equal(t, reqval, attrs[0][0].Value[""])

	// If the disjunction requires our attribute to have a different value than it does,
	// then it is NOT a match.
	reqval = "foobarbaz"
	disjunction[0][0].Value = &reqval
	attrs, satisfiable, err = client.candidatesDisCon(request, disjunction)
	require.NoError(t, err)
	require.False(t, satisfiable)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 1)
	require.NotNil(t, attrs[0])
	require.False(t, attrs[0][0].Present())
	require.NotNil(t, attrs[0][0].Value)
	require.Equal(t, reqval, attrs[0][0].Value[""])

	// A required value of nil counts as no requirement on the value, so our attribute is a candidate
	// and we should also get the option to get another value
	disjunction[0][0].Value = nil
	attrs, satisfiable, err = client.candidatesDisCon(request, disjunction)
	require.NoError(t, err)
	require.True(t, satisfiable)
	require.NotNil(t, attrs)
	require.Len(t, attrs, 2)
	require.NotNil(t, attrs[0])
	require.Equal(t, attrs[0][0].Type, attrtype)
	require.True(t, attrs[0][0].Present())
	require.Empty(t, attrs[0][0].Value)
	require.Equal(t, attrs[1][0].Type, attrtype)
	require.False(t, attrs[1][0].Present())
	require.Empty(t, attrs[1][0].Value)

	// Require an attribute we do not have: a "non-present" credential (i.e. without hash)
	// is included with the candidates as suggestion to the user
	disjunction[0][0] = irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname")
	attrs, satisfiable, err = client.candidatesDisCon(request, disjunction)
	require.NoError(t, err)
	require.False(t, satisfiable)
	require.Len(t, attrs, 1)
	require.NotNil(t, attrs[0])
	require.False(t, attrs[0][0].Present())
	require.Empty(t, attrs[0][0].Value)

	// When the nonpresent attribute comes from a credential type that is being issued,
	// that credential type is not included with the candidates as suggestion
	isreq := irma.NewIssuanceRequest([]*irma.CredentialRequest{{
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root"),
		Attributes:       map[string]string{"BSN": "12345"},
	}})
	isreq.Disclose = irma.AttributeConDisCon{{
		{},
		{irma.NewAttributeRequest("irma-demo.MijnOverheid.root.BSN")},
	}}
	attrs, satisfiable, err = client.candidatesDisCon(isreq, isreq.Disclose[0])
	require.NoError(t, err)
	require.True(t, satisfiable)
	// we don't have irma-demo.MijnOverheid.root, the empty conjunction gives the only candidate
	require.Len(t, attrs, 1)
}

func TestCandidateConjunctionOrder(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()

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

	req := &irma.DisclosureRequest{
		BaseRequest: irma.BaseRequest{ProtocolVersion: client.maxVersion},
		Disclose:    cdc,
	}

	for i := 1; i < 20; i++ {
		candidates, satisfiable, err := client.Candidates(req)
		require.NoError(t, err)
		require.True(t, satisfiable)
		require.Equal(t, "irma-demo.RU.studentCard.level", candidates[0][0][0].Type.String())
	}
}

func TestCredentialRemoval(t *testing.T) {
	client, handler := parseStorage(t)
	defer client.Close()

	id := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	id2 := irma.NewCredentialTypeIdentifier("test.test.mijnirma")

	cred, err := client.credential(id, 0)
	require.NoError(t, err)
	require.NotNil(t, cred)
	err = client.RemoveCredentialByHash(cred.attrs.Hash())
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
	client, _ = parseExistingStorage(t, handler.storage)
	defer client.storage.db.Close()
	cred, err = client.credential(id2, 0)
	require.NoError(t, err)
	require.Nil(t, cred)
}

func TestRemoveSchemes(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()

	// Unset configuration assets to enable removal of schemes
	var err error
	client.Configuration, err = irma.NewConfiguration(
		client.Configuration.Path,
		irma.ConfigurationOptions{IgnorePrivateKeys: true},
	)
	require.NoError(t, err)
	err = client.Configuration.ParseFolder()
	require.NoError(t, err)

	// Remove demo scheme
	irmaDemoSchemeID := irma.NewSchemeManagerIdentifier("irma-demo")
	err = client.RemoveScheme(irmaDemoSchemeID)
	require.NoError(t, err)
	require.NotContains(t, client.Configuration.SchemeManagers, irmaDemoSchemeID)

	// Remove test scheme
	testSchemeID := irma.NewSchemeManagerIdentifier("test")
	err = client.RemoveScheme(testSchemeID)
	require.NoError(t, err)
	require.NotContains(t, client.Configuration.SchemeManagers, testSchemeID)

	// Remove nonexistent scheme
	err = client.RemoveScheme(irma.NewSchemeManagerIdentifier("nonexistent"))
	require.Error(t, err)

	// Remove requestor scheme
	testRequestorsSchemeID := irma.NewRequestorSchemeIdentifier("test-requestors")
	err = client.RemoveRequestorScheme(testRequestorsSchemeID)
	require.NoError(t, err)
	require.NotContains(t, client.Configuration.RequestorSchemes, testRequestorsSchemeID)
	require.NotContains(t, client.Configuration.Requestors, testRequestorsSchemeID)
	for wizardID := range client.Configuration.IssueWizards {
		require.False(t, strings.HasPrefix(wizardID.String(), testRequestorsSchemeID.String()))
	}

	// Remove nonexistent requestor scheme
	err = client.RemoveRequestorScheme(irma.NewRequestorSchemeIdentifier("nonexistent"))
	require.Error(t, err)
}

func TestWrongSchemeManager(t *testing.T) {
	client, handler := parseStorage(t)
	defer client.Close()

	irmademo := irma.NewSchemeManagerIdentifier("irma-demo")
	require.Contains(t, client.Configuration.SchemeManagers, irmademo)
	path := filepath.Join(handler.storage, "client", "irma_configuration", "irma-demo", "MijnOverheid", "description.xml")
	require.NoError(t, os.WriteFile(path, []byte("overwrite to invalidate file signature"), 0600))

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
	client, _ := parseStorage(t)
	defer client.Close()

	schemeid := irma.NewSchemeManagerIdentifier("irma-demo")
	credid := irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard")
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.newAttribute")

	scheme := client.Configuration.SchemeManagers[schemeid]
	scheme.URL = "http://localhost:48681/irma_configuration_updated/irma-demo"
	require.NoError(t, client.Configuration.UpdateScheme(scheme, nil))
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
	storage := test.CreateTestStorage(t)
	client, _ := parseExistingStorage(t, storage)
	defer client.Close()
	require.NotNil(t, client)
}

func TestKeyshareEnrollmentRemoval(t *testing.T) {
	client, handler := parseStorage(t)
	defer client.Close()

	err := client.KeyshareRemove(irma.NewSchemeManagerIdentifier("test"))
	require.NoError(t, err)

	err = client.storage.Close()
	require.NoError(t, err)
	client, _ = parseExistingStorage(t, handler.storage)
	err = client.storage.Close()
	require.NoError(t, err)

	require.NotContains(t, client.keyshareServers, "test")
}

func TestUpdatingStorage(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()
	require.NotNil(t, client)

	// Check whether all update functions succeeded
	for _, u := range client.updates {
		require.Equal(t, true, u.Success)
	}
}

func TestRemoveStorage(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()

	// Check whether we have logs in storage to know whether the logs bucket is there
	logs, err := client.LoadNewestLogs(1)
	require.NoError(t, err)

	bucketsBefore := map[string]bool{"attrs": true, "sigs": true, "userdata": true, "logs": len(logs) > 0}
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

func TestCredentialsConcurrency(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()
	grp := sync.WaitGroup{}

	for j := 0; j < 1000; j++ {
		// Clear map for next iteration
		client.credentialsCache = concmap.New[credLookup, *credential]()

		for i := 0; i < 10; i++ {
			grp.Add(1)
			go func() {
				_, err := client.credential(irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"), 0)
				require.NoError(t, err)
				grp.Done()
			}()
		}

		grp.Wait()
	}
}

func TestVerifyAndStoreSdJwtVc_GivenValidSdJwt_Succeeds(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()

	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	certChain, err := utils.ParsePemCertificateChainToX5cFormat(chain)
	if err != nil {
		panic(err)
	}

	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()
	sdjwt, _ := createTestSdJwtVc(keyBinder, "test.test.mobilephone", "https://openid4vc.staging.yivi.app",
		map[string]any{
			"mobilephone": "+31612345678",
		}, certChain,
	)

	cred := irma.CredentialRequest{}

	err = client.VerifyAndStoreSdJwts([]sdjwtvc.SdJwtVc{sdjwt}, []*irma.CredentialRequest{&cred})

	require.NoError(t, err)
}

func TestVerifyAndStoreSdJwtVc_GivenInvalidSdJwt_Fails(t *testing.T) {
	client, _ := parseStorage(t)
	defer client.Close()

	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	certChain, err := utils.ParsePemCertificateChainToX5cFormat(chain)
	if err != nil {
		panic(err)
	}

	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()
	sdjwt, _ := createTestSdJwtVc(
		keyBinder,
		"test.test.mobilephone", "http://openid4vc.staging.yivi.app", // issuer is invalid (no HTTPS)
		map[string]any{
			"mobilephone": "+31612345678",
		}, certChain,
	)

	cred := irma.CredentialRequest{}

	err = client.VerifyAndStoreSdJwts([]sdjwtvc.SdJwtVc{sdjwt}, []*irma.CredentialRequest{&cred})

	require.Error(t, err)
}

// ------

type TestClientHandler struct {
	t       *testing.T
	c       chan error
	storage string
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
func (i *TestClientHandler) ChangePinSuccess() {
	select {
	case i.c <- nil: // nop
	default: // nop
	}
}
func (i *TestClientHandler) ChangePinFailure(manager irma.SchemeManagerIdentifier, err error) {
	select {
	case i.c <- err: // nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ChangePinIncorrect(manager irma.SchemeManagerIdentifier, attempts int) {
	err := errors.New("incorrect pin")
	select {
	case i.c <- err: // nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ChangePinBlocked(manager irma.SchemeManagerIdentifier, timeout int) {
	err := errors.New("blocked account")
	select {
	case i.c <- err: // nop
	default:
		i.t.Fatal(err)
	}
}
func (i *TestClientHandler) ReportError(err error) {
	select {
	case i.c <- err: // nop
	default:
		i.t.Fatal(err)
	}
}
