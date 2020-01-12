package sessiontest

import (
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/revocation"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/stretchr/testify/require"
)

var (
	revocationHttpServer      *http.Server
	revocationServer          *irmaserver.Server
	revocationConfiguration   *server.Configuration
	revocationIssuanceRequest = irma.NewIssuanceRequest([]*irma.CredentialRequest{{
		RevocationKey:    "cred0", // once revocation is required for a credential type, this key is required
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root"),
		Attributes: map[string]string{
			"BSN": "299792458",
		},
	}})
)

func TestRevocationAll(t *testing.T) {
	t.Run("Revocation", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		attr := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
		cred := attr.CredentialTypeIdentifier()
		client, handler := revocationSetup(t)

		// issue second credential which overwrites the first one, as our credtype is a singleton
		// this is ok, as we use cred0 only to revoke it, to see if cred1 keeps working
		revocationIssuanceRequest.Credentials[0].RevocationKey = "cred1"
		result := requestorSessionHelper(t, revocationIssuanceRequest, client)
		require.Nil(t, result.Err)

		// perform disclosure session (of cred1) with nonrevocation proof
		logger.Info("step 1")
		result = revocationSession(t, client)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)

		// revoke cred0
		logger.Info("step 2")
		require.NoError(t, revocationServer.Revoke(cred, "cred0"))

		// perform another disclosure session with nonrevocation proof to see that cred1 still works
		// client updates its witness to the new accumulator first
		logger.Info("step 3")
		result = revocationSession(t, client)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)

		// revoke cred1
		logger.Info("step 4")
		require.NoError(t, revocationServer.Revoke(cred, "cred1"))

		// try to perform session with revoked credential
		// client notices that his credential is revoked and aborts
		logger.Info("step 5")
		result = revocationSession(t, client, sessionOptionIgnoreClientError)
		require.Equal(t, server.StatusCancelled, result.Status)
		// client revocation callback was called
		require.NotNil(t, handler.(*TestClientHandler).revoked)
		require.Equal(t, cred, handler.(*TestClientHandler).revoked.Type)
		// credential is no longer suggested as candidate
		candidates, missing := client.Candidates(irma.AttributeDisCon{{{Type: attr}}})
		require.Empty(t, candidates)
		require.NotEmpty(t, missing)
	})

	t.Run("OtherAccumulator", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		attr := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
		cred := attr.CredentialTypeIdentifier()
		client, _ := revocationSetup(t)

		// Prepare key material
		conf := revocationConfiguration.IrmaConfiguration.Revocation
		sk, err := conf.Keys.PrivateKey(cred.IssuerIdentifier(), 2)
		require.NoError(t, err)
		pk, err := conf.Keys.PublicKey(cred.IssuerIdentifier(), 2)
		require.NoError(t, err)
		update, err := revocation.NewAccumulator(sk)
		require.NoError(t, err)
		acc, err := update.SignedAccumulator.UnmarshalVerify(pk)
		require.NoError(t, err)

		// Prepare session request
		request := revocationRequest().(*irma.DisclosureRequest)
		require.NoError(t, revocationConfiguration.IrmaConfiguration.Revocation.SetRevocationUpdates(request.Base()))
		events := request.RevocationUpdates[cred][2].Events
		require.Equal(t, uint64(1), events[len(events)-1].Index)

		// Construct disclosure proof with nonrevocation proof against accumulator with index 1
		candidates, missing := client.CheckSatisfiability(request.Disclosure().Disclose)
		require.Empty(t, missing)
		choice := &irma.DisclosureChoice{Attributes: [][]*irma.AttributeIdentifier{candidates[0][0]}}
		disclosure, _, err := client.Proofs(choice, request)
		require.NoError(t, err)
		pacc, err := disclosure.Proofs[0].(*gabi.ProofD).NonRevocationProof.SignedAccumulator.UnmarshalVerify(pk)
		require.NoError(t, err)
		require.Equal(t, uint64(1), pacc.Index)

		// Revoke a bogus credential, advancing accumulator index to 2, and update the session request,
		// indicated that we expect a nonrevocation proof wrt accumulator with index 2
		revoke(t, "2", conf, cred, acc)
		request.RevocationUpdates = nil
		require.NoError(t, conf.SetRevocationUpdates(request.Base()))
		events = request.RevocationUpdates[cred][2].Events
		require.Equal(t, uint64(2), events[len(events)-1].Index)

		// Try to verify against updated session request
		_, status, err := disclosure.Verify(client.Configuration, request)
		require.Error(t, err)
		require.Equal(t, irma.ProofStatusInvalid, status)

		// Revoke another bogus credential, advancing index to 3, and make a new disclosure request
		// requiring a nonrevocation proof against the accumulator with index 3
		revoke(t, "3", conf, cred, acc)
		newrequest := revocationRequest().(*irma.DisclosureRequest)
		require.NoError(t, conf.SetRevocationUpdates(newrequest.Base()))
		events = newrequest.RevocationUpdates[cred][2].Events
		require.Equal(t, uint64(3), events[len(events)-1].Index)

		// Use newrequest to update client to index 3 and contruct a disclosure proof
		require.NoError(t, client.NonrevPrepare(newrequest))
		disclosure, _, err = client.Proofs(choice, newrequest)
		require.NoError(t, err)
		pacc, err = disclosure.Proofs[0].(*gabi.ProofD).NonRevocationProof.SignedAccumulator.UnmarshalVerify(pk)
		require.NoError(t, err)
		require.Equal(t, uint64(3), pacc.Index)

		// Check that the nonrevocation proof which uses a newer accumulator than ours verifies
		events = request.RevocationUpdates[cred][2].Events
		require.Equal(t, uint64(2), events[len(events)-1].Index)
		_, status, err = disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusValid, status)
	})

	t.Run("ClientUpdate", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		attr := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
		cred := attr.CredentialTypeIdentifier()
		client, _ := revocationSetup(t)

		conf := revocationConfiguration.IrmaConfiguration.Revocation

		sk, err := conf.Keys.PrivateKey(cred.IssuerIdentifier(), 2)
		require.NoError(t, err)
		pk, err := conf.Keys.PublicKey(cred.IssuerIdentifier(), 2)
		require.NoError(t, err)
		update, err := revocation.NewAccumulator(sk)
		require.NoError(t, err)
		acc, err := update.SignedAccumulator.UnmarshalVerify(pk)
		require.NoError(t, err)

		// Advance the accumulator by doing revocations so much that the client will need
		// to contact the RA to update its witness
		for i := 0; i < irma.RevocationDefaultEventCount+1; i++ {
			key := strconv.Itoa(i)
			revoke(t, key, conf, cred, acc)
		}

		result := revocationSession(t, client)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
	})

	t.Run("SameIrmaServer", func(t *testing.T) {
		StartIrmaServer(t, false)
		defer StopIrmaServer()
		defer test.ClearTestStorage(t)

		// issue a credential, populating irmaServer's revocation memdb
		client, _ := revocationSetup(t, sessionOptionReuseServer)

		// disable serving revocation updates in revocation server
		require.NoError(t, revocationConfiguration.IrmaConfiguration.Revocation.Close())

		// do disclosure session, using irmaServer's memdb
		result := revocationSession(t, client, sessionOptionReuseServer)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
	})
}

// Helper functions

func revocationRequest() irma.SessionRequest {
	attr := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	req := irma.NewDisclosureRequest(attr)
	req.Revocation = []irma.CredentialTypeIdentifier{attr.CredentialTypeIdentifier()}
	return req
}

func revocationSession(t *testing.T, client *irmaclient.Client, options ...sessionOption) *requestorSessionResult {
	result := requestorSessionHelper(t, revocationRequest(), client, options...)
	require.Nil(t, result.Err)
	return result
}

// revocationSetup sets up an irmaclient with a revocation-enabled credential, constants, and revocation key material.
func revocationSetup(t *testing.T, options ...sessionOption) (*irmaclient.Client, irmaclient.ClientHandler) {
	startRevocationServer(t)

	// issue a MijnOverheid.root instance with revocation enabled
	client, handler := parseStorage(t)
	result := requestorSessionHelper(t, revocationIssuanceRequest, client, options...)
	require.Nil(t, result.Err)

	return client, handler
}

func revoke(t *testing.T, key string, conf *irma.RevocationStorage, cred irma.CredentialTypeIdentifier, acc *revocation.Accumulator) {
	sk, err := conf.Keys.PrivateKey(cred.IssuerIdentifier(), 2)
	require.NoError(t, err)
	witness, err := revocation.RandomWitness(sk, acc)
	require.NoError(t, err)
	require.NoError(t, conf.AddIssuanceRecord(&irma.IssuanceRecord{
		Key:        key,
		CredType:   cred,
		PKCounter:  2,
		Attr:       (*irma.RevocationAttribute)(witness.E),
		Issued:     time.Now().UnixNano(),
		ValidUntil: time.Now().Add(1 * time.Hour).UnixNano(),
	}))
	require.NoError(t, conf.Revoke(cred, key))
	_, newacc, err := conf.Accumulator(cred, 2)
	require.NoError(t, err)
	*acc = *newacc
}

func startRevocationServer(t *testing.T) {
	var err error

	irma.Logger = logger

	//dbtype, dbstr := "postgres", "host=127.0.0.1 port=5432 user=testuser dbname=test password='testpassword' sslmode=disable"
	dbtype, dbstr := "mysql", "testuser:testpassword@tcp(127.0.0.1)/test"

	// Connect to database and clear records from previous test runs
	g, err := gorm.Open(dbtype, dbstr)
	require.NoError(t, err)
	require.NoError(t, g.DropTableIfExists((*irma.EventRecord)(nil)).Error)
	require.NoError(t, g.DropTableIfExists((*irma.AccumulatorRecord)(nil)).Error)
	require.NoError(t, g.DropTableIfExists((*irma.IssuanceRecord)(nil)).Error)
	require.NoError(t, g.AutoMigrate((*irma.EventRecord)(nil)).Error)
	require.NoError(t, g.AutoMigrate((*irma.AccumulatorRecord)(nil)).Error)
	require.NoError(t, g.AutoMigrate((*irma.IssuanceRecord)(nil)).Error)
	require.NoError(t, g.Close())

	cred := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")
	settings := map[irma.CredentialTypeIdentifier]*irma.RevocationSetting{
		cred: {Mode: irma.RevocationModeServer},
	}
	irmaconf, err := irma.NewConfiguration(filepath.Join(testdata, "irma_configuration"), irma.ConfigurationOptions{
		RevocationDBConnStr: dbstr,
		RevocationDBType:    dbtype,
		RevocationSettings:  settings,
	})
	require.NoError(t, err)
	require.NoError(t, irmaconf.ParseFolder())

	conf := &server.Configuration{
		Logger:               logger,
		DisableSchemesUpdate: true,
		SchemesPath:          filepath.Join(testdata, "irma_configuration"),
		RevocationSettings:   settings,
		IrmaConfiguration:    irmaconf,
		RevocationDBConnStr:  dbstr,
		RevocationDBType:     dbtype,
	}

	// Enable revocation for our credential type
	sk, err := irmaconf.Revocation.Keys.PrivateKeyLatest(cred.IssuerIdentifier())
	require.NoError(t, err)
	require.NoError(t, irmaconf.Revocation.EnableRevocation(cred, sk))

	// Start revocation server
	revocationServer, err = irmaserver.New(conf)
	revocationConfiguration = conf
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/", revocationServer.HandlerFunc())
	revocationHttpServer = &http.Server{Addr: ":48683", Handler: mux}
	go func() {
		_ = revocationHttpServer.ListenAndServe()
	}()
}

func stopRevocationServer() {
	revocationServer.Stop()
	_ = revocationHttpServer.Close()
}
