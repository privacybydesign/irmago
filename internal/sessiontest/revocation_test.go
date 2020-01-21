package sessiontest

import (
	"encoding/json"
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
	revocationHttpServer    *http.Server
	revocationServer        *irmaserver.Server
	revocationConfiguration *server.Configuration

	//revocationDbType, revocationDbStr = "postgres", "host=127.0.0.1 port=5432 user=testuser dbname=test password='testpassword' sslmode=disable"
	revocationDbType, revocationDbStr = "mysql", "testuser:testpassword@tcp(127.0.0.1)/test"

	revocationTestAttr        = irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	revocationTestCred        = revocationTestAttr.CredentialTypeIdentifier()
	revocationIssuanceRequest = irma.NewIssuanceRequest([]*irma.CredentialRequest{{
		RevocationKey:    "cred0", // once revocation is required for a credential type, this key is required
		CredentialTypeID: revocationTestCred,
		Attributes: map[string]string{
			"BSN": "299792458",
		},
	}})
)

func TestRevocationAll(t *testing.T) {
	t.Run("Revocation", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		client, handler := revocationSetup(t)

		// issue second credential which overwrites the first one, as our credtype is a singleton
		// this is ok, as we use cred0 only to revoke it, to see if cred1 keeps working
		revocationIssuanceRequest.Credentials[0].RevocationKey = "cred1"
		result := requestorSessionHelper(t, revocationIssuanceRequest, client)
		require.Nil(t, result.Err)

		// perform disclosure session (of cred1) with nonrevocation proof
		logger.Info("step 1")
		result = revocationSession(t, client, nil)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)

		// revoke cred0
		logger.Info("step 2")
		require.NoError(t, revocationServer.Revoke(revocationTestCred, "cred0"))

		// perform another disclosure session with nonrevocation proof to see that cred1 still works
		// client updates its witness to the new accumulator first
		logger.Info("step 3")
		result = revocationSession(t, client, nil)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)

		// revoke cred1
		logger.Info("step 4")
		require.NoError(t, revocationServer.Revoke(revocationTestCred, "cred1"))

		// try to perform session with revoked credential
		// client notices that his credential is revoked and aborts
		logger.Info("step 5")
		result = revocationSession(t, client, nil, sessionOptionIgnoreClientError)
		require.Equal(t, server.StatusCancelled, result.Status)
		// client revocation callback was called
		require.NotNil(t, handler.(*TestClientHandler).revoked)
		require.Equal(t, revocationTestCred, handler.(*TestClientHandler).revoked.Type)
		// credential is no longer suggested as candidate
		candidates, missing := client.Candidates(irma.AttributeDisCon{{{Type: revocationTestAttr}}})
		require.Empty(t, candidates)
		require.NotEmpty(t, missing)
	})

	t.Run("AttributeBasedSignature", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		client, _ := revocationSetup(t)

		request := revocationSigRequest()
		result := revocationSession(t, client, request)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
		require.NotNil(t, result.Signature)

		_, status, err := result.Signature.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusValid, status)

		_, status, err = result.Signature.Verify(client.Configuration, nil)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusValid, status)
	})

	t.Run("VerifyAttributeBasedSignature", func(t *testing.T) {
		client, _ := parseStorage(t)
		defer test.ClearTestStorage(t)

		j := `{"@context":"https://irma.app/ld/signature/v2","signature":[{"c":"e2nKrqit2VU+dSMrgZeUzVTuf8NQ0MPWrjCSW9ZmJYk=","A":"b2/DBvaqnmd346EEvSKu8zDqSDukEHutZdE14HnmljLsVy8DI93gjH0Udsc+p4Sj2AO8x6vjtrXSVptncMsE4tz+7m8euDfH6tdggAd07p5wRxXJCOg/EQpC750QJU3Z30rNkjDv5ajA4stLaKtGs92TFJ0S676PlbYfUHS0QHg=","e_response":"Sfwy53PSeEmBiJJxMU3qqm/z+8klQoRhHYhRqs6gJeGlUUMeQFxzdNC/P9PmzK8wOvpGwTjw7MgY","v_response":"Dj36QVCjaZACzUGckLJWNSJibCGN6xtgt5gDrFQw2yuQmxNm+SFpfK9Pe/REozkHOV5raqynEZG+CX7zGmjEp2M8AoKdgoDc3hsDpyUfOmRVcszJikljWB+gd1HCiJYDruzif1Ar2XElP1Z0ehHjZl504wVabVR3VfuRawRel/jvuhHbnxEgmRrj7AseQdwgUU9t/Qnq1538Uaa0crjJbO8YpEE6zcs/UP1uRZJ93rBhlMo9ui2idPCtaiUYlELAsLEHK2Kjw19F2t2ffa2Iv0NRR5MlDXNjFOLJEbLovrylSs/kihC9eOzF+JopUh6qtcZ7NDgaVSDN2giZA8J+","a_responses":{"0":"JRsR9U7nyK6vjEJ1IbIc3tObCXVksaoqDbmLkTKXLMgysTw3CSQLWWiPLu6mK2/czfY2JtT/c09jhxsvWt4lqVs72WoPKpNhVMQ="},"nonrev_response":"B0M4FYrv3jergGlsiFQqXJ7VCfdM8gJG2q5bydFfs9Raw8FCuHDKjgFWaAn+OF7T7gdZ5tlBs6CgT6HdhLIucadOSbbQE+J87Q==","nonrev_proof":{"C_r":"G0A1Tz6jB1mEJJJp5/4Vk8B4JFWHztqspKa8Mn7IkzaJPBi6xKqIcvEj6JupoZOTgqrIOoZLKE2FzOt9zmgqWyEy+mZPchAEXDka5LB02o2Yals+zu4tDoINgOIjiSOXpByEJogGTkTUJxwv4Ug494nBf669QpeUKXiqFSD4hog=","C_u":"FknWq3GdaetxuMiC+hcgf/tb9MRy9lYR+ha4RwHdOOtzDwkGio4vSDV9WB4KcrRrdMfwMQ82doiAKlAKhMd4KCIx4g2S3lC8zuODx+SbgtbJKA+6UZ8n1jRqYFvGH9+BZWQbegVu8QZlbJUUsFciEszHjwkv0ac0QmkZajTybjU=","responses":{"beta":"ATdypWmAGl9U/JHtBupMcukq6J4641TDkUkGnLdphd/t5cVp6suEC7MXAoi+a+gZxKPuRyCqz/MB6rURmRR3l4oCuEbGVEcGqPxbCEWGx7vA3DTm1AVjohNEbLRu/xHGzW8kNEt/fzf0reU65eYneoEvFIYLxOd46hsK0ppfZn8hU5+umn8NiyMRr7GfH8/qmKrv7Ul62qVlvXJDKNhVbwBQToohT2xvPikLRVI4ZWWKuoUHqatenRzBfZyhyv14TG7ybVDA4X3+","delta":"ASQwxh5OZbSDunGm5HPVW8494idgYikMyC8400NT1Z+IIEWO3u8lS6rWO7rNF9SazLV9luP0Mw2qKmjP2eMHmdN5W9v5LnPAWHut0iAAnQhAymyYUFbQtka1Q2jAx3MnET9BqgE0AUZ3RmDmysv4BckkY8pyvY/rYD/rlG5KgtkZap5tniadWQu8w7ulsMJDbjc7YudlOw1hXaY64TZP34vX6EHSaa3vYy6+sA6RYD0OeshO6wQO9i87+Z1QIEiZBU2aeNdlEknK","epsilon":"Gmw3aqtwbEZrJ/ej9YdD1IE08DG8KjrIP7nmYZKVfwTexAb3mqrlrue7rXR3gfMeufIUmTZeIAkKTw4UcUBKaposc3NaOo8e+kmK0kZ9biLMC53bHZ36KZWrT5h20hwtcmMq4FG8NDh/o8lb2Ibbv8mf71opJyyVUUoEqIatZh1pVYvLVdi9Vxwc1P7tHrJQ8e9ppDqVHkVFYGNfVNGW3RXLKHr/tMsLbUIP9DjVY7M=","zeta":"BKdrESBubE/eKZ1m0eVY5VT5tYrbKA6ArB1o68PV1sMu8IhhOw745zv5KbIH56k/5+JJXv5Hyx3lY3qgI1w+h+w+/G+So7EzhXw4pqFkZy29Seq0xQM/Su6FMMC97auV3hRYX2VAaf+Qc2mb02cDMbKeX92p6+R6wj0KN/1Wel1IHb1GgMOvIURHddROJCpQI23MEU+uxJOb8TZQY/ICM2QFax/rd7FIawdGXnwYXY4="},"sacc":{"data":"omNNc2dYxaRiTnVYgFrKyTR/bZDCSwK1Kg9nNIdIkxX+/PkQAK6FaOT9YFAcEcG+rYqhdfVRWohl2KeBV8Fa1o8AfZ/MbvXcPiTh91p6PNX5OVBFHIGC5GDkLo9MMot6rJ/UZrtmhrhGHzX8c5Gf7xa01XB5MCZGjLKq6AbxTabyWedkhZpdnDN5Y5nSZUluZGV4AWRUaW1lGl4guwxpRXZlbnRIYXNoWCISIOeNpEe8g6DBBYWG1BJ4uA2tJGSt9etirxuxm+/R5W27Y1NpZ1hHMEUCIBNGB6X96tm/zyF9IaHiGt4WqISi+WK0DEEaq0iIEbRgAiEAxg/WLqsO8Aeis/B2embcwy5dBNNShLcMC2CKzIz9w6U=","pk":2}},"a_disclosed":{"1":"AwAKMwAaAAIIuOcAMwFiUVy4Y5PtnTFG","2":"ZHJybnJkaGpx"}}],"indices":[[{"cred":0,"attr":2}]],"nonce":"aXxcuAXX4c0qlD7rsgfsCw==","context":"AQ==","message":"message","timestamp":{"Time":1579203344,"ServerUrl":"https://keyshare.privacybydesign.foundation/atumd","Sig":{"Alg":"ed25519","Data":"6+RHBJ8SUjQu8UNVvVRntUnW7dPCWTbv5N5lC9lGsbcKj4NYMTiyKkD8Vp3c1170ZcWVDH4yIuabIaOJNDAFAw==","PublicKey":"MKdXxJxEWPRIwNP7SuvP0J/M/NV51VZvqCyO+7eDwJ8="}}}`

		sig := &irma.SignedMessage{}
		require.NoError(t, json.Unmarshal([]byte(j), sig))
		_, status, err := sig.Verify(client.Configuration, nil)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusValid, status)
	})

	t.Run("POSTUpdates", func(t *testing.T) {
		revocationConfiguration = revocationConf(t)
		revocationConfiguration.RevocationSettings[revocationTestCred].PostURLs = []string{
			"http://localhost:48680",
		}
		StartIrmaServer(t, false)
		defer func() {
			StopIrmaServer()
			revocationConfiguration = nil
		}()

		startRevocationServer(t)
		sacc1, err := revocationConfiguration.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, 2)
		require.NoError(t, err)
		acctime := sacc1.Accumulator.Time
		accindex := sacc1.Accumulator.Index
		time.Sleep(time.Second)

		// run scheduled update of accumulator, triggering a POST to our IRMA server
		revocationConfiguration.IrmaConfiguration.Scheduler.RunAll()
		// give request time to be processed
		time.Sleep(100 * time.Millisecond)

		// check that both the revocation server's and our IRMA server's configuration
		// agree on the same accumulator which has the same index but updated time
		sacc1, err = revocationConfiguration.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, 2)
		require.NoError(t, err)
		require.True(t, sacc1.Accumulator.Time > acctime)
		require.Equal(t, accindex, sacc1.Accumulator.Index)
		sacc2, err := irmaServerConfiguration.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, 2)
		require.NoError(t, err)
		require.Equal(t, sacc1, sacc2)

		// do a bogus revocation and see that the updated accumulator appears in both configurations
		revoke(t, "1", revocationConfiguration.IrmaConfiguration.Revocation, sacc2.Accumulator)
		time.Sleep(100 * time.Millisecond)
		sacc1, err = revocationConfiguration.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, 2)
		require.NoError(t, err)
		sacc2, err = irmaServerConfiguration.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, 2)
		require.NoError(t, err)
		require.Equal(t, sacc1, sacc2)
		require.Equal(t, accindex+1, sacc1.Accumulator.Index)
	})

	t.Run("OtherAccumulator", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		client, _ := revocationSetup(t)

		// Prepare key material
		conf := revocationConfiguration.IrmaConfiguration.Revocation
		sk, err := conf.Keys.PrivateKey(revocationTestCred.IssuerIdentifier(), 2)
		require.NoError(t, err)
		pk, err := conf.Keys.PublicKey(revocationTestCred.IssuerIdentifier(), 2)
		require.NoError(t, err)
		update, err := revocation.NewAccumulator(sk)
		require.NoError(t, err)
		acc, err := update.SignedAccumulator.UnmarshalVerify(pk)
		require.NoError(t, err)

		// Prepare session request
		request := revocationRequest()
		require.NoError(t, revocationConfiguration.IrmaConfiguration.Revocation.SetRevocationUpdates(request.Base()))
		events := request.RevocationUpdates[revocationTestCred][2].Events
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
		revoke(t, "2", conf, acc)
		request.RevocationUpdates = nil
		require.NoError(t, conf.SetRevocationUpdates(request.Base()))
		events = request.RevocationUpdates[revocationTestCred][2].Events
		require.Equal(t, uint64(2), events[len(events)-1].Index)

		// Try to verify against updated session request
		_, status, err := disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusInvalid, status)

		// Revoke another bogus credential, advancing index to 3, and make a new disclosure request
		// requiring a nonrevocation proof against the accumulator with index 3
		revoke(t, "3", conf, acc)
		newrequest := revocationRequest()
		require.NoError(t, conf.SetRevocationUpdates(newrequest.Base()))
		events = newrequest.RevocationUpdates[revocationTestCred][2].Events
		require.Equal(t, uint64(3), events[len(events)-1].Index)

		// Use newrequest to update client to index 3 and contruct a disclosure proof
		require.NoError(t, client.NonrevPrepare(newrequest))
		disclosure, _, err = client.Proofs(choice, newrequest)
		require.NoError(t, err)
		pacc, err = disclosure.Proofs[0].(*gabi.ProofD).NonRevocationProof.SignedAccumulator.UnmarshalVerify(pk)
		require.NoError(t, err)
		require.Equal(t, uint64(3), pacc.Index)

		// Check that the nonrevocation proof which uses a newer accumulator than ours verifies
		events = request.RevocationUpdates[revocationTestCred][2].Events
		require.Equal(t, uint64(2), events[len(events)-1].Index)
		_, status, err = disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusValid, status)

		// If the client does not send a nonrevocation proof the proof is invalid
		// clear revocation data from newrequest and create a disclosure from it
		newrequest.Revocation = nil
		newrequest.RevocationUpdates = nil
		disclosure, _, err = client.Proofs(choice, newrequest)
		require.NoError(t, err)
		// verify disclosure against request that still requests nonrevocation proofs
		_, status, err = disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusInvalid, status)
	})

	t.Run("ClientUpdate", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		client, _ := revocationSetup(t)

		conf := revocationConfiguration.IrmaConfiguration.Revocation

		sk, err := conf.Keys.PrivateKey(revocationTestCred.IssuerIdentifier(), 2)
		require.NoError(t, err)
		pk, err := conf.Keys.PublicKey(revocationTestCred.IssuerIdentifier(), 2)
		require.NoError(t, err)
		update, err := revocation.NewAccumulator(sk)
		require.NoError(t, err)
		acc, err := update.SignedAccumulator.UnmarshalVerify(pk)
		require.NoError(t, err)

		// Advance the accumulator by doing revocations so much that the client will need
		// to contact the RA to update its witness
		for i := 0; i < irma.RevocationDefaultEventCount+1; i++ {
			key := strconv.Itoa(i)
			revoke(t, key, conf, acc)
		}

		result := revocationSession(t, client, nil)
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
		result := revocationSession(t, client, nil, sessionOptionReuseServer)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
	})
}

// Helper functions

func revocationSigRequest() *irma.SignatureRequest {
	req := irma.NewSignatureRequest("message", revocationTestAttr)
	req.Revocation = []irma.CredentialTypeIdentifier{revocationTestAttr.CredentialTypeIdentifier()}
	return req
}

func revocationRequest() *irma.DisclosureRequest {
	req := irma.NewDisclosureRequest(revocationTestAttr)
	req.Revocation = []irma.CredentialTypeIdentifier{revocationTestAttr.CredentialTypeIdentifier()}
	return req
}

func revocationSession(t *testing.T, client *irmaclient.Client, request irma.SessionRequest, options ...sessionOption) *requestorSessionResult {
	if request == nil {
		request = revocationRequest()
	}
	result := requestorSessionHelper(t, request, client, options...)
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

func revoke(t *testing.T, key string, conf *irma.RevocationStorage, acc *revocation.Accumulator) {
	sk, err := conf.Keys.PrivateKey(revocationTestCred.IssuerIdentifier(), 2)
	require.NoError(t, err)
	witness, err := revocation.RandomWitness(sk, acc)
	require.NoError(t, err)
	require.NoError(t, conf.AddIssuanceRecord(&irma.IssuanceRecord{
		Key:        key,
		CredType:   revocationTestCred,
		PKCounter:  2,
		Attr:       (*irma.RevocationAttribute)(witness.E),
		Issued:     time.Now().UnixNano(),
		ValidUntil: time.Now().Add(1 * time.Hour).UnixNano(),
	}))
	require.NoError(t, conf.Revoke(revocationTestCred, key))
	sacc, err := conf.Accumulator(revocationTestCred, 2)
	require.NoError(t, err)
	*acc = *sacc.Accumulator
}

func revocationConf(t *testing.T) *server.Configuration {
	settings := map[irma.CredentialTypeIdentifier]*irma.RevocationSetting{
		revocationTestCred: {Mode: irma.RevocationModeServer},
	}
	irmaconf, err := irma.NewConfiguration(filepath.Join(testdata, "irma_configuration"), irma.ConfigurationOptions{
		RevocationDBConnStr: revocationDbStr,
		RevocationDBType:    revocationDbType,
		RevocationSettings:  settings,
	})
	require.NoError(t, err)
	require.NoError(t, irmaconf.ParseFolder())
	return &server.Configuration{
		Logger:               logger,
		DisableSchemesUpdate: true,
		SchemesPath:          filepath.Join(testdata, "irma_configuration"),
		RevocationSettings:   settings,
		IrmaConfiguration:    irmaconf,
		RevocationDBConnStr:  revocationDbStr,
		RevocationDBType:     revocationDbType,
	}
}

func startRevocationServer(t *testing.T) {
	var err error

	irma.Logger = logger

	// Connect to database and clear records from previous test runs
	g, err := gorm.Open(revocationDbType, revocationDbStr)
	require.NoError(t, err)
	require.NoError(t, g.DropTableIfExists((*irma.EventRecord)(nil)).Error)
	require.NoError(t, g.DropTableIfExists((*irma.AccumulatorRecord)(nil)).Error)
	require.NoError(t, g.DropTableIfExists((*irma.IssuanceRecord)(nil)).Error)
	require.NoError(t, g.AutoMigrate((*irma.EventRecord)(nil)).Error)
	require.NoError(t, g.AutoMigrate((*irma.AccumulatorRecord)(nil)).Error)
	require.NoError(t, g.AutoMigrate((*irma.IssuanceRecord)(nil)).Error)
	require.NoError(t, g.Close())

	if revocationConfiguration == nil {
		revocationConfiguration = revocationConf(t)
	}
	irmaconf := revocationConfiguration.IrmaConfiguration

	// Enable revocation for our credential type
	sk, err := irmaconf.Revocation.Keys.PrivateKeyLatest(revocationTestCred.IssuerIdentifier())
	require.NoError(t, err)
	require.NoError(t, irmaconf.Revocation.EnableRevocation(revocationTestCred, sk))

	// Start revocation server
	revocationServer, err = irmaserver.New(revocationConfiguration)
	revocationConfiguration = revocationConfiguration
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
