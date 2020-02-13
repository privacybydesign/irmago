package sessiontest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
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

	revocationPkCounter uint = 2
	revocationTestAttr       = irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	revocationTestCred       = revocationTestAttr.CredentialTypeIdentifier()
	revKeyshareTestAttr      = irma.NewAttributeTypeIdentifier("test.test.email.email")
	revKeyshareTestCred      = revKeyshareTestAttr.CredentialTypeIdentifier()
)

func testRevocation(t *testing.T, attr irma.AttributeTypeIdentifier) {
	defer test.ClearTestStorage(t)
	client, handler := revocationSetup(t)
	defer stopRevocationServer()
	credid := attr.CredentialTypeIdentifier()

	// issue second credential which overwrites the first one, as our credtype is a singleton
	// this is ok, as we use cred0 only to revoke it, to see if cred1 keeps working
	issrequest := revocationIssuanceRequest(t, credid)
	issrequest.Credentials[0].RevocationKey = "cred1"
	result := requestorSessionHelper(t, issrequest, client)
	require.Nil(t, result.Err)

	// perform disclosure session (of cred1) with nonrevocation proof
	logger.Info("step 1")
	request := revocationRequest(attr)
	result = revocationSession(t, client, request)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)
	require.NotEmpty(t, result.Disclosed[0])
	require.NotNil(t, result.Disclosed[0][0])
	// not included: window within which nonrevocation is not guaranteed, as it is within tolerance
	require.True(t, result.Disclosed[0][0].NotRevoked)
	require.Nil(t, result.Disclosed[0][0].NotRevokedBefore)

	// revoke cred0
	logger.Info("step 2")
	require.NoError(t, revocationServer.Revoke(revocationTestCred, "cred0", time.Time{}))

	// perform another disclosure session with nonrevocation proof to see that cred1 still works
	// client updates its witness to the new accumulator first
	logger.Info("step 3")
	result = revocationSession(t, client, request)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)

	// revoke cred1
	logger.Info("step 4")
	require.NoError(t, revocationServer.Revoke(credid, "cred1", time.Time{}))

	// try to perform session with revoked credential
	// client notices that his credential is revoked and aborts
	logger.Info("step 5")
	result = revocationSession(t, client, request, sessionOptionUnsatisfiableRequest)
	require.NotEmpty(t, result.Missing)
	// client revocation callback was called
	require.NotNil(t, handler.(*TestClientHandler).revoked)
	require.Equal(t, credid, handler.(*TestClientHandler).revoked.Type)
	// credential is no longer suggested as candidate
	candidates, missing, err := client.Candidates(
		revocationRequest(attr).Base(),
		irma.AttributeDisCon{{{Type: attr}}},
	)
	require.NoError(t, err)
	require.Empty(t, candidates)
	require.NotEmpty(t, missing)
}

func TestRevocationAll(t *testing.T) {
	t.Run("Revocation", func(t *testing.T) {
		testRevocation(t, revocationTestAttr)
	})

	t.Run("RevocationServerSessions", func(t *testing.T) {
		revocationConfiguration = revocationConf(t)
		startRevocationServer(t, true)
		defer func() {
			stopRevocationServer()
			revocationConfiguration = nil
		}()

		// Make the session functions use our revocation server
		irmaServer = revocationServer

		// issue a MijnOverheid.root instance with revocation enabled
		client, _ := parseStorage(t)
		request := revocationIssuanceRequest(t, revocationTestCred)
		result := requestorSessionHelper(t, request, client, sessionOptionReuseServer)
		require.Nil(t, result.Err)

		// do disclosure and signature sessions
		result = revocationSession(t, client, nil, sessionOptionReuseServer)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
		result = revocationSession(t, client, revocationSigRequest(), sessionOptionReuseServer)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)

		// revoke
		require.NoError(t, revocationServer.Revoke(
			revocationTestCred,
			request.Credentials[0].RevocationKey,
			time.Time{}),
		)

		// try another disclosure
		result = revocationSession(t, client, nil, sessionOptionUnsatisfiableRequest, sessionOptionReuseServer)
		require.NotEmpty(t, result.Missing)
	})

	t.Run("AttributeBasedSignature", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		client, _ := revocationSetup(t)
		defer stopRevocationServer()

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

		startRevocationServer(t, true)
		defer stopRevocationServer()
		sacc1, err := revocationConfiguration.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, revocationPkCounter)
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
		sacc1, err = revocationConfiguration.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.True(t, sacc1.Accumulator.Time > acctime)
		require.Equal(t, accindex, sacc1.Accumulator.Index)
		sacc2, err := irmaServerConfiguration.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.Equal(t, sacc1, sacc2)

		// do a bogus revocation and see that the updated accumulator appears in both configurations
		fakeRevocation(t, "1", revocationConfiguration.IrmaConfiguration.Revocation, sacc2.Accumulator)
		time.Sleep(100 * time.Millisecond)
		sacc1, err = revocationConfiguration.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		sacc2, err = irmaServerConfiguration.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.Equal(t, sacc1, sacc2)
		require.Equal(t, accindex+1, sacc1.Accumulator.Index)
	})

	t.Run("NoKnownAccumulator", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		client, _ := revocationSetup(t)

		// stop revocation server so the verifier cannot fetch revocation state
		stopRevocationServer()

		result := revocationSession(t, client, nil, sessionOptionIgnoreError)
		require.Equal(t, server.StatusCancelled, result.Status)
		require.NotNil(t, result.Err)
		require.Equal(t, result.Err.ErrorName, string(server.ErrorRevocation.Type))
	})

	t.Run("OtherAccumulator", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		client, _ := revocationSetup(t)
		defer stopRevocationServer()

		// Prepare key material
		conf := revocationConfiguration.IrmaConfiguration.Revocation
		sk, err := conf.Keys.PrivateKey(revocationTestCred.IssuerIdentifier(), revocationPkCounter)
		require.NoError(t, err)
		pk, err := conf.Keys.PublicKey(revocationTestCred.IssuerIdentifier(), revocationPkCounter)
		require.NoError(t, err)
		update, err := revocation.NewAccumulator(sk)
		require.NoError(t, err)
		acc, err := update.SignedAccumulator.UnmarshalVerify(pk)
		require.NoError(t, err)

		// Prepare session request
		request := revocationRequest(revocationTestAttr)
		require.NoError(t, conf.SetRevocationUpdates(request.Base()))
		events := request.Revocation[revocationTestCred].Updates[revocationPkCounter].Events
		require.Equal(t, uint64(0), events[len(events)-1].Index)

		// Construct disclosure proof with nonrevocation proof against accumulator with index 0
		candidates, missing, err := client.CheckSatisfiability(request)
		require.NoError(t, err)
		require.Empty(t, missing)
		choice := &irma.DisclosureChoice{Attributes: [][]*irma.AttributeIdentifier{candidates[0][0]}}
		disclosure, _, err := client.Proofs(choice, request)
		require.NoError(t, err)
		proofAcc, err := disclosure.Proofs[0].(*gabi.ProofD).NonRevocationProof.SignedAccumulator.UnmarshalVerify(pk)
		require.NoError(t, err)
		require.Equal(t, uint64(0), proofAcc.Index)

		// Revoke a bogus credential, advancing accumulator index to 1, and update the session request,
		// indicated that we expect a nonrevocation proof wrt accumulator with index 1
		fakeRevocation(t, "1", conf, acc)
		request.Revocation = irma.NonRevocationParameters{revocationTestCred: {}}
		require.NoError(t, conf.SetRevocationUpdates(request.Base()))
		events = request.Revocation[revocationTestCred].Updates[revocationPkCounter].Events
		require.Equal(t, uint64(1), events[len(events)-1].Index)

		// Try to verify against updated session request
		_, status, err := disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusInvalid, status)

		// Revoke another bogus credential, advancing index to 2, and make a new disclosure request
		// requiring a nonrevocation proof against the accumulator with index 2
		fakeRevocation(t, "2", conf, acc)
		newrequest := revocationRequest(revocationTestAttr)
		require.NoError(t, conf.SetRevocationUpdates(newrequest.Base()))
		events = newrequest.Revocation[revocationTestCred].Updates[revocationPkCounter].Events
		require.Equal(t, uint64(2), events[len(events)-1].Index)

		// Use newrequest to update client to index 2 and contruct a disclosure proof
		require.NoError(t, client.NonrevPrepare(newrequest))
		disclosure, _, err = client.Proofs(choice, newrequest)
		require.NoError(t, err)
		proofAcc, err = disclosure.Proofs[0].(*gabi.ProofD).NonRevocationProof.SignedAccumulator.UnmarshalVerify(pk)
		require.NoError(t, err)
		require.Equal(t, uint64(2), proofAcc.Index)

		// Check that the nonrevocation proof which uses a newer accumulator than ours verifies
		events = request.Revocation[revocationTestCred].Updates[revocationPkCounter].Events
		require.Equal(t, uint64(1), events[len(events)-1].Index)
		_, status, err = disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusValid, status)

		// If the client does not send a nonrevocation proof the proof is invalid
		// clear revocation data from newrequest and create a disclosure from it
		newrequest.Revocation = nil
		disclosure, _, err = client.Proofs(choice, newrequest)
		require.NoError(t, err)
		// verify disclosure against request that still requests nonrevocation proofs
		_, status, err = disclosure.Verify(client.Configuration, request)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusInvalid, status)
	})

	t.Run("ClientSessionServerUpdate", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		client, _ := revocationSetup(t)
		defer stopRevocationServer()

		conf := revocationConfiguration.IrmaConfiguration.Revocation
		sacc, err := conf.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)

		// Advance the accumulator by doing fake revocations so much that the client will need
		// to contact the RA to update its witness, concurrently fetching a number of event intervals
		fakeMultipleRevocations(t, 116, conf, sacc.Accumulator)

		result := revocationSession(t, client, nil)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
	})

	t.Run("ClientAutoServerUpdate", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		client, _ := revocationSetup(t) // revocation server is stopped manually below

		// Advance the accumulator by performing a few revocations
		conf := revocationConfiguration.IrmaConfiguration.Revocation
		sacc, err := conf.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		fakeMultipleRevocations(t, irma.RevocationParameters.DefaultUpdateEventCount+3, conf, sacc.Accumulator)

		// Client updates at revocation server
		require.NoError(t, client.NonrevUpdateFromServer(revocationTestCred))

		// Start an IRMA server and let it update at revocation server
		StartIrmaServer(t, false)
		defer StopIrmaServer()
		conf = irmaServerConfiguration.IrmaConfiguration.Revocation
		require.NoError(t, conf.SyncDB(revocationTestCred))

		// IRMA server's accumulator is now at the same index as that of the revocation server
		sacc, err = conf.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		pk, err := conf.Keys.PublicKey(revocationTestCred.IssuerIdentifier(), revocationPkCounter)
		require.NoError(t, err)
		acc, err := sacc.UnmarshalVerify(pk)
		require.NoError(t, err)
		require.Equal(t, irma.RevocationParameters.DefaultUpdateEventCount+3, acc.Index)

		// Stop revocation server and do session
		// IRMA server is at index 3, so if the client would not be it would need to update, which would fail
		stopRevocationServer()
		result := revocationSession(t, client, nil, sessionOptionReuseServer)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
	})

	t.Run("SameIrmaServer", func(t *testing.T) {
		StartIrmaServer(t, false)
		defer StopIrmaServer()
		defer test.ClearTestStorage(t)

		// issue a credential, populating irmaServer's revocation memdb
		client, _ := revocationSetup(t, sessionOptionReuseServer)
		defer stopRevocationServer()

		// disable serving revocation updates in revocation server
		require.NoError(t, revocationConfiguration.IrmaConfiguration.Revocation.Close())

		// do disclosure session, using irmaServer's memdb
		result := revocationSession(t, client, nil, sessionOptionReuseServer)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
	})

	t.Run("RestartRevocationServer", func(t *testing.T) {
		revocationConfiguration = nil
		startRevocationServer(t, true)
		rev := revocationConfiguration.IrmaConfiguration.Revocation
		sacc1, err := rev.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.NotNil(t, sacc1)
		require.NotNil(t, sacc1.Accumulator)
		require.Equal(t, uint64(0), sacc1.Accumulator.Index)

		fakeRevocation(t, "1", rev, sacc1.Accumulator)
		sacc2, err := rev.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.NotNil(t, sacc2)
		require.NotNil(t, sacc2.Accumulator)
		require.Equal(t, uint64(1), sacc2.Accumulator.Index)

		stopRevocationServer()
		revocationConfiguration = nil

		startRevocationServer(t, false)
		defer stopRevocationServer()
		rev = revocationConfiguration.IrmaConfiguration.Revocation
		sacc3, err := rev.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.Equal(t, sacc2, sacc3)

		update, err := rev.UpdateLatest(revocationTestCred, 10, &revocationPkCounter)
		require.NoError(t, err)
		pk, err := rev.Keys.PublicKey(revocationTestCred.IssuerIdentifier(), revocationPkCounter)
		require.NoError(t, err)
		require.Contains(t, update, revocationPkCounter)
		_, err = update[revocationPkCounter].Verify(pk)
		require.NoError(t, err)
		require.Equal(t, 2, len(update[revocationPkCounter].Events))
	})

	t.Run("DeleteExpiredIssuanceRecords", func(t *testing.T) {
		startRevocationServer(t, true)
		defer stopRevocationServer()

		// Insert expired issuance record
		rev := revocationConfiguration.IrmaConfiguration.Revocation
		require.NoError(t, rev.AddIssuanceRecord(&irma.IssuanceRecord{
			Key:        "1",
			CredType:   revocationTestCred,
			PKCounter:  &revocationPkCounter,
			Attr:       (*irma.RevocationAttribute)(big.NewInt(42)),
			Issued:     time.Now().Add(-2 * time.Hour).UnixNano(),
			ValidUntil: time.Now().Add(-1 * time.Hour).UnixNano(),
		}))
		// Check existence of insterted record
		rec, err := rev.IssuanceRecords(revocationTestCred, "1", time.Time{})
		require.NoError(t, err)
		require.NotEmpty(t, rec)

		// Run jobs, triggering DELETE
		revocationConfiguration.IrmaConfiguration.Scheduler.RunAll()

		// Check that issuance record is gone
		rec, err = rev.IssuanceRecords(revocationTestCred, "1", time.Time{})
		require.Equal(t, irma.ErrUnknownRevocationKey, err)
	})

	t.Run("RevokeMany", func(t *testing.T) {
		startRevocationServer(t, true)
		defer stopRevocationServer()
		rev := revocationConfiguration.IrmaConfiguration.Revocation
		sacc, err := rev.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.NotNil(t, sacc)
		require.NotNil(t, sacc.Accumulator)

		// Insert a bunch of issuance records with the same revocation key
		insertIssuanceRecord(t, "1", rev, sacc.Accumulator)
		insertIssuanceRecord(t, "1", rev, sacc.Accumulator)
		insertIssuanceRecord(t, "1", rev, sacc.Accumulator)
		r, err := rev.IssuanceRecords(revocationTestCred, "1", time.Time{})
		require.NoError(t, err)
		require.Len(t, r, 3)

		// revoke just the first record, should be two left afterwards
		require.NoError(t, rev.Revoke(revocationTestCred, "1", time.Unix(0, r[0].Issued)))
		r2, err := rev.IssuanceRecords(revocationTestCred, "1", time.Time{})
		require.NoError(t, err)
		require.Len(t, r2, 2)

		// revoke all remaining records, should be none left afterwards
		require.NoError(t, rev.Revoke(revocationTestCred, "1", time.Time{}))
		r2, err = rev.IssuanceRecords(revocationTestCred, "1", time.Time{})
		require.Equal(t, irma.ErrUnknownRevocationKey, err)

		// fetch and verify update message
		update, err := rev.UpdateLatest(revocationTestCred, 10, &revocationPkCounter)
		require.NoError(t, err)
		require.Contains(t, update, revocationPkCounter)
		pk, err := rev.Keys.PublicKey(revocationTestCred.IssuerIdentifier(), revocationPkCounter)
		require.NoError(t, err)
		_, err = update[revocationPkCounter].Verify(pk)
		require.NoError(t, err)

		// check that the events of the update message match our issuance records
		require.Len(t, update[revocationPkCounter].Events, 4)
		require.Equal(t, 0, update[revocationPkCounter].Events[0].E.Cmp(big.NewInt(1)))
		for i := 0; i < 3; i++ {
			require.Equal(t, 0, update[revocationPkCounter].Events[i+1].E.Cmp((*big.Int)(r[i].Attr)))
		}
	})

	t.Run("RevocationTolerance", func(t *testing.T) {
		defer test.ClearTestStorage(t)
		client, _ := revocationSetup(t)
		defer stopRevocationServer()
		start := time.Now()

		result := revocationSession(t, client, nil)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
		require.NotEmpty(t, result.Disclosed[0])
		require.NotNil(t, result.Disclosed[0][0])
		// not included: window within which nonrevocation is not guaranteed, as it is within tolerance
		require.Nil(t, result.Disclosed[0][0].NotRevokedBefore)

		request := revocationRequest(revocationTestAttr)
		request.Revocation[revocationTestCred].Tolerance = 1
		result = revocationSession(t, client, request, sessionOptionClientWait)

		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
		require.NotEmpty(t, result.Disclosed[0])
		require.NotNil(t, result.Disclosed[0][0])
		require.True(t, result.Disclosed[0][0].NotRevoked)
		require.NotNil(t, result.Disclosed[0][0].NotRevokedBefore)
		require.True(t, result.Disclosed[0][0].NotRevokedBefore.After(irma.Timestamp(start)))
	})

	t.Run("Cache", func(t *testing.T) {
		startRevocationServer(t, true)
		defer stopRevocationServer()
		rev := revocationConfiguration.IrmaConfiguration.Revocation
		sacc, err := rev.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)

		// ensure enough events esists for /events endpoint
		fakeMultipleRevocations(t, 17, rev, sacc.Accumulator)

		// check /events endpoint
		url := revocationConfiguration.IrmaConfiguration.CredentialTypes[revocationTestCred].RevocationServers[0] +
			"/revocation/events/irma-demo.MijnOverheid.root/2/0/16"
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		res, err := (&http.Client{}).Do(req)
		require.NoError(t, err)
		require.Equal(t,
			fmt.Sprintf("max-age=%d", irma.RevocationParameters.EventsCacheMaxAge),
			res.Header.Get("Cache-Control"),
		)

		// check /update endpoint
		url = revocationConfiguration.IrmaConfiguration.CredentialTypes[revocationTestCred].RevocationServers[0] +
			"revocation/update/irma-demo.MijnOverheid.root/16"
		req, err = http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		res, err = (&http.Client{}).Do(req)
		require.NoError(t, err)
		require.Equal(t,
			fmt.Sprintf("max-age=%d", irma.RevocationParameters.AccumulatorUpdateInterval),
			res.Header.Get("Cache-Control"),
		)
	})

	t.Run("NonRevocationAwareCredential", func(t *testing.T) {
		client, _ := parseStorage(t)

		// Start irma server and hackily temporarily disable revocation for our credtype
		// by editing its irma.Configuration instance
		StartIrmaServer(t, false)
		defer StopIrmaServer()
		credtyp := irmaServerConfiguration.IrmaConfiguration.CredentialTypes[revocationTestCred]
		servers := credtyp.RevocationServers // save it for re-enabling revocation below
		credtyp.RevocationServers = nil

		// Issue non-revocation-aware credential instance
		result := requestorSessionHelper(t, irma.NewIssuanceRequest([]*irma.CredentialRequest{{
			CredentialTypeID: revocationTestCred,
			Attributes: map[string]string{
				"BSN": "299792458",
			},
		}}), client, sessionOptionReuseServer)
		require.Nil(t, result.Err)

		// Restore revocation setup
		credtyp.RevocationServers = servers
		startRevocationServer(t, true)
		defer stopRevocationServer()

		// Try disclosure session requiring nonrevocation proof
		// client notices it has no revocation-aware credential instance and aborts
		result = revocationSession(t, client, nil, sessionOptionReuseServer, sessionOptionUnsatisfiableRequest)
		require.NotEmpty(t, result.Missing)
	})
}

// Helper functions

func revocationSigRequest() *irma.SignatureRequest {
	req := irma.NewSignatureRequest("message", revocationTestAttr)
	req.ProtocolVersion = &irma.ProtocolVersion{Major: 2, Minor: 6}
	req.Revocation = irma.NonRevocationParameters{revocationTestCred: {}}
	return req
}

func revocationIssuanceRequest(t *testing.T, credid irma.CredentialTypeIdentifier) *irma.IssuanceRequest {
	switch credid {
	case revocationTestCred:
		return irma.NewIssuanceRequest([]*irma.CredentialRequest{{
			RevocationKey:    "cred0",
			CredentialTypeID: credid,
			Attributes: map[string]string{
				"BSN": "299792458",
			},
		}})
	case revKeyshareTestCred:
		return irma.NewIssuanceRequest([]*irma.CredentialRequest{{
			RevocationKey:    "cred0",
			CredentialTypeID: credid,
			Attributes: map[string]string{
				"email": "irma@example.com",
			},
		}})
	default:
		t.Fatal("unsupportec credential type")
		return nil
	}
}

func revocationRequest(attr irma.AttributeTypeIdentifier) *irma.DisclosureRequest {
	req := irma.NewDisclosureRequest(attr)
	req.ProtocolVersion = &irma.ProtocolVersion{Major: 2, Minor: 6}
	req.Revocation = irma.NonRevocationParameters{attr.CredentialTypeIdentifier(): {}}
	return req
}

func revocationSession(t *testing.T, client *irmaclient.Client, request irma.SessionRequest, options ...sessionOption) *requestorSessionResult {
	if request == nil {
		request = revocationRequest(revocationTestAttr)
	}
	result := requestorSessionHelper(t, request, client, options...)
	if processOptions(options...)&sessionOptionIgnoreError == 0 && result.SessionResult != nil {
		require.Nil(t, result.Err)
	}
	return result
}

// revocationSetup sets up an irmaclient with a revocation-enabled credential, constants, and revocation key material.
func revocationSetup(t *testing.T, options ...sessionOption) (*irmaclient.Client, irmaclient.ClientHandler) {
	startRevocationServer(t, true)

	// issue a MijnOverheid.root instance with revocation enabled
	client, handler := parseStorage(t)
	result := requestorSessionHelper(t, revocationIssuanceRequest(t, revocationTestCred), client, options...)
	require.Nil(t, result.Err)

	return client, handler
}

func insertIssuanceRecord(t *testing.T, key string, conf *irma.RevocationStorage, acc *revocation.Accumulator) {
	sk, err := conf.Keys.PrivateKey(revocationTestCred.IssuerIdentifier(), revocationPkCounter)
	require.NoError(t, err)
	witness, err := revocation.RandomWitness(sk, acc)
	require.NoError(t, err)
	require.NoError(t, conf.AddIssuanceRecord(&irma.IssuanceRecord{
		Key:        key,
		CredType:   revocationTestCred,
		PKCounter:  &revocationPkCounter,
		Attr:       (*irma.RevocationAttribute)(witness.E),
		Issued:     time.Now().UnixNano(),
		ValidUntil: time.Now().Add(1 * time.Hour).UnixNano(),
	}))
}

func fakeRevocation(t *testing.T, key string, conf *irma.RevocationStorage, acc *revocation.Accumulator) {
	insertIssuanceRecord(t, key, conf, acc)
	require.NoError(t, conf.Revoke(revocationTestCred, key, time.Time{}))
	sacc, err := conf.Accumulator(revocationTestCred, revocationPkCounter)
	require.NoError(t, err)
	*acc = *sacc.Accumulator
}

func fakeMultipleRevocations(t *testing.T, count uint64, conf *irma.RevocationStorage, acc *revocation.Accumulator) {
	sk, err := conf.Keys.PrivateKey(revocationTestCred.IssuerIdentifier(), revocationPkCounter)
	require.NoError(t, err)
	events := make([]*revocation.Event, count)

	u, err := conf.UpdateLatest(revocationTestCred, 1, &revocationPkCounter)
	require.NoError(t, err)
	require.NotEmpty(t, u[revocationPkCounter].Events)
	event := u[revocationPkCounter].Events[len(u[revocationPkCounter].Events)-1]

	for i := uint64(0); i < count; i++ {
		witness, err := revocation.RandomWitness(sk, acc)
		require.NoError(t, err)
		acc, event, err = acc.Remove(sk, witness.E, event)
		require.NoError(t, err)
		events[i] = event
	}

	update, err := revocation.NewUpdate(sk, acc, events)
	require.NoError(t, err)
	require.NoError(t, conf.AddUpdate(revocationTestCred, update))
}

func revocationConf(t *testing.T) *server.Configuration {
	return &server.Configuration{
		URL:                  "http://localhost:48683",
		Logger:               logger,
		DisableSchemesUpdate: true,
		SchemesPath:          filepath.Join(testdata, "irma_configuration"),
		RevocationSettings: map[irma.CredentialTypeIdentifier]*irma.RevocationSetting{
			revocationTestCred:  {ServerMode: true},
			revKeyshareTestCred: {ServerMode: true},
		},
		RevocationDBConnStr: revocationDbStr,
		RevocationDBType:    revocationDbType,
	}
}

func startRevocationServer(t *testing.T, droptables bool) {
	var err error

	irma.Logger = logger

	// Connect to database and clear records from previous test runs
	if droptables {
		g, err := gorm.Open(revocationDbType, revocationDbStr)
		require.NoError(t, err)
		require.NoError(t, g.DropTableIfExists((*irma.EventRecord)(nil)).Error)
		require.NoError(t, g.DropTableIfExists((*irma.AccumulatorRecord)(nil)).Error)
		require.NoError(t, g.DropTableIfExists((*irma.IssuanceRecord)(nil)).Error)
		require.NoError(t, g.AutoMigrate((*irma.EventRecord)(nil)).Error)
		require.NoError(t, g.AutoMigrate((*irma.AccumulatorRecord)(nil)).Error)
		require.NoError(t, g.AutoMigrate((*irma.IssuanceRecord)(nil)).Error)
		require.NoError(t, g.Close())
	}

	// Start revocation server
	if revocationConfiguration == nil {
		revocationConfiguration = revocationConf(t)
	}
	revocationServer, err = irmaserver.New(revocationConfiguration)
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
	revocationConfiguration = nil
}
