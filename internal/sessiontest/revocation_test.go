//go:build !local_tests
// +build !local_tests

package sessiontest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-co-op/gocron"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/revocation"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/stretchr/testify/require"
)

var (
	revocationDbStrs = map[string]string{
		"postgres":  "host=127.0.0.1 port=5432 user=testuser dbname=test password='testpassword' sslmode=disable",
		"mysql":     "testuser:testpassword@tcp(127.0.0.1)/test",
		"sqlserver": "sqlserver://testuser:testpassword@127.0.0.1:1433?database=test",
	}

	revocationPkCounter uint = 2
)

func testRevocation(t *testing.T, attr irma.AttributeTypeIdentifier, client *irmaclient.Client, handler irmaclient.ClientHandler, server *irmaserver.Server) {
	// issue first credential
	credid := attr.CredentialTypeIdentifier()
	result := doSession(t, revocationIssuanceRequest(t, credid), client, nil, nil, nil, nil)
	require.Nil(t, result.Err)

	// Issue second credential, which may overwrite the first one in case of singleton credtypes.
	// This is ok, as we use the first credential only to revoke it, to see if the second credential
	// keeps working.
	issrequest := revocationIssuanceRequest(t, credid)
	key := issrequest.Credentials[0].RevocationKey
	issrequest.Credentials[0].RevocationKey = key + "2"
	result = doSession(t, issrequest, client, nil, nil, nil, nil)
	require.Nil(t, result.Err)

	// perform disclosure session (of key2) with nonrevocation proof
	logger.Info("step 1")
	request := revocationRequest(attr)
	result = revocationSession(t, client, request, nil)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)
	require.NotEmpty(t, result.Disclosed[0])
	require.NotNil(t, result.Disclosed[0][0])
	// not included: window within which nonrevocation is not guaranteed, as it is within tolerance
	require.True(t, result.Disclosed[0][0].NotRevoked)
	require.Nil(t, result.Disclosed[0][0].NotRevokedBefore)

	// revoke key
	logger.Info("step 2")
	require.NoError(t, server.Revoke(credid, key, time.Time{}))

	// perform another disclosure session with nonrevocation proof to see that key2 still works
	// client updates its witness to the new accumulator first
	logger.Info("step 3")
	result = revocationSession(t, client, request, nil)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)

	// revoke key2
	logger.Info("step 4")
	require.NoError(t, server.Revoke(credid, key+"2", time.Time{}))

	// try to perform session with revoked credential
	// client notices that his credential is revoked and aborts
	logger.Info("step 5")
	result = revocationSession(t, client, request, nil, optionUnsatisfiableRequest)
	require.NotEmpty(t, result.Missing)
	require.NotNil(t, result.Dismisser)
	result.Dismisser.Dismiss()
	// client revocation callback was called
	require.NotNil(t, handler.(*TestClientHandler).revoked)
	require.Equal(t, credid, handler.(*TestClientHandler).revoked.Type)
	// credential is no longer available as candidate
	_, satisfiable, err := client.Candidates(request)
	require.NoError(t, err)
	require.False(t, satisfiable)
}

func TestRevocationPostgres(t *testing.T) {
	testRevocationAll(t, "postgres")
}

func TestRevocationMySQL(t *testing.T) {
	testRevocationAll(t, "mysql")
}

func TestRevocationSQLServer(t *testing.T) {
	testRevocationAll(t, "sqlserver")
}

func testRevocationAll(t *testing.T, dbType string) {
	t.Run("Revocation", func(t *testing.T) {
		revServer := startRevocationServer(t, true, dbType)
		defer revServer.Stop()
		client, handler := parseStorage(t)
		defer test.ClearTestStorage(t, client, handler.storage)
		testRevocation(t, revocationTestAttr, client, handler, revServer.irma)
	})

	t.Run("RevocationServerSessions", func(t *testing.T) {
		revServer := startRevocationServer(t, true, dbType)
		defer revServer.Stop()

		// issue a MijnOverheid.root instance with revocation enabled
		client, handler := parseStorage(t)
		defer test.ClearTestStorage(t, client, handler.storage)
		request := revocationIssuanceRequest(t, revocationTestCred)
		result := doSession(t, request, client, revServer, nil, nil, nil)
		require.Nil(t, result.Err)

		// do disclosure and signature sessions
		result = revocationSession(t, client, nil, revServer)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
		result = revocationSession(t, client, revocationSigRequest(), revServer)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)

		// revoke
		require.NoError(t, revServer.irma.Revoke(
			revocationTestCred,
			request.Credentials[0].RevocationKey,
			time.Time{}),
		)

		// try another disclosure
		result = revocationSession(t, client, nil, revServer, optionUnsatisfiableRequest)
		require.NotEmpty(t, result.Missing)
	})

	t.Run("MixRevocationNonRevocation", func(t *testing.T) {
		revServer, client, handler := revocationSetup(t, nil, dbType)
		defer test.ClearTestStorage(t, client, handler.storage)
		defer revServer.Stop()

		request := revocationRequest(revocationTestAttr)
		request.Disclose[0][0] = append(request.Disclose[0][0], irma.NewAttributeRequest("irma-demo.RU.studentCard.studentID"))
		result := revocationSession(t, client, request, nil)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)

		request = revocationRequest(revocationTestAttr)
		request.Disclose = append(request.Disclose, irma.AttributeDisCon{{irma.NewAttributeRequest("irma-demo.RU.studentCard.studentID")}})
		result = revocationSession(t, client, request, nil)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
	})

	t.Run("AttributeBasedSignature", func(t *testing.T) {
		irmaServer := StartIrmaServer(t, nil)
		defer irmaServer.Stop()

		revServer, client, handler := revocationSetup(t, nil, dbType)
		defer test.ClearTestStorage(t, client, handler.storage)
		defer revServer.Stop()

		request := revocationSigRequest()
		result := revocationSession(t, client, request, irmaServer)
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
		client, handler := parseStorage(t)
		defer test.ClearTestStorage(t, client, handler.storage)

		j := `{"@context":"https://irma.app/ld/signature/v2","signature":[{"c":"It0yT9OjFotXN0tUMZKaEo43WOugqv6GVlG0/WP03jE=","A":"WkB+1nj1vT5kdq7Q9hjoNlndvGtKoaLB/Ugs0rvjqMYBhCgXq19h/5ThesxLysVH15yPbVh+rlaZRYWfqKRvXs1z4aBhcHi+1hBB1JXENAnBpdfEQvZtzfz5I1fOIqEFkY+5kU6t7wkGj4QM7OhjHsquihoCnTT/vp6VIpYZnfI=","e_response":"wL+gwLa/myLy8HdilGKor4/Kfake1PvY0ZYfZyY4LZiO41hLC17MD6vYSTrsblkzuWO6ai3WsCIW","v_response":"DI3bQp04GNAIF7ylUqElTTwh4aLuytQOzFYVSGwtzlX8YGxsUZzOaLo0iCc2MKtqCiYBJp1LsQNW9f1lKub31ML2Xu53wYw99tGuqngl1wJaqHI6rQCSLlxTgyXzj0CJ6SXNkWEIBFpPcauMLnRG4eD20WtQ8oyFHQjfRrm0hZKMNlqb8CQOdDZNL8POnUHlap9FhFrM7IVCjUuOf8XHtgXo5PaFh7Gzj1dkyZKdofvM51hVvLi4T+qf4b9F5XZV4b1fVmmU70Sm/BA3eaonXv67vk5XBb8XW7cbLGtUqtg8tO/T5Cpdnw/fGGn0g61CJ11RmuEqbFa0uwp/rhIs","a_responses":{"0":"dBDhQmFfrCLFwIUL92UudSsk4TdtCj/bfpl6wBNjV4fD1upB8ViXSn8mQMMCm7SoOM8/9qf/aWw0vzuv4JAWe03N6gqdMTlNbtI=","3":"ZqbH95Dc56+9LzG9AJi7jZX1rEzv5AKtbrom+DVuF6k59dAahz77huVos/SYSSSGsQl6yh8oUinaGhyel9hgPYZXOREA8OfG"},"a_disclosed":{"1":"AwAKOQAaAAIIuOcAMwFiUVy4Y5PtnTFG","2":"ZHJybnJkaGpx"},"nonrev_proof":{"C_r":"bi6ByaP46KtZaJEril4vMky1sbQr3/tBIo/yra1KTNV7vWIPc7IEusYLaTWRIfgdASYFgZg7MWgPPqcvzzrx8M0tjUEEayQeeWKwuKm0pL3lHOaZY+IuCzQXdh2lEZxGPlTM0gFlWE7JOywvt4rC6b8CThVgropZBgc8PJBPjWs=","C_u":"udtOV/dALqU2ab5GRzy7Ps6F10g6XyU7aj0ij4D7G55UQu/9Dxy562VLcmJQWGVhW63EuyHYKpEWEcQsi81UJV+eYXI7obiKJ0UJE8L5dLiEjR5+Nbwm+RsyJ+75daOpkerf/gpyECroiTsYtIl6u5Yz5uP9DgfyzKqjpSYzSY4=","responses":{"alpha":"ZqbH95Dc56+9LzG9AJi7jZX1rEzv5AKtbrom+DVuF6k59dAahz77huVos/SYSSSGsQl6yh8oUinaGhyel9hgPYZXOREA8OfG","beta":"68eyUujDJDUv8P3ooM2yMLuHqTcAJERyVW7bQGF4MCfKRF7iIQz1bNr4bXWWw9QPBcKbryQjAQpUzPfIsWd0c9sjXvE6AdRj9KHWTo6WPbGB59vemK2hHf/WI88mysy+/zskEj1TZVJSBjqaGXcRLvV5HsAvgI3IlYAfdB2F+EE6ZSLuH3nkYVhFOlw15lI0mU3FnKwaeT9Tm+SbW2Zzy1VoFdaK+wkxACmYD/6hFhFH5rP7SvRMZ2aqjDa1I0I8GUxTnv7HZdo=","delta":"AQgE6fY7pFpC8iRrI9PhmfBNf0dQAYWNf5Jlm3Q7QhAm4BA9v7EzM0c8nUCcLTA39yWKw3ZOaLnXnRNmdRzRDPauWi9brvHmgaMVdABhoE3d6r84tLg1GHgnPPWh30W6C5PZAsPy+65CUQzcdZZo138agebi2OiYGv5t07E7KaGwHR/SuQAOQl0oDZ3p74Uc/tY7/Ocz5DHHoG7hYEmoa7jaNBFarlDItLs4OoLvMpOijQNelu2f3qn8MVEfwb/B5ucpWWDzwUka","epsilon":"dJ/RNAi6XLKUupglYfbnYEXGBcblVLwjcGhh/TTGFIdnBrENirg+33XAq8+Hl1DPYEA6PAj7ictCO9rq9Zf8HIohTcqwOx0aV7m9nXZgilQuu+v3WrVhuk06HnVPNHAP7C7VdoWkg6J6J4EXpJj1bb/uZx/gWmWhneUIalfZP44K8YrzGnJ6eSfu3xjk0XYbAlQDrIRC2cZ+pq/LpPKNDZtSBSyTJOlPTIvkD2zljA==","zeta":"K7zPNUe2rNH2mFhGUA0o5JH/cbb88/URksO0Bq2ASUiqIs3t4UaNqcEDizbkoC+l2OJ2LzvObr5z3qcI/qhXAmiLWg/ifExRLHF9jGIjwQbjptftjlF3hGmhhDsHAsP8WGfACFNfvwSdsMPgCGIAZQDSWhgXyoIJzafS9xZx82/LwwNYX8E27FeKZzlh62/ZTC/3sU/mLcsL1TIk4ysmXGMLLDJUCbXN4EIWE14vsnA="},"sacc":{"data":"omNNc2dYxaRiTnVYgCmYtZDXoWoh9Do70RmLdeiIAWimmG4pJAMK/3kHKqJy+U8ePnzh/5qKo8JTj++RUOkPN2vBwqRMRrNsn4rd4Aa0xHmx17/d2YnjhEWwk2M4kPvIoNoM3202fLQRpwPh2vofp7JwYEaz+/DkmK3Gz8f/kv5fLqP/Q5X5Be2jZFiKZUluZGV4AGRUaW1lGl5X3AtpRXZlbnRIYXNoWCISIMiMqOJlUpd1DIx4UEkjTRF0he/yjjM3TQ6I8x7ShWF7Y1NpZ1hHMEUCIAqH0UaPkqeEp6dmEk1sdf/SOVYUjJvU2Hb05LlBJ5mrAiEA0jDFc5fQhOl8rgcJdSlDCY169UksNQQKgtPKNoWhX0k=","pk":2}}}],"indices":[[{"cred":0,"attr":2}]],"nonce":"OkdD8pg642lA3m7uCjW7Xw==","context":"AQ==","message":"message","timestamp":{"Time":1582816270,"ServerUrl":"https://irma.sidn.nl/atumd/","Sig":{"Alg":"ed25519","Data":"8E/Nj/acMLe8Xbn5IKWAoivS9xVRf7oPr0HmxmhGQ8TqurjIWyEuMdSTRZNORKjDATLjDrTHA6bL5UK2roxCCQ==","PublicKey":"MKdXxJxEWPRIwNP7SuvP0J/M/NV51VZvqCyO+7eDwJ8="}}}`

		sig := &irma.SignedMessage{}
		require.NoError(t, json.Unmarshal([]byte(j), sig))
		_, status, err := sig.Verify(client.Configuration, nil)
		require.NoError(t, err)
		require.Equal(t, irma.ProofStatusValid, status)
	})

	t.Run("POSTUpdates", func(t *testing.T) {
		revServer := startRevocationServer(t, true, dbType)
		defer revServer.Stop()
		irmaServer := StartIrmaServer(t, nil)
		defer irmaServer.Stop()

		require.NoError(t, revServer.conf.IrmaConfiguration.Revocation.SyncDB(revocationTestCred))

		sacc1, err := revServer.conf.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		acctime := sacc1.Accumulator.Time
		accindex := sacc1.Accumulator.Index
		time.Sleep(time.Second)

		// run scheduled update of accumulator, triggering a POST to our IRMA server
		runAllSchedulerJobs(revServer.conf.IrmaConfiguration.Scheduler)
		// give HTTP request time to be processed
		time.Sleep(100 * time.Millisecond)

		// check that both the revocation server's and our IRMA server's configuration
		// agree on the same accumulator which has the same index but updated time
		sacc1, err = revServer.conf.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.True(t, sacc1.Accumulator.Time > acctime)
		require.Equal(t, accindex, sacc1.Accumulator.Index)
		sacc2, err := revServer.conf.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.Equal(t, sacc1, sacc2)

		// do a bogus revocation and see that the updated accumulator appears in both configurations
		fakeRevocation(t, "1", revServer.conf.IrmaConfiguration.Revocation, sacc2.Accumulator)
		time.Sleep(100 * time.Millisecond)
		sacc1, err = revServer.conf.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		sacc2, err = revServer.conf.IrmaConfiguration.Revocation.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.Equal(t, sacc1, sacc2)
		require.Equal(t, accindex+1, sacc1.Accumulator.Index)
	})

	t.Run("NoKnownAccumulator", func(t *testing.T) {
		revServer, client, handler := revocationSetup(t, nil, dbType)
		defer test.ClearTestStorage(t, client, handler.storage)

		// stop revocation server so the verifier cannot fetch revocation state
		revServer.Stop()

		result := revocationSession(t, client, nil, nil, optionIgnoreError)
		require.Equal(t, irma.ServerStatusCancelled, result.Status)
		require.NotNil(t, result.Err)
		require.Equal(t, result.Err.ErrorName, string(server.ErrorRevocation.Type))
	})

	t.Run("OtherAccumulator", func(t *testing.T) {
		revServer, client, handler := revocationSetup(t, nil, dbType)
		defer test.ClearTestStorage(t, client, handler.storage)
		defer revServer.Stop()

		// Prepare key material
		conf := revServer.conf.IrmaConfiguration.Revocation
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
		candidates, satisfiable, err := client.Candidates(request)
		require.NoError(t, err)
		require.True(t, satisfiable)
		ids, err := candidates[0][0].Choose()
		require.NoError(t, err)
		choice := &irma.DisclosureChoice{Attributes: [][]*irma.AttributeIdentifier{ids}}
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
		revServer, client, handler := revocationSetup(t, nil, dbType)
		defer test.ClearTestStorage(t, client, handler.storage)
		defer revServer.Stop()

		conf := revServer.conf.IrmaConfiguration.Revocation
		sacc, err := conf.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)

		// Advance the accumulator by doing fake revocations so much that the client will need
		// to contact the RA to update its witness, concurrently fetching a number of event intervals
		fakeMultipleRevocations(t, 116, conf, sacc.Accumulator)

		result := revocationSession(t, client, nil, nil)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
	})

	t.Run("UpdateSameIndex", func(t *testing.T) {
		revServer := startRevocationServer(t, true, dbType)
		defer revServer.Stop()
		irmaServer := StartIrmaServer(t, nil)
		defer irmaServer.Stop()

		// get current accumulator
		require.NoError(t, revServer.conf.IrmaConfiguration.Revocation.SyncDB(revKeyshareTestCred))
		sacc, err := revServer.conf.IrmaConfiguration.Revocation.Accumulator(revKeyshareTestCred, 3)
		require.NoError(t, err)
		accindex := sacc.Accumulator.Index
		sacctime := sacc.Accumulator.Time

		// wait for a moment to assure the accumulator's timestamp will actually differ
		time.Sleep(time.Second)
		// trigger time update and update accumulator
		runAllSchedulerJobs(revServer.conf.IrmaConfiguration.Scheduler)

		require.NoError(t, revServer.conf.IrmaConfiguration.Revocation.SyncDB(revKeyshareTestCred))

		// check that accumulator is newer
		sacc, err = revServer.conf.IrmaConfiguration.Revocation.Accumulator(revKeyshareTestCred, 3)
		require.NoError(t, err)
		require.Equal(t, accindex, sacc.Accumulator.Index)
		require.NotEqual(t, sacctime, sacc.Accumulator.Time)

		// populate revocation data in session request and check it received the newest accumulator
		req := getDisclosureRequest(revKeyshareTestAttr)
		req.Revocation = irma.NonRevocationParameters{revKeyshareTestCred: {}}
		require.NoError(t, revServer.conf.IrmaConfiguration.Revocation.SetRevocationUpdates(req.Base()))
		acc := req.Revocation[revKeyshareTestCred].Updates[3].SignedAccumulator.Accumulator
		require.Equal(t, accindex, acc.Index)
		require.NotEqual(t, sacctime, acc.Time)
	})

	t.Run("ClientAutoServerUpdate", func(t *testing.T) {
		revServer, client, handler := revocationSetup(t, nil, dbType) // revocation server is stopped manually below
		defer test.ClearTestStorage(t, client, handler.storage)

		// Advance the accumulator by performing 3 revocations
		conf := revServer.conf.IrmaConfiguration.Revocation
		sacc, err := conf.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		fakeMultipleRevocations(t, 3, conf, sacc.Accumulator)

		// Client updates at revocation server to index 3
		require.NoError(t, client.NonrevUpdateFromServer(revocationTestCred))
		sacc, err = conf.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.Equal(t, uint64(3), sacc.Accumulator.Index)

		// Perform extra revocations such that those updates won't be present in the client
		fakeMultipleRevocations(t, irma.RevocationParameters.DefaultUpdateEventCount, conf, sacc.Accumulator)

		// Start an IRMA server and let it update at revocation server
		irmaServer := StartIrmaServer(t, nil)
		defer irmaServer.Stop()
		conf = irmaServer.conf.IrmaConfiguration.Revocation
		require.NoError(t, conf.SyncDB(revocationTestCred))

		// IRMA server's accumulator is now at the same index as that of the revocation server
		sacc, err = conf.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		pk, err := conf.Keys.PublicKey(revocationTestCred.IssuerIdentifier(), revocationPkCounter)
		require.NoError(t, err)
		acc, err := sacc.UnmarshalVerify(pk)
		require.NoError(t, err)
		require.Equal(t, irma.RevocationParameters.DefaultUpdateEventCount+3, acc.Index)

		// Stop revocation server
		revServer.Stop()

		// The client has only been updated until revocation event with index 3, and because the revocation server has
		// been stopped the client cannot update by itself anymore. The IRMA server should exactly provide enough revocation
		// events from its cache to fulfill the client's update needs. Therefore, the session should succeed.
		result := revocationSession(t, client, nil, irmaServer)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
	})

	t.Run("LaggingNonRevocationWitness", func(t *testing.T) {
		revServer, client, handler := revocationSetup(t, nil, dbType)
		defer revServer.Stop()
		defer test.ClearTestStorage(t, client, handler.storage)

		// Advance the accumulator by performing a few revocations
		revServerStorage := revServer.conf.IrmaConfiguration.Revocation
		sacc, err := revServerStorage.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		fakeMultipleRevocations(t, irma.RevocationParameters.DefaultUpdateEventCount+3, revServerStorage, sacc.Accumulator)

		// Start an IRMA server and let it update at the revocation server
		irmaServer := StartIrmaServer(t, nil)
		defer irmaServer.Stop()
		irmaServerStorage := irmaServer.conf.IrmaConfiguration.Revocation
		require.NoError(t, irmaServerStorage.SyncDB(revocationTestCred))
		sacc, err = irmaServerStorage.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.Equal(t, irma.RevocationParameters.DefaultUpdateEventCount+3, sacc.Accumulator.Index)

		// Increase revocation update count to enlarge the IRMA server's revocation cache.
		irmaServer.conf.IrmaConfiguration.CredentialTypes[revocationTestCred].RevocationUpdateCount = 2 * irma.RevocationParameters.DefaultUpdateEventCount

		// Advance the accumulator further.
		fakeMultipleRevocations(t, 3, revServerStorage, sacc.Accumulator)

		// Let the IRMA server update at the revocation server again.
		require.NoError(t, irmaServerStorage.SyncDB(revocationTestCred))
		sacc, err = irmaServerStorage.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.Equal(t, irma.RevocationParameters.DefaultUpdateEventCount+6, sacc.Accumulator.Index)

		// We increased the revocation update count, but the IRMA server's revocation storage will not be updated retroactively.
		// So, just as before, the initial revocation event and the first 3 update events should miss in the storage.
		// The events that were cached previously and the 3 events that we added after the first SyncDB should be present now.
		updates, err := irmaServerStorage.LatestUpdates(revocationTestCred, 2*irma.RevocationParameters.DefaultUpdateEventCount, &revocationPkCounter)
		require.NoError(t, err)
		require.Contains(t, updates, revocationPkCounter)
		events := updates[revocationPkCounter].Events
		require.Len(t, events, int(irma.RevocationParameters.DefaultUpdateEventCount)+3)
		require.Equal(t, uint64(4), events[0].Index)
		require.Equal(t, irma.RevocationParameters.DefaultUpdateEventCount+6, events[len(events)-1].Index)

		// Do a revocation session.
		// The client has not updated at all, so it should use the revocation events from the IRMA server's cache to update,
		// and it should contact the revocation server to fetch the 4 events that the cache is missing.
		result := revocationSession(t, client, nil, irmaServer)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
	})

	t.Run("SameIrmaServer", func(t *testing.T) {
		irmaServer := StartIrmaServer(t, nil)
		defer irmaServer.Stop()

		// issue a credential, populating irmaServer's revocation memdb
		revServer, client, handler := revocationSetup(t, irmaServer, dbType)
		defer test.ClearTestStorage(t, client, handler.storage)
		defer revServer.Stop()

		// disable serving revocation updates in revocation server
		require.NoError(t, revServer.conf.IrmaConfiguration.Revocation.Close())

		// do disclosure session, using irmaServer's memdb
		result := revocationSession(t, client, nil, irmaServer)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
	})

	t.Run("RestartRevocationServer", func(t *testing.T) {
		revServer := startRevocationServer(t, true, dbType)
		rev := revServer.conf.IrmaConfiguration.Revocation
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

		revServer.Stop()

		revServer = startRevocationServer(t, false, dbType)
		defer revServer.Stop()
		rev = revServer.conf.IrmaConfiguration.Revocation
		sacc3, err := rev.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)
		require.Equal(t, sacc2, sacc3)

		update, err := rev.LatestUpdates(revocationTestCred, 10, &revocationPkCounter)
		require.NoError(t, err)
		pk, err := rev.Keys.PublicKey(revocationTestCred.IssuerIdentifier(), revocationPkCounter)
		require.NoError(t, err)
		require.Contains(t, update, revocationPkCounter)
		_, err = update[revocationPkCounter].Verify(pk)
		require.NoError(t, err)
		require.Equal(t, 2, len(update[revocationPkCounter].Events))
	})

	t.Run("DeleteExpiredIssuanceRecords", func(t *testing.T) {
		revServer := startRevocationServer(t, true, dbType)
		defer revServer.Stop()

		// Insert expired issuance record
		rev := revServer.conf.IrmaConfiguration.Revocation
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
		runAllSchedulerJobs(revServer.conf.IrmaConfiguration.Scheduler)

		// Check that issuance record is gone
		_, err = rev.IssuanceRecords(revocationTestCred, "1", time.Time{})
		require.Equal(t, irma.ErrUnknownRevocationKey, err)
	})

	t.Run("RevokeMany", func(t *testing.T) {
		revServer := startRevocationServer(t, true, dbType)
		defer revServer.Stop()
		rev := revServer.conf.IrmaConfiguration.Revocation
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
		_, err = rev.IssuanceRecords(revocationTestCred, "1", time.Time{})
		require.Equal(t, irma.ErrUnknownRevocationKey, err)

		// fetch and verify update message
		update, err := rev.LatestUpdates(revocationTestCred, 10, &revocationPkCounter)
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
		revServer, client, handler := revocationSetup(t, nil, dbType)
		defer test.ClearTestStorage(t, client, handler.storage)
		defer revServer.Stop()
		start := time.Now()

		result := revocationSession(t, client, nil, nil)
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
		require.NotEmpty(t, result.Disclosed[0])
		require.NotNil(t, result.Disclosed[0][0])
		// not included: window within which nonrevocation is not guaranteed, as it is within tolerance
		require.Nil(t, result.Disclosed[0][0].NotRevokedBefore)

		request := revocationRequest(revocationTestAttr)
		request.Revocation[revocationTestCred].Tolerance = 1
		result = revocationSession(t, client, request, nil, optionClientWait)

		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.NotEmpty(t, result.Disclosed)
		require.NotEmpty(t, result.Disclosed[0])
		require.NotNil(t, result.Disclosed[0][0])
		require.True(t, result.Disclosed[0][0].NotRevoked)
		require.NotNil(t, result.Disclosed[0][0].NotRevokedBefore)

		// notRevokedBefore is truncated, so also truncate the start time to get a sensible comparison
		start = start.Truncate(time.Second)
		notRevokedBefore := (*time.Time)(result.Disclosed[0][0].NotRevokedBefore)
		require.True(t, notRevokedBefore.Equal(start) || notRevokedBefore.After(start))
	})

	t.Run("Cache", func(t *testing.T) {
		revServer := startRevocationServer(t, true, dbType)
		defer revServer.Stop()
		rev := revServer.conf.IrmaConfiguration.Revocation
		sacc, err := rev.Accumulator(revocationTestCred, revocationPkCounter)
		require.NoError(t, err)

		// ensure enough events esists for /events endpoint
		fakeMultipleRevocations(t, 17, rev, sacc.Accumulator)

		// check /events endpoint
		url := revServer.conf.IrmaConfiguration.CredentialTypes[revocationTestCred].RevocationServers[0] +
			"/revocation/irma-demo.MijnOverheid.root/events/2/0/16"
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		res, err := (&http.Client{}).Do(req)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		cacheheader := res.Header.Get("Cache-Control")
		require.True(t, cacheheader == fmt.Sprintf("max-age=%d", irma.RevocationParameters.EventsCacheMaxAge) ||
			cacheheader == fmt.Sprintf("max-age=%d", irma.RevocationParameters.EventsCacheMaxAge-1),
		)

		// check /update endpoint
		url = revServer.conf.IrmaConfiguration.CredentialTypes[revocationTestCred].RevocationServers[0] +
			"/revocation/irma-demo.MijnOverheid.root/update/16"
		req, err = http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		res, err = (&http.Client{}).Do(req)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		// We have to correct the max age for network delay.
		maxAge := sacc.Accumulator.Time + int64(irma.RevocationParameters.AccumulatorUpdateInterval) - time.Now().Unix()
		require.Equal(t,
			fmt.Sprintf("max-age=%d", maxAge),
			res.Header.Get("Cache-Control"),
		)
	})

	t.Run("NonRevocationAwareCredential", func(t *testing.T) {
		client, handler := parseStorage(t)
		defer test.ClearTestStorage(t, client, handler.storage)

		// Start irma server and hackily temporarily disable revocation for our credtype
		// by editing its irma.Configuration instance
		irmaServer := StartIrmaServer(t, nil)
		defer irmaServer.Stop()
		conf := irmaServer.conf.IrmaConfiguration
		credtyp := conf.CredentialTypes[revocationTestCred]
		servers := credtyp.RevocationServers // save it for re-enabling revocation below
		credtyp.RevocationServers = nil
		revAttr := credtyp.AttributeTypes[len(credtyp.AttributeTypes)-1]
		credtyp.AttributeTypes = credtyp.AttributeTypes[:len(credtyp.AttributeTypes)-1]

		// Issue non-revocation-aware credential instance
		result := doSession(t, irma.NewIssuanceRequest([]*irma.CredentialRequest{{
			CredentialTypeID: revocationTestCred,
			Attributes: map[string]string{
				"BSN": "299792458",
			},
		}}), client, irmaServer, nil, nil, nil)
		require.Nil(t, result.Err)

		// Restore revocation setup
		credtyp.RevocationServers = servers
		credtyp.AttributeTypes = append(credtyp.AttributeTypes, revAttr)
		revServer := startRevocationServer(t, true, dbType)
		defer revServer.Stop()

		// Try disclosure session requiring nonrevocation proof
		// client notices it has no revocation-aware credential instance and aborts
		result = revocationSession(t, client, nil, irmaServer, optionUnsatisfiableRequest)
		require.NotEmpty(t, result.Missing)
	})
}

func TestKeyshareRevocation(t *testing.T) {
	dbType := "postgres"
	t.Run("Keyshare", func(t *testing.T) {
		revServer := startRevocationServer(t, true, dbType)
		defer revServer.Stop()
		keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
		defer keyshareServer.Stop()
		client, handler := parseStorage(t)
		defer test.ClearTestStorage(t, client, handler.storage)

		testRevocation(t, revKeyshareTestAttr, client, handler, revServer.irma)
	})

	t.Run("Both", func(t *testing.T) {
		revServer := startRevocationServer(t, true, dbType)
		defer revServer.Stop()
		keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
		defer keyshareServer.Stop()
		client, handler := parseStorage(t)
		defer test.ClearTestStorage(t, client, handler.storage)

		testRevocation(t, revKeyshareTestAttr, client, handler, revServer.irma)
		testRevocation(t, revocationTestAttr, client, handler, revServer.irma)
	})

	t.Run("KeyshareMultipleCredentials", func(t *testing.T) {
		revServer := startRevocationServer(t, true, dbType)
		defer revServer.Stop()
		keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
		defer keyshareServer.Stop()
		client, handler := parseStorage(t)
		defer test.ClearTestStorage(t, client, handler.storage)

		testRevocation(t, revKeyshareTestAttr, client, handler, revServer.irma)
		testRevocation(t, revKeyshareSecondTestAttr, client, handler, revServer.irma)
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
			RevocationKey:    "key",
			CredentialTypeID: credid,
			Attributes: map[string]string{
				"BSN": "299792458",
			},
		}})
	case revKeyshareTestCred:
		fallthrough
	case revKeyshareSecondTestCred:
		return irma.NewIssuanceRequest([]*irma.CredentialRequest{{
			RevocationKey:    "keysharekey",
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

func revocationSession(t *testing.T, client *irmaclient.Client, request irma.SessionRequest, irmaServer *IrmaServer, options ...option) *requestorSessionResult {
	if request == nil {
		request = revocationRequest(revocationTestAttr)
	}
	result := doSession(t, request, client, irmaServer, nil, nil, nil, options...)
	if processOptions(options...)&optionIgnoreError == 0 && result.SessionResult != nil {
		require.Nil(t, result.Err)
	}
	return result
}

// revocationSetup sets up an irmaclient with a revocation-enabled credential, constants, and revocation key material.
func revocationSetup(t *testing.T, irmaServer *IrmaServer, dbType string) (*IrmaServer, *irmaclient.Client, *TestClientHandler) {
	revServer := startRevocationServer(t, true, dbType)

	// issue a MijnOverheid.root instance with revocation enabled
	client, handler := parseStorage(t)
	result := doSession(t, revocationIssuanceRequest(t, revocationTestCred), client, irmaServer, nil, nil, nil)
	require.Nil(t, result.Err)

	return revServer, client, handler
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

	u, err := conf.LatestUpdates(revocationTestCred, 1, &revocationPkCounter)
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

func revocationConf(_ *testing.T, dbType string) *server.Configuration {
	return &server.Configuration{
		URL:                   revocationServerURL,
		Logger:                logger,
		EnableSSE:             true,
		DisableSchemesUpdate:  true,
		SchemesPath:           filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
		RevocationSettings: irma.RevocationSettings{
			revocationTestCred:        {Authority: true},
			revKeyshareTestCred:       {Authority: true},
			revKeyshareSecondTestCred: {Authority: true},
		},
		RevocationDBConnStr: revocationDbStrs[dbType],
		RevocationDBType:    dbType,
	}
}

func startRevocationServer(t *testing.T, droptables bool, dbType string) *IrmaServer {
	var err error

	// Connect to database and clear records from previous test runs
	if droptables {
		var g *gorm.DB
		switch dbType {
		case "postgres":
			g, err = gorm.Open(postgres.Open(revocationDbStrs[dbType]))
		case "mysql":
			g, err = gorm.Open(mysql.Open(revocationDbStrs[dbType]))
		case "sqlserver":
			g, err = gorm.Open(sqlserver.Open(revocationDbStrs[dbType]))
		}
		require.NoError(t, err)
		require.NoError(t, g.Migrator().DropTable((*irma.EventRecord)(nil)))
		require.NoError(t, g.Migrator().DropTable((*irma.AccumulatorRecord)(nil)))
		require.NoError(t, g.Migrator().DropTable((*irma.IssuanceRecord)(nil)))
		require.NoError(t, g.AutoMigrate((*irma.EventRecord)(nil)))
		require.NoError(t, g.AutoMigrate((*irma.AccumulatorRecord)(nil)))
		require.NoError(t, g.AutoMigrate((*irma.IssuanceRecord)(nil)))
		db, err := g.DB()
		require.NoError(t, err)
		require.NoError(t, db.Close())
	}

	// Start revocation server
	conf := revocationConf(t, dbType)
	revocationServer, err := irmaserver.New(conf)
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/", revocationServer.HandlerFunc())
	revocationHttpServer := &http.Server{Addr: fmt.Sprintf("localhost:%d", revocationServerPort), Handler: mux}
	go func() {
		_ = revocationHttpServer.ListenAndServe()
	}()
	return &IrmaServer{
		irma: revocationServer,
		conf: conf,
		http: revocationHttpServer,
	}
}

// runAllSchedulerJobs calls RunAll() on the scheduler, and blocks until the jobs have finished.
// The scheduler has no wait to run all jobs and wait for them to finish, so this function
// https://github.com/go-co-op/gocron/issues/326
func runAllSchedulerJobs(scheduler *gocron.Scheduler) {
	// The scheduler library has no
	// Limit max concurrent jobs so that the job below doesn't run concurrently with others
	scheduler.SetMaxConcurrentJobs(1, gocron.WaitMode)

	// Register a job that we can monitor when it has been executed
	wg := sync.WaitGroup{}
	wg.Add(1)
	job, _ := scheduler.Every(1).Hour().WaitForSchedule().Do(func() {
		wg.Done()
	})

	// Now run all jobs
	scheduler.RunAll()

	// Wait until the last job has been executed
	wg.Wait()
	scheduler.Remove(job)

	// Assert all jobs have finished
outer:
	for {
		time.Sleep(10 * time.Millisecond)
		for _, job := range scheduler.Jobs() {
			if job.IsRunning() {
				continue outer
			}
		}
		break outer
	}
}
