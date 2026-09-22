package isomdoc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// ============================================================
// LIVE INTEROP — against multipaz-verifier-server
// ============================================================
//
// irmago #724 Phase 2's gate: "a plain org-iso-mdoc presentation round-trips
// against multipaz-verifier-server". This is that round trip — their request in,
// our sealed response back, decrypted by them.
//
// SKIPPED unless the server is listening. It is not a CI test: it needs a Ktor
// app from the multipaz checkout on 127.0.0.1:8006.
//
//	cd D:/Yivi/multipaz && ./gradlew :multipaz-verifier-server:run
//
// What it actually proves, and why that is the interesting part: the verifier
// does NOT decrypt with the encryptionInfo it sent. It REBUILDS that text from
// its own session state (nonce + encryption key), hashes [rebuilt, origin], and
// uses the result as the HPKE info parameter. So the exchange only opens if our
// transcript is byte-identical to one we never saw. Every other test of this
// package's transcript compares our construction against our own expectation.
//
// Issuer trust is a separate matter and is expected to fail: the credential here
// is signed by mdoc.NewTestIssuer, which this verifier has no reason to trust.
// A rejection AFTER decryption is the success condition for the transport; a
// failure to decrypt is the one that would matter.

const verifierBase = "http://127.0.0.1:8006"

func skipUnlessVerifierRunning(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8006", 750*time.Millisecond)
	if err != nil {
		t.Skip("multipaz-verifier-server not listening on 127.0.0.1:8006; " +
			"start it with ./gradlew :multipaz-verifier-server:run in the multipaz checkout")
	}
	_ = conn.Close()
}

func postJSON(t *testing.T, path string, body any, into any) {
	t.Helper()

	encoded, err := json.Marshal(body)
	require.NoError(t, err)

	response, err := http.Post(verifierBase+path, "application/json", bytes.NewReader(encoded))
	require.NoError(t, err)
	defer response.Body.Close()

	var raw json.RawMessage
	require.NoError(t, json.NewDecoder(response.Body).Decode(&raw))
	require.Equal(t, http.StatusOK, response.StatusCode, "POST %s: %s", path, raw)
	require.NoError(t, json.Unmarshal(raw, into))
}

// TestLiveRoundTripAgainstMultipazVerifier drives the whole exchange.
func TestLiveRoundTripAgainstMultipazVerifier(t *testing.T) {
	skipUnlessVerifierRunning(t)

	// The origin we claim here is the one the verifier binds its transcript to,
	// so it has to be the same value in both calls and in Respond.
	const origin = "https://verifier.example.com"

	// ---- their request ----------------------------------------------------
	var begin dcBeginResponse
	postJSON(t, "/verifier/dcBegin", map[string]any{
		"format": "mdoc", "docType": "eu.europa.ec.av.1", "requestId": "age_over_18",
		"rawDcql": "", "multiDocumentRequestId": "",
		"protocol": "w3c_dc_mdoc_api", "origin": origin, "host": "127.0.0.1:8006",
		"signRequest": false, "encryptResponse": true,
	}, &begin)

	require.Equal(t, DcApiProtocolIsoMdoc, begin.DcRequestProtocol)
	require.NotEmpty(t, begin.SessionID)

	request, err := RequestFromDcApi([]byte(begin.DcRequestString), origin)
	require.NoError(t, err)

	// ---- our response -----------------------------------------------------
	// A fake discloser rather than real storage: what is under test is the
	// transport, and wiring SQLCipher in would add a second thing that can fail
	// without testing anything the wallet tests do not already cover.
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})
	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Holder: holder}}}

	sealed, err := (&Session{Discloser: wallet}).Respond(request)
	require.NoError(t, err)

	encoded, err := cbor.Marshal(sealed)
	require.NoError(t, err)
	credentialResponse, err := json.Marshal(map[string]any{
		"response": base64.RawURLEncoding.EncodeToString(encoded),
	})
	require.NoError(t, err)

	// ---- hand it back -----------------------------------------------------
	var result map[string]any
	postJSON(t, "/verifier/dcGetData", map[string]any{
		"sessionId":          begin.SessionID,
		"credentialProtocol": DcApiProtocolIsoMdoc,
		"credentialResponse": string(credentialResponse),
	}, &result)

	// Reaching a 200 means the verifier rebuilt the session transcript from its
	// own state, derived the same HPKE info we sealed with, and decrypted. That
	// is the transport claim. What it then makes of an untrusted issuer is
	// reported, not asserted.
	pretty, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("verifier accepted and decrypted the response:\n%s\n", pretty)
}
