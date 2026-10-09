package isomdoc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
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
// SKIPPED unless the server is listening on 127.0.0.1:8006. It is not a CI
// test. Two ways to stand the server up:
//
//	docker compose --profile interop up --build -d multipaz-verifier
//	./gradlew :multipaz-verifier-server:run                 # in the multipaz checkout
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
		// Nothing here knows or cares what serves 8006 — this test is about the
		// protocol, not about who hosts it. The compose service is simply the
		// one way to get a verifier that needs no multipaz checkout.
		t.Skip("multipaz-verifier-server not listening on 127.0.0.1:8006; " +
			"start it with: docker compose --profile interop up --build -d multipaz-verifier")
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

// liveOrigin is what we claim to the verifier. It binds its transcript to this,
// so the same value has to reach both calls and Respond.
const liveOrigin = "https://verifier.example.com"

// dcBeginBody is the request that asks multipaz-verifier-server to mint an
// org-iso-mdoc exchange.
//
// One definition, two users: the round trip below sends it, and the fixture
// regeneration sends exactly the same thing. That is the point of extracting it
// — testdata/multipaz_verifier_dcbegin.json was originally captured by hand, so
// nothing tied the stored response to the request the live test makes, and the
// two could drift apart without either failing.
func dcBeginBody() map[string]any {
	return map[string]any{
		"format":                 "mdoc",
		"docType":                "eu.europa.ec.av.1",
		"requestId":              "age_over_18",
		"rawDcql":                "",
		"multiDocumentRequestId": "",
		"protocol":               "w3c_dc_mdoc_api",
		"origin":                 liveOrigin,
		"host":                   "127.0.0.1:8006",
		"signRequest":            false,
		"encryptResponse":        true,
	}
}

// TestRegenerateMultipazFixture rewrites the captured dcBegin response that
// interop_multipaz_test.go asserts against, from the server actually running.
//
// Opt-in, and deliberately not part of any ordinary run: a test that rewrites
// its own fixture cannot fail, and one that did so automatically would turn a
// genuine disagreement with upstream into a silent update. Run it when the
// pinned MULTIPAZ_REF in docker-compose moves, then read the diff:
//
//	docker compose --profile interop up --build -d multipaz-verifier
//	REGENERATE_MULTIPAZ_FIXTURE=1 go test ./eudi/isomdoc -run TestRegenerateMultipazFixture
//	git diff eudi/isomdoc/testdata/multipaz_verifier_dcbegin.json
//
// A diff here is information, not a chore: it is upstream changing the shape of
// a request we parse.
func TestRegenerateMultipazFixture(t *testing.T) {
	if os.Getenv("REGENERATE_MULTIPAZ_FIXTURE") == "" {
		t.Skip("set REGENERATE_MULTIPAZ_FIXTURE=1 to rewrite the captured dcBegin response")
	}
	skipUnlessVerifierRunning(t)

	encoded, err := json.Marshal(dcBeginBody())
	require.NoError(t, err)

	response, err := http.Post(verifierBase+"/verifier/dcBegin", "application/json", bytes.NewReader(encoded))
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)

	// Stored verbatim, not re-encoded from a decoded structure: the fixture's
	// job is to be what the server really sent, down to key order and spacing.
	// Re-marshalling it would make the tests assert our own encoder's output.
	raw, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	// Parses as the real thing before it replaces the fixture, so a server that
	// answers 200 with something unusable cannot quietly become the baseline.
	var sanity dcBeginResponse
	require.NoError(t, json.Unmarshal(raw, &sanity))
	require.Equal(t, DcApiProtocolIsoMdoc, sanity.DcRequestProtocol)
	require.NotEmpty(t, sanity.DcRequestString)

	require.NoError(t, os.WriteFile(multipazVerifierRequest, raw, 0o644))
	t.Logf("rewrote %s (%d bytes)", multipazVerifierRequest, len(raw))
}

// TestLiveRoundTripAgainstMultipazVerifier drives the whole exchange.
func TestLiveRoundTripAgainstMultipazVerifier(t *testing.T) {
	skipUnlessVerifierRunning(t)

	const origin = liveOrigin

	// ---- their request ----------------------------------------------------
	var begin dcBeginResponse
	postJSON(t, "/verifier/dcBegin", dcBeginBody(), &begin)

	require.Equal(t, DcApiProtocolIsoMdoc, begin.DcRequestProtocol)
	require.NotEmpty(t, begin.SessionID)

	request, err := RequestFromDcApi([]byte(begin.DcRequestString), origin)
	require.NoError(t, err)

	// ---- our response -----------------------------------------------------
	// A fake discloser rather than real storage: what is under test is the
	// transport, and wiring SQLCipher in would add a second thing that can fail
	// without testing anything the wallet tests do not already cover.
	document, holder := credential(t, avDocType, avNameSpace, map[string]any{"age_over_18": true})
	wallet := &fakeDiscloser{answer: []Selection{{DocType: avDocType, Document: document, Signer: holder}}}

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
