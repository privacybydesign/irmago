package client

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/mdocpresent"
	"github.com/stretchr/testify/require"
)

// These cover the two halves of the routing that do not need a wallet behind
// them: the shape handed back to the platform, and the park-for-consent
// handshake. The exchange itself is tested in eudi/mdocpresent.

// testTimeout and testPoll bound the waits for the session goroutine to park.
// Generous, because a loaded CI machine scheduling a goroutine late is not a
// defect; the test fails on a handshake that never happens, not on a slow one.
const (
	testTimeout = 2 * time.Second
	testPoll    = time.Millisecond
)

// newIsoMdocTestSession wires the least an isoMdocSession needs to dispatch and
// finish, without a Client, storage or a real discloser.
func newIsoMdocTestSession() (*isoMdocSession, *dispatchSpy) {
	session, spy := newFinishTestSession()
	iso := &isoMdocSession{
		session: session,
		answers: make(chan *isoMdocConsentAnswer, 1),
	}
	session.isoMdocSession = iso
	return iso, spy
}

func consentRequest() mdocpresent.ConsentRequest {
	return mdocpresent.ConsentRequest{
		Origin: "https://verifier.example.com",
		Plan:   &clientmodels.DisclosurePlan{},
	}
}

// TestDcApiResponseDataIsAJsonObject: SessionState.DcApiResponse already carries a
// JSON `data` member for OpenID4VP. Handing back a bare string here would make the
// app branch on protocol to return it.
func TestDcApiResponseDataIsAJsonObject(t *testing.T) {
	sealed := mdoc.DCAPIEncryptedResponse{
		Enc:        []byte{0x04, 0x01, 0x02},
		CipherText: []byte{0xaa, 0xbb},
	}

	data, err := dcApiResponseData(sealed)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(data), &decoded))

	encoded, ok := decoded["response"].(string)
	require.True(t, ok, "the data member carries the sealed response under \"response\"")

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err, "the value is base64url")

	// It must be the ["dcapi", {...}] envelope, not a bare struct encode: a
	// verifier decoding the envelope would reject the latter.
	var roundTripped mdoc.DCAPIEncryptedResponse
	require.NoError(t, cbor.Unmarshal(raw, &roundTripped))
	require.Equal(t, sealed.Enc, roundTripped.Enc)
	require.Equal(t, sealed.CipherText, roundTripped.CipherText)
}

// TestRequestConsentParksAndReturnsTheAnswer is the handshake: the plan reaches
// the UI, the session blocks, and the user's choices come back to the discloser.
func TestRequestConsentParksAndReturnsTheAnswer(t *testing.T) {
	iso, spy := newIsoMdocTestSession()

	granted := []clientmodels.DisclosureDisconSelection{{
		Credentials: []clientmodels.SelectedCredential{{CredentialHash: "hash"}},
	}}

	done := make(chan []clientmodels.DisclosureDisconSelection, 1)
	go func() {
		choices, err := iso.RequestConsent(consentRequest())
		require.NoError(t, err)
		done <- choices
	}()

	// Deliver once the session is actually parked, so the test exercises the
	// handshake rather than the buffered channel.
	require.Eventually(t, iso.awaiting.Load, testTimeout, testPoll)
	require.True(t, iso.answer(true, granted))
	require.Equal(t, granted, <-done)

	require.Equal(t, []clientmodels.SessionStatus{clientmodels.Status_RequestPermission}, spy.statuses)
	require.Equal(t, clientmodels.Protocol_ISO18013_5, iso.session.State.Protocol,
		"the app is told which exchange it is showing")
	require.Equal(t, "https://verifier.example.com", iso.session.State.Requestor.Name,
		"an org-iso-mdoc request carries no verifier identity but the origin")
	require.False(t, iso.session.State.Requestor.Verified,
		"reader auth proves a certificate chained to an anchor, not that it belongs to this origin")
}

// TestRequestConsentRefusalIsNotAnError: a user declining returns no choices and
// no error, which the session turns into a response carrying documentErrors
// rather than into a failure.
func TestRequestConsentRefusalIsNotAnError(t *testing.T) {
	iso, _ := newIsoMdocTestSession()

	done := make(chan []clientmodels.DisclosureDisconSelection, 1)
	go func() {
		choices, err := iso.RequestConsent(consentRequest())
		require.NoError(t, err)
		done <- choices
	}()

	require.Eventually(t, iso.awaiting.Load, testTimeout, testPoll)
	require.True(t, iso.answer(false, nil))
	require.Empty(t, <-done)
}

// TestAnswerIsExclusive: a second answer, or one arriving after the session
// unwound, has nowhere to go. Delivering it anyway would block on a channel no
// goroutine will read.
func TestAnswerIsExclusive(t *testing.T) {
	iso, _ := newIsoMdocTestSession()

	require.False(t, iso.answer(true, nil), "nobody is parked yet")

	done := make(chan struct{})
	go func() {
		_, _ = iso.RequestConsent(consentRequest())
		close(done)
	}()

	require.Eventually(t, iso.awaiting.Load, testTimeout, testPoll)
	require.True(t, iso.answer(true, nil))
	<-done
	require.False(t, iso.answer(true, nil), "the window closed with the first answer")
}

// TestDismissBeforeTheWindowOpensRefuses: a dismissal can arrive while the
// request is still being parsed and the reader authenticated. Showing a consent
// screen afterwards would ask about a session the user already left.
func TestDismissBeforeTheWindowOpensRefuses(t *testing.T) {
	iso, spy := newIsoMdocTestSession()

	iso.Dismiss()

	choices, err := iso.RequestConsent(consentRequest())
	require.NoError(t, err, "backing out is a refusal, not a failure")
	require.Empty(t, choices)
	require.Empty(t, spy.statuses, "no permission screen is dispatched for a dismissed session")
}

// TestDismissWhileParkedIsADenial: a dismissal travels the same channel the
// user's own "no" does.
func TestDismissWhileParkedIsADenial(t *testing.T) {
	iso, _ := newIsoMdocTestSession()

	done := make(chan []clientmodels.DisclosureDisconSelection, 1)
	go func() {
		choices, _ := iso.RequestConsent(consentRequest())
		done <- choices
	}()

	require.Eventually(t, iso.awaiting.Load, testTimeout, testPoll)
	iso.Dismiss()
	require.Empty(t, <-done)
}
