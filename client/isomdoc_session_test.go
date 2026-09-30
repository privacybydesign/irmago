package client

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/isomdoc"
	"github.com/stretchr/testify/require"
)

// These cover the two halves of the routing that do not need a wallet behind
// them: the shape handed back to the platform, and the park-for-consent
// handshake. The exchange itself is tested in eudi/isomdoc.

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

func consentRequest() isomdoc.ConsentRequest {
	return isomdoc.ConsentRequest{
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
	require.True(t, iso.answer(consentGranted, granted))
	require.Equal(t, granted, <-done)

	require.Equal(t, []clientmodels.SessionStatus{clientmodels.Status_RequestPermission}, spy.statuses)
	require.Equal(t, clientmodels.Protocol_ISO18013_5, iso.session.State.Protocol,
		"the app is told which exchange it is showing")
	// #724 O1: nothing in an org-iso-mdoc request names the caller, so the wallet
	// reports no party rather than dressing the origin up as one. The UI owes this
	// case a different screen, and can only know to show one if the model says so.
	requestor := iso.session.State.Requestor
	require.True(t, requestor.Anonymous,
		"an org-iso-mdoc request carries no verifier identity at all")
	require.Empty(t, requestor.Name,
		"an origin is an address, not a name; putting it in Name is what O1 rejects")
	require.NotNil(t, requestor.Origin)
	require.Equal(t, "https://verifier.example.com", *requestor.Origin,
		"the origin is still shown — it is the one fact the platform authenticated")
	require.False(t, requestor.Verified,
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
	require.True(t, iso.answer(consentDenied, nil))
	require.Empty(t, <-done)
}

// TestAnswerIsExclusive: a second answer, or one arriving after the session
// unwound, has nowhere to go. Delivering it anyway would block on a channel no
// goroutine will read.
func TestAnswerIsExclusive(t *testing.T) {
	iso, _ := newIsoMdocTestSession()

	require.False(t, iso.answer(consentGranted, nil), "nobody is parked yet")

	done := make(chan struct{})
	go func() {
		_, _ = iso.RequestConsent(consentRequest())
		close(done)
	}()

	require.Eventually(t, iso.awaiting.Load, testTimeout, testPoll)
	require.True(t, iso.answer(consentGranted, nil))
	<-done
	require.False(t, iso.answer(consentGranted, nil), "the window closed with the first answer")
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

// TestRefusalIsNotReportedAsSuccess: an exchange that disclosed nothing is
// Dismissed, not Success -- and writes no disclosure log, since run gates both
// on this one predicate.
//
// The distinction is invisible below this point. A refusal is a well-formed
// response -- 8.3.2.1.2.2 expresses it as status 0 with a documentError per
// document -- so it is built, sealed and delivered exactly like a disclosure,
// and Respond returns no error for either. Reporting Success for both told a
// user who had just declined that their data had been shared.
func TestRefusalIsNotReportedAsSuccess(t *testing.T) {
	require.Equal(t, clientmodels.Status_Dismissed, outcomeOf(0),
		"nothing left the wallet: the user refused, or nothing asked for could be served")
	require.Equal(t, clientmodels.Status_Success, outcomeOf(1))
	require.Equal(t, clientmodels.Status_Success, outcomeOf(2),
		"a request answered from two credentials is still one successful disclosure")

	// The activity log follows the same answer. OpenID4VP writes no disclosure
	// log for a request the wallet refuses, a permission the user denies or a
	// session the app dismisses, and an org-iso-mdoc exchange returning nothing
	// but documentErrors is that same event: an entry claiming a disclosure
	// happened, listing nothing, is worse than no entry, because this log is the
	// only record the user has of a presentation that is otherwise unlinkable.
	require.NotEqual(t, clientmodels.Status_Success, outcomeOf(0),
		"run logs the disclosure only when this says Success")
}

// TestConsentStampsWhenTheUserAnswered: the duration the app shows on the
// zero-knowledge feedback screen is measured from this stamp, so a granted
// consent that fails to set it reports a proof that took no time at all.
func TestConsentStampsWhenTheUserAnswered(t *testing.T) {
	iso, _ := newIsoMdocTestSession()
	require.True(t, iso.consentAt.IsZero(), "nothing has been answered yet")

	done := make(chan struct{})
	go func() {
		_, _ = iso.RequestConsent(consentRequest())
		close(done)
	}()

	require.Eventually(t, iso.awaiting.Load, testTimeout, testPoll)
	require.True(t, iso.answer(consentGranted, nil))
	<-done

	require.False(t, iso.consentAt.IsZero(),
		"the stamp the reported disclosure duration is measured from")
	require.WithinDuration(t, time.Now(), iso.consentAt, testTimeout)
}

// TestDisclosureDurationOmittedWhenUnmeasured: omitempty has to drop an unset
// duration rather than hand the app a zero, which it would render as a proof
// that took no time. A disclosure genuinely completing inside a millisecond is
// not a case this transport has: the proof alone is seconds.
func TestDisclosureDurationOmittedWhenUnmeasured(t *testing.T) {
	measured, err := json.Marshal(clientmodels.SessionState{DisclosureDurationMs: 1234})
	require.NoError(t, err)
	require.Contains(t, string(measured), `"disclosure_duration_ms":1234`)

	unmeasured, err := json.Marshal(clientmodels.SessionState{})
	require.NoError(t, err)
	require.NotContains(t, string(unmeasured), "disclosure_duration_ms",
		"a zero must not reach the app as a measurement")
}
