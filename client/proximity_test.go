package client

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/proximity"
)

// ============================================================
// THE SYNCHRONOUS/ASYNCHRONOUS CONSENT BRIDGE
// ============================================================
//
// proximity.Session.Handle is synchronous and has to stop mid-transaction to ask a
// human; the app answers later through HandleUserInteraction. proximityConsent is
// what parks in between, and it is the one genuinely new mechanism in the proximity
// wiring — everything else it touches was already exercised by the OpenID4VP flow.
//
// Every failure mode here is a hang rather than a wrong answer, which is why each
// test carries its own deadline: a regression that deadlocks would otherwise stall
// the suite rather than fail it, and `go test` would report a panic from an
// unrelated place.

// recordingHandler captures the states dispatched to the app.
type recordingHandler struct {
	states chan clientmodels.SessionState
}

func newRecordingHandler() *recordingHandler {
	return &recordingHandler{states: make(chan clientmodels.SessionState, 8)}
}

func (h *recordingHandler) UpdateSession(state clientmodels.SessionState) {
	select {
	case h.states <- state:
	default: // never block the session on a slow test
	}
}

// newTestConsent builds a proximityConsent over a bare session, with no storage or
// wallet behind it. Enough for the parking behaviour, which is all this file is
// about: RequestConsent reaches the channel without touching either.
func newTestConsent(t *testing.T) (*proximityConsent, *recordingHandler) {
	t.Helper()

	handler := newRecordingHandler()
	clientSession := &session{
		State:   &clientmodels.SessionState{Id: 1},
		handler: handler,
	}
	consent := &proximityConsent{
		session: clientSession,
		answers: make(chan *proximityAnswer, 1),
	}
	clientSession.proximityConsent = consent
	return consent, handler
}

// consentRequest is a request with no authenticated reader and no scheme data, so
// RequestConsent goes straight to parking rather than running the authorization
// check. The plan is what the UI would render; its contents do not matter here.
func consentRequest() proximity.ConsentRequest {
	return proximity.ConsentRequest{
		Plan:      &clientmodels.DisclosurePlan{},
		Documents: []proximity.RequestedDocument{{DocType: "eu.europa.ec.av.1"}},
	}
}

// await runs RequestConsent on its own goroutine and yields the result, so a test
// can fail on a deadline instead of hanging.
func await(t *testing.T, consent *proximityConsent) <-chan []clientmodels.DisclosureDisconSelection {
	t.Helper()
	done := make(chan []clientmodels.DisclosureDisconSelection, 1)
	go func() {
		choices, err := consent.RequestConsent(consentRequest())
		if err != nil {
			t.Errorf("RequestConsent: %v", err)
		}
		done <- choices
	}()
	return done
}

// TestProximityConsentParksUntilTheUserAnswers is the happy path: the request is
// dispatched to the app, RequestConsent blocks, and the answer delivered through
// HandleUserInteraction is what comes back.
func TestProximityConsentParksUntilTheUserAnswers(t *testing.T) {
	consent, handler := newTestConsent(t)
	result := await(t, consent)

	// The app is asked.
	select {
	case state := <-handler.states:
		if state.Status != clientmodels.Status_RequestPermission {
			t.Fatalf("dispatched status = %v, want RequestPermission", state.Status)
		}
		if state.Protocol != clientmodels.Protocol_ISO18013_5 {
			t.Errorf("dispatched protocol = %v, want %v", state.Protocol, clientmodels.Protocol_ISO18013_5)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the app was never asked for permission")
	}

	// And it has not returned yet — the whole point of the bridge.
	select {
	case <-result:
		t.Fatal("RequestConsent returned before the user answered")
	case <-time.After(50 * time.Millisecond):
	}

	chosen := []clientmodels.DisclosureDisconSelection{{
		Credentials: []clientmodels.SelectedCredential{{CredentialHash: "abc"}},
	}}
	if !consent.answer(&proximityAnswer{choices: chosen}) {
		t.Fatal("answer was not delivered to the parked request")
	}

	select {
	case choices := <-result:
		if len(choices) != 1 || len(choices[0].Credentials) != 1 ||
			choices[0].Credentials[0].CredentialHash != "abc" {
			t.Errorf("got %+v, want the choices the user made", choices)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RequestConsent did not return after the user answered")
	}
}

// TestProximityConsentRefusalYieldsNoChoices: the user said no. Nothing is
// disclosed, and — importantly — this is not an error. The reader receives a
// well-formed response carrying documentErrors.
func TestProximityConsentRefusalYieldsNoChoices(t *testing.T) {
	consent, handler := newTestConsent(t)
	result := await(t, consent)
	<-handler.states

	consent.answer(nil)

	select {
	case choices := <-result:
		if len(choices) != 0 {
			t.Errorf("a refusal produced %d choices, want none", len(choices))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RequestConsent did not return after a refusal")
	}
}

// TestProximityConsentDismissalBeforeTheWindowOpensIsNotLost is the race the
// arm-then-check-latch order exists for.
//
// A dismissal that arrives before RequestConsent has armed its window would, with
// the naive ordering, find nothing parked and be dropped — and RequestConsent would
// then park forever on a session the user had already walked away from. Handle
// would never return, and the transaction would hang rather than fail.
func TestProximityConsentDismissalBeforeTheWindowOpensIsNotLost(t *testing.T) {
	consent, _ := newTestConsent(t)

	// Dismissed first, before anything asks for consent.
	consent.dismiss()

	result := await(t, consent)

	select {
	case choices := <-result:
		if len(choices) != 0 {
			t.Errorf("a dismissed session produced %d choices, want none", len(choices))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RequestConsent parked forever on an already-dismissed session")
	}
}

// TestProximityConsentDeliversOnlyOneAnswer: a dismissal racing the user's own
// choice must not leave a stray value in the channel for a later request to pick
// up as though it were its own answer.
func TestProximityConsentDeliversOnlyOneAnswer(t *testing.T) {
	consent, handler := newTestConsent(t)
	result := await(t, consent)
	<-handler.states

	if !consent.answer(&proximityAnswer{choices: nil}) {
		t.Fatal("the first answer was not delivered")
	}
	if consent.answer(&proximityAnswer{choices: nil}) {
		t.Error("a second answer was delivered; the window should have closed")
	}
	// A dismissal arriving after the user already answered is likewise a no-op.
	consent.dismiss()

	select {
	case <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("RequestConsent did not return")
	}

	// Nothing left behind for the next await to consume.
	select {
	case stray := <-consent.answers:
		t.Errorf("a stray answer was left in the channel: %+v", stray)
	default:
	}
}

// TestProximityConsentRoutesThroughHandleUserInteraction closes the loop: the path
// the app actually takes, rather than calling answer directly.
func TestProximityConsentRoutesThroughHandleUserInteraction(t *testing.T) {
	consent, handler := newTestConsent(t)

	client := &Client{sessionManager: sessionManager{
		Sessions:       map[int]*session{1: consent.session},
		SessionHandler: handler,
	}}
	consent.session.client = client

	result := await(t, consent)
	<-handler.states

	err := client.HandleUserInteraction(clientmodels.SessionUserInteraction{
		SessionId: 1,
		Type:      clientmodels.UI_Permission,
		Payload: clientmodels.SessionPermissionInteractionPayload{
			Granted: true,
			DisclosureChoices: []clientmodels.DisclosureDisconSelection{{
				Credentials: []clientmodels.SelectedCredential{{CredentialHash: "xyz"}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("HandleUserInteraction: %v", err)
	}

	select {
	case choices := <-result:
		if len(choices) != 1 || choices[0].Credentials[0].CredentialHash != "xyz" {
			t.Errorf("got %+v, want the choices the app delivered", choices)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the app's answer never reached the parked RequestConsent")
	}
}

// TestProximityConsentDeniedThroughHandleUserInteraction: the same path, with the
// user pressing no. Granted=false must not be mistaken for an empty-but-granted
// selection, which would look identical if only the choices were read.
func TestProximityConsentDeniedThroughHandleUserInteraction(t *testing.T) {
	consent, handler := newTestConsent(t)

	client := &Client{sessionManager: sessionManager{
		Sessions:       map[int]*session{1: consent.session},
		SessionHandler: handler,
	}}
	consent.session.client = client

	result := await(t, consent)
	<-handler.states

	if err := client.HandleUserInteraction(clientmodels.SessionUserInteraction{
		SessionId: 1,
		Type:      clientmodels.UI_Permission,
		Payload:   clientmodels.SessionPermissionInteractionPayload{Granted: false},
	}); err != nil {
		t.Fatalf("HandleUserInteraction: %v", err)
	}

	select {
	case choices := <-result:
		if len(choices) != 0 {
			t.Errorf("a denial produced %d choices", len(choices))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the denial never reached the parked RequestConsent")
	}
}
