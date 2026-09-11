package client

import (
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
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

// ---------------------------------------------------------------------------
// Ending a transaction
// ---------------------------------------------------------------------------

// failingDiscloser stands in for a wallet that cannot answer: storage
// unavailable, the credential unreadable — a local fault the reader cannot be
// told about, which is the only thing Session.Handle returns an error for.
type failingDiscloser struct{}

func (failingDiscloser) Disclose(proximity.DisclosureRequest) ([]proximity.Selection, error) {
	return nil, errors.New("the wallet could not read its own storage")
}

// stubBinder satisfies the device key binder without any storage. Never reached:
// the discloser above fails first.
type stubBinder struct{}

func (stubBinder) HolderForDeviceKey(*ecdsa.PublicKey) (mdoc.Holder, error) {
	return nil, errors.New("no device keys in this test")
}

// newTestProximitySession builds a ProximitySession over a bare client, enough
// for finish() to dispatch and delete without any storage behind it.
func newTestProximitySession(t *testing.T) (*ProximitySession, *recordingHandler) {
	t.Helper()

	handler := newRecordingHandler()
	client := &Client{sessionManager: sessionManager{Sessions: map[int]*session{}}}
	clientSession := &session{
		State:   &clientmodels.SessionState{Id: 1, Type: clientmodels.Type_Disclosure},
		handler: handler,
		client:  client,
	}
	consent := &proximityConsent{session: clientSession, answers: make(chan *proximityAnswer, 1)}
	clientSession.proximityConsent = consent

	inner, err := proximity.NewSession(proximity.SessionConfig{
		Discloser:  failingDiscloser{},
		DeviceKeys: stubBinder{},
		Readers:    mdoc.NewVerifier(nil),
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return &ProximitySession{session: clientSession, inner: inner, consent: consent}, handler
}

// TestProximityHandleDestroysKeysOnLocalFault: 9.1.1.4 has both parties destroy
// their session keys when the session ends, and a local fault ends it — nothing
// further is answered after one. Close and Dismiss both destroyed; this path did
// not, leaving the AES-GCM keys and the message counters alive for as long as the
// object was referenced.
func TestProximityHandleDestroysKeysOnLocalFault(t *testing.T) {
	p, _ := newTestProximitySession(t)

	qr, err := p.EngagementQR()
	if err != nil {
		t.Fatalf("EngagementQR: %v", err)
	}
	reader := proximity.NewReader(proximity.ReaderConfig{})
	if err := reader.Engage(qr); err != nil {
		t.Fatalf("Engage: %v", err)
	}
	// An mDL mandatory element, which 7.2.1 forbids making reader authentication a
	// precondition for. This reader carries no readerAuth, so anything else would
	// be refused before the wallet was ever asked — and the fault under test
	// happens when it is asked.
	request, err := reader.Request(mdoc.ItemsRequest{
		DocType:    mdoc.MDLDocType,
		NameSpaces: map[string]mdoc.DataElements{mdoc.MDLNameSpace: {"family_name": false}},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}

	if _, err := p.Handle(request); err == nil {
		t.Fatal("a discloser that cannot read its storage must fail the transaction")
	}
	if !p.inner.Terminated() {
		t.Error("the session must be terminated — and its keys destroyed — when it ends in a fault")
	}
	if p.session.State.Status != clientmodels.Status_Error {
		t.Errorf("expected the session to report an error, got %q", p.session.State.Status)
	}
}

// TestProximityHandleIgnoresMessagesAfterTheSessionEnded: a reader that sends a
// straggler or a duplicate part on its way out gets the same "session is
// terminated" from the inner session as any other post-termination message.
// Treated as a fault, that overwrites a finished, successful transaction with
// Status_Error and reports a failure the user never had.
func TestProximityHandleIgnoresMessagesAfterTheSessionEnded(t *testing.T) {
	p, handler := newTestProximitySession(t)

	// End it the way a completed transaction does, without going through succeed(),
	// which needs the storage this bare session does not have.
	if _, err := p.inner.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	p.session.State.Status = clientmodels.Status_Success

	reply, err := p.Handle([]byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("a late message is not a fault of this session: %v", err)
	}
	if reply != nil {
		t.Error("there is nothing to reply with on a session that has ended")
	}
	if p.session.State.Status != clientmodels.Status_Success {
		t.Errorf("a straggler must not overwrite the outcome, got %q", p.session.State.Status)
	}
	if p.session.State.Error != nil {
		t.Errorf("no error should be recorded, got %v", p.session.State.Error)
	}
	for {
		select {
		case state := <-handler.states:
			if state.Status == clientmodels.Status_Error {
				t.Error("an error state was dispatched to the app for a session that succeeded")
			}
			continue
		default:
		}
		break
	}
}

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
