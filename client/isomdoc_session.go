package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/isomdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage/db"
)

// ============================================================
// ROUTING org-iso-mdoc INTO THE SESSION
// ============================================================
//
// The Digital Credentials API delivers two unrelated things under one app-level
// entry point. Three of its protocol identifiers carry OpenID4VP and are handled
// by eudi/openid4vp; the fourth, "org-iso-mdoc", carries ISO/IEC 18013-5's own
// DeviceRequest and answers with a DeviceResponse. That one is routed here.
//
// The split is at this layer rather than inside the OpenID4VP client because the
// two produce different things: an Authorization Response versus an HPKE-sealed
// DeviceResponse, from a request that has no client_id, nonce, DCQL query or
// response_mode to parse. See the DcApiProtocolIsoMdoc comment in
// eudi/openid4vp/dc_api.go.
//
// Almost nothing the user sees is different either. The consent screen is the
// same DisclosurePlan, answered with the same SessionPermissionInteractionPayload,
// and the response reaches the app on the same SessionState.DcApiResponse, so an
// app that can already show an OpenID4VP DC API session needs no new code to show
// this one.
//
// The exception is SessionState.ZeroKnowledge, which only this transport can set:
// it says whether the wallet answered with a proof or with a signed disclosure,
// and an app that wants to tell the user which of the two happened has to read it.
// Ignoring it costs nothing beyond that.

// isoMdocSession drives one org-iso-mdoc exchange.
//
// It owns the park-for-consent handshake, which is the only stateful part: the
// exchange itself runs to completion inside isomdoc.Session.Respond, and that
// call blocks on the wallet's Disclose, which blocks on the user.
type isoMdocSession struct {
	session   *session
	discloser *isomdoc.WalletDiscloser

	// answers carries the user's verdict to the parked goroutine. Buffered so
	// nobody blocks, mirroring openid4vpSession.
	answers chan *isoMdocConsentAnswer

	// awaiting is true only while the session goroutine is parked in
	// RequestConsent, i.e. only while an answer has somewhere to go. Claiming it
	// by CAS is what makes an answer exclusive.
	awaiting atomic.Bool

	// dismissed is latched by Dismiss. A dismissal can arrive before the
	// permission window opens — the request is still being parsed and the reader
	// authenticated — where it would be discarded; RequestConsent reads the latch
	// and refuses immediately rather than showing a screen nobody is waiting on.
	dismissed atomic.Bool

	// consentAt is when the user answered, set in RequestConsent and read at the
	// end of run. Both happen on the session goroutine -- RequestConsent is the
	// Discloser callback, invoked from inside Respond -- so this needs no lock.
	//
	// It exists to time the half of the exchange the wallet controls. Bracketing
	// from the request instead would measure how long the user spent reading the
	// screen, which is the dominant term and tells us nothing.
	consentAt time.Time
}

// consentVerdict is what the user decided about a disclosure.
//
// A named type rather than a bool: the verdict travels as a bare argument to
// answer, and at a call site `iso.answer(false, nil)` says nothing about what
// false means -- refused, not-yet-asked, and failed-to-ask all read the same.
// `iso.answer(consentDenied, nil)` says which one it is.
type consentVerdict int

const (
	// consentDenied is the zero value deliberately: a verdict nobody set is a
	// refusal, which is the safe reading for a disclosure.
	consentDenied consentVerdict = iota
	consentGranted
)

// consentVerdictFrom converts the app-facing boolean into a verdict.
//
// The conversion lives here, at the one boundary that has to do it:
// SessionPermissionInteractionPayload.Granted is part of the published client
// API and shared with the OpenID4VP and OpenID4VCI paths, so it stays a bool.
// Everything inside this session speaks consentVerdict instead.
func consentVerdictFrom(granted bool) consentVerdict {
	if granted {
		return consentGranted
	}
	return consentDenied
}

type isoMdocConsentAnswer struct {
	verdict consentVerdict
	choices []clientmodels.DisclosureDisconSelection
}

// newIsoMdocSession starts the exchange on its own goroutine and returns a
// dismisser bound to it.
func (client *Client) newIsoMdocSession(
	data []byte,
	origin string,
	session *session,
) *isoMdocSession {
	iso := &isoMdocSession{
		session: session,
		answers: make(chan *isoMdocConsentAnswer, 1),
	}

	// The wallet behind the session, built from the same machinery the OpenID4VP
	// path uses: the same DCQL handlers search the same credentials, the same
	// instance selector spends them, and the same binder resolves the device key.
	// A second implementation of any of those is how a property that holds on one
	// transport stops holding on the other. See eudi/isomdoc/wallet.go.
	iso.discloser = isomdoc.NewWalletDiscloser(
		client.openid4vpClient.DcqlHandler(),
		services.NewMdocInstanceSelector(db.NewMdocStore(client.eudiStorage.Db())),
		services.NewMdocDeviceKeyBinder(db.NewMdocDeviceKeyStore(client.eudiStorage.Db())),
		iso,
	).WithReaderAuthorizer(schemeReaderAuthorizer{validators: &openid4vp.DefaultQueryValidatorFactory{}})

	session.isoMdocSession = iso
	go iso.run(client, data, origin)
	return iso
}

// run performs the whole exchange and reports its outcome on the session state.
func (iso *isoMdocSession) run(client *Client, data []byte, origin string) {
	// Released on every path out, including the successful one, where releasing
	// what Commit already spent is a no-op. Respond releases too; this covers the
	// paths that never reach it.
	defer iso.discloser.Release()

	request, err := isomdoc.RequestFromDcApi(data, origin)
	if err != nil {
		iso.fail("org-iso-mdoc: %v", err)
		return
	}

	// Reader authentication is verified against the wallet's VERIFIER trust
	// model — the same anchors that authenticate an OpenID4VP relying party —
	// rather than the issuer one. A request from a reader this wallet cannot
	// authenticate is not served: that policy mirrors OpenID4VP's, where an
	// authorization request whose verifier cannot be authenticated never reaches
	// a consent screen, and it is the wallet's own choice rather than something
	// 18013-5 requires. See mdoc.VerifyReaderAuth.
	// ZkSystems is whatever the application registered with client.WithZkProver,
	// and nil when it registered nothing. Nil is the ordinary case, not an error:
	// it routes an AV request to the plain A.6 presentation instead of failing
	// it. The session reads the reader's zkRequest either way and takes the ZK
	// branch only when a prover is present, so nothing on this path knows or
	// cares which kind of build it is in.
	mdocSession := &isomdoc.Session{
		Verifier:  mdoc.NewVerifierFromTrustSource(&client.openid4vpClient.Configuration.Verifiers),
		Discloser: iso.discloser,
		ZkSystems: client.zkSystems,
	}

	sealed, err := mdocSession.Respond(request)
	if err != nil {
		iso.fail("org-iso-mdoc: %v", err)
		return
	}

	response, err := dcApiResponseData(sealed)
	if err != nil {
		iso.fail("org-iso-mdoc: %v", err)
		return
	}

	// Handed back to the platform the same way an OpenID4VP DC API response is,
	// on the same state field, so the app returns it without knowing which
	// protocol produced it.
	iso.session.State.DcApiResponse = response

	// A refusal is a well-formed response, not a failure: 8.3.2.1.2.2 expresses
	// "you cannot have this" as status 0 with a documentError per document, so
	// Respond returns cleanly and the reader is told the outcome either way.
	// That makes the sealed response useless for telling the two apart, and
	// reporting Success for both put a "your data was shared" screen in front of
	// someone who had just declined to share it.
	//
	// Disclosed() is the discloser's own record of what actually left the wallet,
	// and is empty both when the user refused and when nothing the reader asked
	// for could be served. Neither is a success, and Dismissed is what the
	// OpenID4VP path reports when a user declines, so the app's existing handling
	// for it applies unchanged.
	disclosedSomething := outcomeOf(len(iso.discloser.Disclosed())) == clientmodels.Status_Success
	if disclosedSomething {
		// Reported so the app can say which kind of presentation was made. Read
		// from the session rather than inferred from the request: a reader that
		// offers circuits still gets the plain fallback when none of them matches.
		iso.session.State.ZeroKnowledge = mdocSession.ZeroKnowledge
		iso.session.State.Status = clientmodels.Status_Success
	} else {
		iso.session.State.Status = clientmodels.Status_Dismissed
	}
	// The wallet's own latency, tap to sealed response: candidate selection,
	// deviceAuth, the ZK proof when one is made -- which dominates, and which
	// includes decompressing and parsing the matched circuit, deferred to here
	// by the startup cache -- and the HPKE seal. Logged rather than measured
	// from two log lines so the number survives log filtering and carries no
	// clock skew between them.
	if !iso.consentAt.IsZero() {
		eudi.Logger.Infof("org-iso-mdoc: disclosure completed %v after consent", time.Since(iso.consentAt).Round(time.Millisecond))
	}

	// Only for a session that actually disclosed, matching OpenID4VP: a request
	// the wallet refuses, a permission the user denies and a session the app
	// dismisses all leave no disclosure log there, and an org-iso-mdoc exchange
	// that returns nothing but documentErrors is the same event wearing ISO's
	// clothes. Logging it anyway filled the activity log with entries saying a
	// disclosure had happened, listing nothing, for readers the user had turned
	// down -- which is worse than silence, because the one thing the log is for
	// is being the only record the user has of an unlinkable presentation.
	//
	// Not the same rule as "no credentials in the entry": OpenID4VP DOES log a
	// session that succeeded while the user skipped every optional credential
	// set. The question is whether the disclosure happened, not how much of it
	// travelled -- and org-iso-mdoc has no optional sets, so here the two
	// coincide.
	if disclosedSomething {
		iso.logDisclosure(client)
	}
	iso.session.finish()
}

// logDisclosure records the session in the activity log, as the OpenID4VP path
// does on its own success.
//
// Logged even when nothing was disclosed -- the user refused, or an
// unauthenticated reader was entitled to nothing -- for the same reason the
// OpenID4VP path does: the user should be able to see which verifier they had a
// session with, whether or not it got anything.
//
// It matters more here than there. A zero-knowledge presentation is designed to
// be unlinkable and reveals nothing to anyone observing it, so this log is the
// only place the user will ever be able to see that they proved their age to
// somebody. A session that completed silently would be, to them, a session that
// never happened.
//
// A failure to log does not fail the session: the response has already been
// sealed and the verifier is waiting on it, and losing the record is worse than
// nothing but far better than losing the disclosure the user just approved.
func (iso *isoMdocSession) logDisclosure(client *Client) {
	locale := client.locale()
	logs := make([]clientmodels.LogCredential, 0, len(iso.discloser.Disclosed()))
	for _, disclosed := range iso.discloser.Disclosed() {
		logs = append(logs, services.BuildMdocLogCredential(
			client.eudiStorage, disclosed.Batch, disclosed.ClaimPaths, disclosed.Claims, locale))
	}

	logService := services.NewEudiLogService(client.eudiStorage, locale)
	if err := logService.AddDisclosureLog(
		clientmodels.Protocol_ISO18013_5, iso.session.State.Requestor, logs); err != nil {
		eudi.Logger.Errorf("failed to store org-iso-mdoc disclosure log: %v", err)
	}
}

// dcApiResponseData builds the `data` member the app hands back to the platform.
//
// A JSON object, not a bare string, because that is what SessionState.DcApiResponse
// already carries for OpenID4VP — `{"vp_token": …}` unencrypted, `{"response": …}`
// encrypted (see openid4vp.createDcApiResponse). An app that returns the field
// verbatim therefore needs no branch on protocol, and adding one shape for one
// protocol would put that branch in the app instead.
//
// The member is "response" and the value is base64url of the
// `["dcapi", {enc, cipherText}]` envelope. This was inferred before ISO/IEC
// TS 18013-7 was available and is now confirmed by it — Annex C.3, verbatim:
//
//	{ "response" : Base64EncryptedResponse }
//	EncryptedResponse = ["dcapi", EncryptedResponseData]
//	EncryptedResponseData = {"enc": bstr, "cipherText": bstr}
//
// "Where Base64EncryptedResponse contains the cbor encoded EncryptedResponse […]
// as a base64-url-without-padding string." Which is what RawURLEncoding emits.
func dcApiResponseData(sealed mdoc.DCAPIEncryptedResponse) (string, error) {
	// MarshalCBOR is DCAPIEncryptedResponse's own and writes the envelope; this is
	// not a struct encode.
	encoded, err := cbor.Marshal(sealed)
	if err != nil {
		return "", fmt.Errorf("encode sealed response: %w", err)
	}

	data, err := json.Marshal(map[string]any{
		"response": base64.RawURLEncoding.EncodeToString(encoded),
	})
	if err != nil {
		return "", fmt.Errorf("encode response data member: %w", err)
	}
	return string(data), nil
}

func (iso *isoMdocSession) fail(message string, args ...any) {
	eudi.Logger.Errorf(message, args...)
	iso.session.State.Status = clientmodels.Status_Error
	iso.session.State.Error = &clientmodels.SessionError{
		WrappedError: fmt.Sprintf(message, args...),
	}
	iso.session.finish()
}

// RequestConsent shows the reader's request and parks until the user answers.
//
// Implements isomdoc.ConsentHandler. Returning no choices is a refusal and is
// expected rather than exceptional: it produces a response carrying documentErrors
// rather than a failed session, which is what an mdoc says when it is not
// answering.
func (iso *isoMdocSession) RequestConsent(
	request isomdoc.ConsentRequest,
) ([]clientmodels.DisclosureDisconSelection, error) {
	// Dismissed before the window opened. Answering with a refusal rather than an
	// error keeps a user who backed out from seeing a failure screen.
	if iso.dismissed.Load() {
		return nil, nil
	}

	state := iso.session.State
	state.Status = clientmodels.Status_RequestPermission
	state.Type = clientmodels.Type_Disclosure
	state.Protocol = clientmodels.Protocol_ISO18013_5
	state.Requestor = iso.requestor(request)
	state.DisclosurePlan = request.Plan

	iso.awaiting.Store(true)

	// Read again now the window is open, not only before it. Dismiss latches
	// this flag and THEN answers, and its answer is dropped when it arrives
	// before the window opened -- its CompareAndSwap finds awaiting still false.
	// So a dismissal landing between the check above and the line above was lost
	// entirely, and the receive below then blocked on a channel nobody would
	// ever write to: this goroutine, the session and its reserved instances
	// leaked for the life of the process, with the app showing a consent screen
	// whose answer went nowhere.
	//
	// Checking on both sides of the store leaves no gap. A dismissal before the
	// window is caught by the first read; one after it is caught by this read or,
	// if it lands later still, by its own answer, which now finds awaiting true
	// and is delivered normally.
	if iso.dismissed.Load() {
		iso.awaiting.Store(false)
		return nil, nil
	}

	iso.session.dispatchState()

	answer := <-iso.answers
	iso.awaiting.Store(false)

	iso.consentAt = time.Now()

	if answer == nil || answer.verdict != consentGranted {
		return nil, nil
	}
	return answer.choices, nil
}

// requestor is who the user is being told is asking — which, here, is nobody.
//
// An org-iso-mdoc request carries no client_id and no verifier metadata. Nothing
// in it names the caller, so the wallet has an address and no identity, and it
// says so: Anonymous, with the origin in Origin and Name left empty.
//
// The alternative was to put the origin in Name and mark it unverified, which is
// what this did first and what the OpenID4VP DC API path still does. It reads as
// a party whose name we could not check. But there is no name to check, and that
// rank already holds an OpenID4VCI issuer whose genuine metadata merely is not
// signed. Making those two indistinguishable is worst in exactly this flow,
// where the question in front of the user is whether to prove their age to a
// stranger. irmago #724 O1 settles it this way; the UI owes an anonymous
// requestor a different screen, not a different badge.
//
// Verified stays false even when readerAuth succeeded, and the reason is
// unchanged by any of the above: reader authentication proves that some
// certificate chained to a trusted anchor, never that it belongs to this origin.
// Conflating the two would let a trusted reader lend its badge to any origin that
// replayed its request.
func (iso *isoMdocSession) requestor(request isomdoc.ConsentRequest) clientmodels.TrustedParty {
	origin := request.Origin
	return clientmodels.TrustedParty{
		Anonymous: true,
		Origin:    &origin,
		Verified:  false,
	}
}

// answer delivers the user's verdict, exactly once.
//
// Returns false when nobody is parked, which is how a duplicate answer, or one
// arriving after the session already unwound, is dropped rather than left to block
// on a channel no goroutine will read.
func (iso *isoMdocSession) answer(verdict consentVerdict, choices []clientmodels.DisclosureDisconSelection) bool {
	if !iso.awaiting.CompareAndSwap(true, false) {
		return false
	}
	iso.answers <- &isoMdocConsentAnswer{verdict: verdict, choices: choices}
	return true
}

// Dismiss dismisses this session. A dismissal is a denial, so it travels the same
// channel the user's own "no" does.
func (iso *isoMdocSession) Dismiss() {
	iso.dismissed.Store(true)
	iso.answer(consentDenied, nil)
}

// outcomeOf turns "how many credentials actually left the wallet" into the
// status the app renders.
//
// Split out because it is the whole of the rule and the rule is easy to get
// wrong: an org-iso-mdoc exchange that discloses nothing still completes
// successfully at every layer below this one -- the response is well-formed,
// sealed and delivered -- so "Respond returned no error" is not the same
// question as "did the user share anything", and answering the first one where
// the second was meant showed a success screen to someone who had just refused.
func outcomeOf(disclosed int) clientmodels.SessionStatus {
	if disclosed == 0 {
		return clientmodels.Status_Dismissed
	}
	return clientmodels.Status_Success
}
