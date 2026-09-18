package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/mdocpresent"
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
// What is NOT different is anything the user sees. The consent screen is the same
// DisclosurePlan, answered with the same SessionPermissionInteractionPayload, and
// the response reaches the app on the same SessionState.DcApiResponse. An app that
// can already show an OpenID4VP DC API session shows this one with no new code.

// isoMdocSession drives one org-iso-mdoc exchange.
//
// It owns the park-for-consent handshake, which is the only stateful part: the
// exchange itself runs to completion inside mdocpresent.Session.Respond, and that
// call blocks on the wallet's Disclose, which blocks on the user.
type isoMdocSession struct {
	session   *session
	discloser *mdocpresent.WalletDiscloser

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
}

type isoMdocConsentAnswer struct {
	granted bool
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
	// transport stops holding on the other. See eudi/mdocpresent/wallet.go.
	iso.discloser = mdocpresent.NewWalletDiscloser(
		client.openid4vpClient.DcqlHandler(),
		services.NewMdocInstanceSelector(db.NewMdocStore(client.eudiStorage.Db())),
		services.NewMdocDeviceKeyBinder(db.NewMdocDeviceKeyStore(client.eudiStorage.Db())),
		iso,
	)

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

	request, err := mdocpresent.RequestFromDcApi(data, origin)
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
	mdocSession := &mdocpresent.Session{
		Verifier:  mdoc.NewVerifierFromTrustSource(&client.openid4vpClient.Configuration.Verifiers),
		Discloser: iso.discloser,
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
	iso.session.State.Status = clientmodels.Status_Success
	iso.session.finish()
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
// Implements mdocpresent.ConsentHandler. Returning no choices is a refusal and is
// expected rather than exceptional: it produces a response carrying documentErrors
// rather than a failed session, which is what an mdoc says when it is not
// answering.
func (iso *isoMdocSession) RequestConsent(
	request mdocpresent.ConsentRequest,
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
	iso.session.dispatchState()

	answer := <-iso.answers
	iso.awaiting.Store(false)

	if answer == nil || !answer.granted {
		return nil, nil
	}
	return answer.choices, nil
}

// requestor is who the user is being told is asking.
//
// The origin, and never more. An org-iso-mdoc request carries no client_id and no
// verifier metadata, so the only identity the wallet has for the caller is the one
// the platform authenticated — and it is the value the response is
// cryptographically bound to, so it is also the truthful one to show.
//
// Verified stays false even when readerAuth succeeded. It reports that the party
// NAMED here was authenticated, and what reader authentication proves is that some
// certificate chained to a trusted anchor, not that it belongs to this origin.
// Conflating the two would let a trusted reader lend its badge to any origin that
// replayed its request.
func (iso *isoMdocSession) requestor(request mdocpresent.ConsentRequest) clientmodels.TrustedParty {
	return clientmodels.TrustedParty{
		Name:     request.Origin,
		Verified: false,
	}
}

// answer delivers the user's verdict, exactly once.
//
// Returns false when nobody is parked, which is how a duplicate answer, or one
// arriving after the session already unwound, is dropped rather than left to block
// on a channel no goroutine will read.
func (iso *isoMdocSession) answer(granted bool, choices []clientmodels.DisclosureDisconSelection) bool {
	if !iso.awaiting.CompareAndSwap(true, false) {
		return false
	}
	iso.answers <- &isoMdocConsentAnswer{granted: granted, choices: choices}
	return true
}

// Dismiss dismisses this session. A dismissal is a denial, so it travels the same
// channel the user's own "no" does.
func (iso *isoMdocSession) Dismiss() {
	iso.dismissed.Store(true)
	iso.answer(false, nil)
}
