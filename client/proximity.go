package client

import (
	"encoding/base64"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/proximity"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/utils"
)

// ============================================================
// ISO 18013-5 PROXIMITY, WIRED TO THE WALLET
// ============================================================
//
// eudi/proximity implements the transaction; this file is what lets the app run
// one. It supplies the three things that package deliberately does not own — which
// credentials exist, who the user is being asked by, and how to ask them — out of
// the machinery the OpenID4VP flow already uses, so a credential offered in person
// is the same credential offered online.
//
// # The one genuinely new problem: a synchronous transaction, an asynchronous user
//
// proximity.Session.Handle is synchronous. It is handed a message and returns the
// reply, and somewhere in the middle it has to stop and ask a human. The app's
// consent flow is the opposite shape: the session dispatches a state, the UI draws
// a screen, and an answer arrives later through HandleUserInteraction.
//
// So the bridge parks. RequestConsent dispatches the permission request and then
// blocks on a channel until the app answers, exactly as openid4vpSession.perform
// does around awaitPermission — including the arm-before-dispatch and
// compare-and-swap discipline, so a handler that answers synchronously is not lost
// and a dismissal racing the user's own answer delivers only one verdict.
//
// The consequence for the caller is the whole reason it is written down here:
// **Handle blocks for as long as the user takes to decide, so it must not be
// called on the UI thread.**

// ProximitySession is one ISO 18013-5 device retrieval transaction.
//
// The app drives it: show EngagementQR as a QR code, then pump whole messages
// through Handle as they arrive over BLE. Not safe for concurrent use — the
// underlying session's message counters must never repeat under one key (9.1.1.5).
type ProximitySession struct {
	session *session
	inner   *proximity.Session
	consent *proximityConsent

	// mu guards transport, which is set when a BLE run starts and read from the
	// platform's notification thread.
	mu        sync.Mutex
	transport *proximity.BLETransport

	closeOnce sync.Once
}

// NewProximitySession starts a proximity transaction and registers it under the
// caller-supplied session id, the same convention the other session entry points
// follow (the id is allocated by the Dart client so the UI can route state events
// without waiting for Go).
//
// Nothing has happened on the wire yet: the returned session holds an ephemeral
// key and an engagement, and waits to be handed the reader's first message.
func (client *Client) NewProximitySession(sessionId int) (*ProximitySession, error) {
	if client.eudiConf == nil {
		return nil, fmt.Errorf("proximity requires EUDI configuration")
	}

	clientSession := client.sessionManager.NewSession(sessionId)
	clientSession.State.Type = clientmodels.Type_Disclosure
	clientSession.State.Protocol = clientmodels.Protocol_ISO18013_5

	consent := &proximityConsent{session: clientSession, client: client}
	consent.answers = make(chan *proximityAnswer, 1)

	discloser := proximity.NewWalletDiscloser(
		client.openid4vpClient.DcqlHandler(),
		services.NewMdocInstanceSelector(db.NewMdocStore(client.eudiStorage.Db())),
		consent,
	)

	inner, err := proximity.NewSession(proximity.SessionConfig{
		Discloser:  discloser,
		DeviceKeys: services.NewMdocDeviceKeyBinder(db.NewMdocDeviceKeyStore(client.eudiStorage.Db())),
		// The SAME anchors that authenticate an OpenID4VP relying party. A reader
		// standing in front of the holder is not a different kind of party from one
		// reached over HTTPS, and giving proximity its own store would mean a
		// verifier the wallet refuses online being accepted in person.
		Readers: mdoc.NewVerifierFromTrustSource(&client.eudiConf.Verifiers),
	})
	if err != nil {
		client.sessionManager.DeleteSession(sessionId)
		return nil, fmt.Errorf("failed to start proximity session: %w", err)
	}

	proximitySession := &ProximitySession{session: clientSession, inner: inner, consent: consent}
	clientSession.dismisser = proximitySession
	return proximitySession, nil
}

// EngagementQR is the "mdoc:" URI to render as a QR code (8.2.2.3). It needs no
// network on either side: everything the reader needs to open the session is in the
// code.
func (p *ProximitySession) EngagementQR() (string, error) {
	return p.inner.EngagementQR()
}

// ServiceUUID is the BLE service this transaction advertises, which the reader
// broadcasts and the app scans for (8.3.3.1.1.3, unique per transaction).
func (p *ProximitySession) ServiceUUID() ([]byte, error) {
	return p.inner.ServiceUUID()
}

// Handle processes one complete message from the reader and returns the reply to
// send, or nil when there is nothing to say.
//
// Whole messages only: the caller reassembles BLE parts with mdoc.MessageAssembler
// first, and splits the reply with mdoc.ChunkMessage.
//
// **Blocks while the user decides.** Call it off the UI thread.
func (p *ProximitySession) Handle(message []byte) ([]byte, error) {
	// A message that arrives after the session is already over is not a fault of
	// this one. The inner session answers every post-termination message with the
	// same "session is terminated", whatever ended it — including the ordinary
	// ending, where the transaction succeeded and the reader sent a straggler or a
	// duplicate part on its way out. Passed to the branch below, that would
	// overwrite a finished, successful session with Status_Error and report a
	// failure the user never had. There is nothing to reply with either way, so it
	// is dropped here instead.
	if p.inner.Terminated() {
		return nil, nil
	}

	reply, err := p.inner.Handle(message)
	if err != nil {
		// 9.1.1.4 has the session keys destroyed when the session ends, and this is
		// an ending: Handle errors only on a local fault the reader cannot be told
		// about — consent, storage, signing — after which nothing more is answered.
		// Close and Dismiss both destroy; without this the AES-GCM keys and the
		// message counters stayed live for the lifetime of the object. Its return
		// is the termination message to send, and there is no longer a link to
		// send it on.
		_, _ = p.inner.Close()
		p.session.State.Status = clientmodels.Status_Error
		p.session.State.Error = &clientmodels.SessionError{
			ErrorType: string(clientmodels.Status_Error),
			Info:      err.Error(),
		}
		p.session.finish()
		return nil, err
	}

	if p.inner.Terminated() {
		p.succeed()
	}
	return reply, nil
}

// Close ends the session from this side, returning Table 20's termination message
// to send if the session was still live. 9.1.1.4 requires both parties to destroy
// their key material on termination, which Close does.
func (p *ProximitySession) Close() ([]byte, error) {
	message, err := p.inner.Close()
	p.succeed()
	return message, err
}

// Dismiss implements the session dismisser the app calls when the user walks away.
// A dismissal is a denial, so it travels the same channel the user's own "no" does.
func (p *ProximitySession) Dismiss() {
	p.consent.dismiss()
	_, _ = p.inner.Close()
	p.session.State.Status = clientmodels.Status_Dismissed
	p.session.finish()
}

// succeed finishes the session once, whichever path got there.
func (p *ProximitySession) succeed() {
	p.closeOnce.Do(func() {
		// A transaction that disclosed nothing is still a transaction the user had,
		// and the log is what lets them see it — the same reason the OpenID4VP
		// adapter logs an all-optional set the user skipped.
		logService := services.NewEudiLogService(p.session.client.eudiStorage, p.session.client.locale())
		if err := logService.AddDisclosureLog(p.session.State.Requestor, p.consent.credentialLogs); err != nil {
			eudi.Logger.Errorf("failed to store proximity disclosure log: %v", err)
		}
		if p.session.State.Status != clientmodels.Status_Error {
			p.session.State.Status = clientmodels.Status_Success
		}
		p.session.finish()
	})
}

// ---------------------------------------------------------------------------
// The consent bridge
// ---------------------------------------------------------------------------

// proximityAnswer is the verdict the app returns.
type proximityAnswer struct {
	choices []clientmodels.DisclosureDisconSelection
}

// proximityConsent adapts the app's asynchronous permission flow to the
// synchronous proximity.ConsentHandler interface.
type proximityConsent struct {
	session *session
	client  *Client

	answers  chan *proximityAnswer
	awaiting atomic.Bool
	// dismissed latches a dismissal that arrived before the permission window
	// opened, so it is not lost and does not leave Handle parked forever.
	dismissed atomic.Bool

	credentialLogs []clientmodels.LogCredential
}

var _ proximity.ConsentHandler = (*proximityConsent)(nil)

// RequestConsent shows the request and parks until the app answers.
func (c *proximityConsent) RequestConsent(request proximity.ConsentRequest) ([]clientmodels.DisclosureDisconSelection, error) {
	requestor, relyingParty := c.identify(request.Documents)
	c.session.State.Requestor = requestor

	// Authorization, not authentication: the reader proved who it is, and this asks
	// whether that party may ask for these attributes at all. The OpenID4VP path
	// applies the same check against the same certificate extension, so a verifier
	// that cannot request an attribute online cannot request it in person either.
	//
	// A reader carrying no scheme extension has no authorized set to check against.
	// It is not refused here — reader authentication and the 7.2.1 release policy
	// have already decided what it may receive — because refusing would also refuse
	// every conformant 18013-5 reader that is simply not part of Yivi's scheme.
	if relyingParty != nil {
		validator := &scheme.SchemeQueryValidator{RelyingParty: relyingParty}
		if err := validator.ValidateCredentialQueries(dcql.CredentialQueryInfos(request.Query)); err != nil {
			// Reported as a refusal rather than an error: the reader learns it is not
			// getting the documents (documentErrors, status 0) and the session stays
			// well-formed, which is more useful than dropping the link. The user is
			// not asked to approve something the request was never entitled to.
			eudi.Logger.Warnf("proximity: reader is not authorized for its own request: %v", err)
			c.session.State.Error = &clientmodels.SessionError{
				ErrorType: string(clientmodels.Status_Error),
				Info:      err.Error(),
			}
			return nil, nil
		}
	}

	c.session.State.Status = clientmodels.Status_RequestPermission
	c.session.State.Type = clientmodels.Type_Disclosure
	c.session.State.Protocol = clientmodels.Protocol_ISO18013_5
	c.session.State.DisclosurePlan = request.Plan
	c.session.proximityConsent = c

	// Armed before dispatching, and the dismissal latch read after arming: a handler
	// may answer synchronously, and a dismissal that ran in between delivers its own
	// answer. Same discipline as openid4vpSession.requestPermission, for the same
	// reason — an answer arriving before the window opens is otherwise discarded and
	// this call never returns.
	c.awaiting.Store(true)
	if c.dismissed.Load() {
		c.answer(nil)
	} else {
		c.session.dispatchState()
	}

	answer := <-c.answers
	if answer == nil {
		return nil, nil // dismissed, or the user declined
	}
	return answer.choices, nil
}

// answer hands a verdict to the parked RequestConsent and reports whether it was
// delivered. Only the first answer per window is, so a dismissal racing the user's
// own choice is a no-op rather than a stray value nothing reads.
func (c *proximityConsent) answer(a *proximityAnswer) bool {
	if !c.awaiting.CompareAndSwap(true, false) {
		return false
	}
	c.answers <- a
	return true
}

func (c *proximityConsent) dismiss() {
	c.dismissed.Store(true)
	c.answer(nil)
}

// identify turns the authenticated reader into something to show the user, and
// into the authorized attribute sets to hold its request to.
//
// Both come from the reader's own certificate, which is the only identity a
// proximity transaction has: there is no metadata document to fetch and no origin
// the platform authenticated. A reader that did not authenticate is named as
// unverified rather than not shown, because the user still has to be told that
// something is asking.
func (c *proximityConsent) identify(documents []proximity.RequestedDocument) (clientmodels.TrustedParty, *scheme.RelyingParty) {
	for _, document := range documents {
		if document.Reader == nil {
			continue
		}

		party := clientmodels.TrustedParty{
			Id:       document.Reader.CommonName(),
			Name:     document.Reader.CommonName(),
			Verified: true,
		}

		// The Yivi scheme extension carries the reader's legal name, logo and
		// authorized attribute sets. Absent on a conformant 18013-5 reader that is
		// not part of this scheme, which is not an error — the certificate's subject
		// is then all there is to show.
		info, err := utils.GetRequestorInfoFromCertificate[scheme.RelyingPartyRequestor](document.Reader.Certificate)
		if err != nil || info == nil {
			return party, nil
		}

		if name := clientmodels.Resolve(
			clientmodels.TranslatedString(info.Organization.LegalName), c.client.locale()); name != "" {
			party.Name = name
		}
		if info.Organization.Logo != nil && len(info.Organization.Logo.Data) > 0 {
			party.Image = &clientmodels.Image{Base64: base64.StdEncoding.EncodeToString(info.Organization.Logo.Data)}
		}
		return party, &info.RelyingParty
	}

	// No document carried an authenticated reader.
	return clientmodels.TrustedParty{Name: "", Verified: false}, nil
}

// RunOverBLE conducts the whole transaction over a BLE connection the platform
// provides, and returns when it is over.
//
// This is the entire app-side flow. After NewProximitySession and rendering
// EngagementQR, the app calls this once on a background thread with its BLEPort
// implementation, and forwards notifications to Notify and the link dropping to
// Disconnected. Nothing else is sequenced by the app: finding the reader,
// subscribing in the order 8.3.3.1.1.5 requires, verifying Ident, chunking,
// reassembly, consent, the response and termination all happen inside.
//
// Blocks — it waits on a consent screen. Not on the UI thread.
func (p *ProximitySession) RunOverBLE(port proximity.BLEPort, scanTimeoutMillis int) error {
	transport, err := proximity.NewBLETransport(p.inner, port, true)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.transport = transport
	p.mu.Unlock()

	if err := transport.Run(scanTimeoutMillis); err != nil {
		p.session.State.Status = clientmodels.Status_Error
		p.session.State.Error = &clientmodels.SessionError{
			ErrorType: string(clientmodels.Status_Error),
			Info:      err.Error(),
		}
		p.session.finish()
		return err
	}

	p.succeed()
	return nil
}

// Notify hands one BLE notification to the running transport.
//
// Parts must arrive in order and exactly once: the session's IV is never
// transmitted, so a dropped, duplicated or reordered notification desynchronises
// everything after it.
func (p *ProximitySession) Notify(characteristic, data []byte) error {
	p.mu.Lock()
	transport := p.transport
	p.mu.Unlock()

	if transport == nil {
		return fmt.Errorf("no BLE transport is running on this session")
	}
	return transport.OnNotification(characteristic, data)
}

// Disconnected reports that the BLE link dropped. Unblocks RunOverBLE.
func (p *ProximitySession) Disconnected() {
	p.mu.Lock()
	transport := p.transport
	p.mu.Unlock()

	if transport != nil {
		transport.OnDisconnect()
	}
}
