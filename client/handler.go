package client

import (
	"sync"

	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

// ClientHandler is how the wallet wakes the app: something the app has already
// rendered went stale, or an asynchronous request it made finished. Required —
// client.New has no meaningful behaviour without it.
//
// Calls arrive on whichever goroutine did the work — a session's, a background
// sweep's — so an implementation must not block.
type ClientHandler interface {
	// CredentialsChanged says the credentials the app is showing are out of
	// date: an idemix credential was issued, a revocation status moved (idemix
	// or SD-JWT VC, newly revoked or no longer suspended), or a logo finished
	// downloading. Re-request them.
	//
	// Not everything that touches the credential list fires it: deleting a
	// credential and an OpenID4VCI issuance are silent, because the app drives
	// those itself and already has the outcome.
	//
	// Coalesced rather than itemised on purpose — the app re-reads the whole
	// list either way — and fired only on a change, never on re-confirming a
	// revocation status the wallet already recorded.
	CredentialsChanged()

	// ReportError reports an error the wallet hit with no session to attach it to.
	ReportError(err error)

	EnrollmentSuccess(scheme irma.SchemeManagerIdentifier)
	EnrollmentFailure(scheme irma.SchemeManagerIdentifier, err error)

	ChangePinSuccess()
	ChangePinFailure(scheme irma.SchemeManagerIdentifier, err error)
	ChangePinIncorrect(scheme irma.SchemeManagerIdentifier, attempts int)
	ChangePinBlocked(scheme irma.SchemeManagerIdentifier, timeout int)

	// WalletUnitActivated reports that the wallet unit was activated with the
	// wallet provider: after enrollment, after a later PIN entry, or inline at
	// an issuance. Only for a wallet with a wallet provider.
	WalletUnitActivated()
	// WalletUnitActivationPending reports that activating the wallet unit
	// failed. The wallet stays enrolled with its wallet unit pending
	// activation, which is retried the next time the wallet verifies the PIN.
	WalletUnitActivationPending(err error)

	// ChangePinRecoveryRequired reports that a PIN change could not be
	// finished: the keyshare servers and the wallet unit may now hold different
	// PINs. Ask the user for the PIN before and after the change and call
	// FinishPinChange. Client.PinChangeRecoveryRequired reports the same after
	// a restart.
	ChangePinRecoveryRequired()
}

// irmaHandler adapts the app's ClientHandler to the callback surface IrmaClient
// expects. Embedding forwards everything the two have in common; the methods
// below are the ones that differ.
type irmaHandler struct {
	ClientHandler

	// revokedSeen is what turns IrmaClient's Revoked into a change signal. See
	// the Revoked method for why it is needed.
	mu          sync.Mutex
	revokedSeen map[irma.CredentialIdentifier]struct{}

	// enrollmentEnded, when set, runs when a keyshare enrollment ends, before
	// the app hears of it. Set once, before any enrollment can start.
	enrollmentEnded func(success bool)
	// pinChangeEnded, when set, runs when a keyshare PIN change ends, before
	// the app hears of it. Set once, before any PIN change can start.
	pinChangeEnded func(success bool)
}

func (h *irmaHandler) endPinChange(success bool) {
	if h.pinChangeEnded != nil {
		h.pinChangeEnded(success)
	}
}

func (h *irmaHandler) ChangePinSuccess() {
	h.endPinChange(true)
	h.ClientHandler.ChangePinSuccess()
}

func (h *irmaHandler) ChangePinFailure(scheme irma.SchemeManagerIdentifier, err error) {
	h.endPinChange(false)
	h.ClientHandler.ChangePinFailure(scheme, err)
}

func (h *irmaHandler) ChangePinIncorrect(scheme irma.SchemeManagerIdentifier, attempts int) {
	h.endPinChange(false)
	h.ClientHandler.ChangePinIncorrect(scheme, attempts)
}

func (h *irmaHandler) ChangePinBlocked(scheme irma.SchemeManagerIdentifier, timeout int) {
	h.endPinChange(false)
	h.ClientHandler.ChangePinBlocked(scheme, timeout)
}

// EnrollmentSuccess lets the wallet act on a completed enrollment (activating
// the wallet unit with the same PIN) and then tells the app.
func (h *irmaHandler) EnrollmentSuccess(scheme irma.SchemeManagerIdentifier) {
	if h.enrollmentEnded != nil {
		h.enrollmentEnded(true)
	}
	h.ClientHandler.EnrollmentSuccess(scheme)
}

func (h *irmaHandler) EnrollmentFailure(scheme irma.SchemeManagerIdentifier, err error) {
	if h.enrollmentEnded != nil {
		h.enrollmentEnded(false)
	}
	h.ClientHandler.EnrollmentFailure(scheme, err)
}

var _ irmaclient.ClientHandler = (*irmaHandler)(nil)

func newIrmaHandler(handler ClientHandler) *irmaHandler {
	return &irmaHandler{
		ClientHandler: handler,
		revokedSeen:   map[irma.CredentialIdentifier]struct{}{},
	}
}

// UpdateAttributes is IrmaClient's "credentials changed" signal, fired after
// issuance.
func (h *irmaHandler) UpdateAttributes() { h.CredentialsChanged() }

// Revoked is IrmaClient's per-credential revocation signal, forwarded once per
// credential. IrmaClient reports revocation as state, not as a transition: a
// revoked credential's witness never advances, so the periodic witness-update
// job rediscovers the same revocation every few tens of seconds. Forwarding
// each rediscovery would have the app re-read its whole credential list on a
// timer.
func (h *irmaHandler) Revoked(cred *irma.CredentialIdentifier) {
	h.mu.Lock()
	_, seen := h.revokedSeen[*cred]
	h.revokedSeen[*cred] = struct{}{}
	h.mu.Unlock()

	if !seen {
		h.CredentialsChanged()
	}
}

// UpdateConfiguration reports a freshly downloaded scheme in irma_configuration
// terms, which nothing app-facing consumes: the credentials that needed it
// arrive through CredentialsChanged.
func (h *irmaHandler) UpdateConfiguration(*irma.IrmaIdentifierSet) {}
