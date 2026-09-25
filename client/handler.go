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
