package wallet

import (
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
)

// PresentationResult describes the outcome of a completed OpenID4VP disclosure.
type PresentationResult struct {
	// Requestor is the verifier the credentials were disclosed to.
	Requestor *clientmodels.TrustedParty
	// Disclosed lists, per credential, what was shared with the verifier.
	Disclosed []clientmodels.LogCredential
	// Result is the raw result string returned by the OpenID4VP client.
	Result string
}

// Present runs an OpenID4VP disclosure session against the given authorization
// request URI (e.g. an openid4vp://?request_uri=... deep link) and returns what
// was disclosed. Which credentials/claims are shared is decided by the wallet's
// Policy.
func (w *Wallet) Present(requestURI string) (*PresentationResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	h := &presentationHandler{
		policy:     w.policy,
		logStorage: w.storage,
		done:       make(chan presentationResult, 1),
	}
	w.vp.NewSession(requestURI, h)

	res := <-h.done
	return res.result, res.err
}

type presentationResult struct {
	result *PresentationResult
	err    error
}

// presentationHandler is a headless openid4vp.Handler.
type presentationHandler struct {
	policy     Policy
	logStorage storage.Storage
	done       chan presentationResult

	requestor *clientmodels.TrustedParty
}

func (h *presentationHandler) Success(result string, credentialLogs []clientmodels.LogCredential) {
	// Parity with client/openid4vp_adapters.go: log even when nothing was shared.
	var requestor clientmodels.TrustedParty
	if h.requestor != nil {
		requestor = *h.requestor
	}
	if h.logStorage != nil {
		if err := services.NewEudiLogService(h.logStorage).AddDisclosureLog(requestor, credentialLogs); err != nil {
			fmt.Printf("wallet: failed to write disclosure log: %v\n", err)
		}
	}
	h.done <- presentationResult{result: &PresentationResult{
		Requestor: h.requestor,
		Disclosed: credentialLogs,
		Result:    result,
	}}
}

func (h *presentationHandler) Cancelled() {
	h.done <- presentationResult{err: fmt.Errorf("wallet: disclosure session cancelled")}
}

func (h *presentationHandler) Failure(err *clientmodels.SessionError) {
	h.done <- presentationResult{err: sessionErrorToError("disclosure", err)}
}

func (h *presentationHandler) RequestVerificationPermission(
	plan *clientmodels.DisclosurePlan,
	requestor *clientmodels.TrustedParty,
	hashToQueryID map[string]string,
	callback openid4vp.PermissionHandler,
) {
	h.requestor = requestor
	selections, ok := h.policy.ApproveDisclosure(plan, requestor, hashToQueryID)
	if !ok {
		callback(false, nil)
		return
	}
	callback(true, selections)
}

// ensure the disclosure selection type is referenced (documents the contract
// that policies build these).
var _ = dcql.DisclosureSelection{}
