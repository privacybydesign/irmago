package irmaclient

import (
	"fmt"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
)

// backgroundIssuanceHandler handles an IRMA issuance session in the background.
type backgroundIssuanceHandler struct {
	pin string

	credentialsToBeIssuedCallback func([]*irma.CredentialRequest)
	resultErr                     chan error
}

// Force keyshareEnrollmentHandler to implement the Handler interface
var _ Handler = (*backgroundIssuanceHandler)(nil)

// Session handlers in the order they are called

func (h *backgroundIssuanceHandler) RequestIssuancePermission(request *irma.IssuanceRequest, satisfiable bool, candidates [][]DisclosureCandidates, ServerName *irma.RequestorInfo, callback PermissionHandler) {
	if h.credentialsToBeIssuedCallback != nil {
		h.credentialsToBeIssuedCallback(request.Credentials)
	}

	// First, collect all attributes that are going to be issued.
	attrsToBeIssued := map[irma.AttributeTypeIdentifier]string{}
	for _, credReq := range request.Credentials {
		for id, value := range credReq.Attributes {
			attrsToBeIssued[irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", credReq.CredentialTypeID, id))] = value
		}
	}

	// We only allow disclosing the previous values if the new values are the same.
	var choice irma.DisclosureChoice
	for _, discon := range candidates {
		for _, con := range discon {
			valid := true
			for _, attr := range con {
				if attr.CredentialHash == "" {
					valid = false
					break
				}
				if newValue, ok := attrsToBeIssued[attr.Type]; !ok || newValue != attr.Value[""] {
					valid = false
					break
				}
			}
			if valid {
				attrs, err := con.Choose()
				if err != nil {
					callback(false, nil)
					return
				}
				choice.Attributes = append(choice.Attributes, attrs)
				break
			}
		}
	}
	// Check whether we chose an option from every candidate discon.
	if len(choice.Attributes) != len(candidates) {
		callback(false, nil)
		return
	}

	callback(true, &choice)
}

func (h *backgroundIssuanceHandler) RequestPin(remainingAttempts int, callback PinHandler) {
	if remainingAttempts == -1 { // -1 signifies that this is the first attempt
		callback(true, h.pin)
	} else {
		h.fail(errors.New("PIN incorrect"))
	}
}

func (h *backgroundIssuanceHandler) Success(result string) {
	if h.resultErr != nil {
		h.resultErr <- nil
	}
}

func (h *backgroundIssuanceHandler) Failure(err *irma.SessionError) {
	h.fail(err)
}

// fail is a helper to ensure the kss is removed from the client in case of any problem
func (h *backgroundIssuanceHandler) fail(err error) {
	if h.resultErr != nil {
		h.resultErr <- err
	}
}

// Not interested, ingore
func (h *backgroundIssuanceHandler) StatusUpdate(action irma.Action, status irma.ClientStatus) {}

// The methods below should never be called, so we let each of them fail the session
func (h *backgroundIssuanceHandler) RequestVerificationPermission(request *irma.DisclosureRequest, satisfiable bool, candidates [][]DisclosureCandidates, ServerName *irma.RequestorInfo, callback PermissionHandler) {
	callback(false, nil)
}
func (h *backgroundIssuanceHandler) RequestSignaturePermission(request *irma.SignatureRequest, satisfiable bool, candidates [][]DisclosureCandidates, ServerName *irma.RequestorInfo, callback PermissionHandler) {
	callback(false, nil)
}
func (h *backgroundIssuanceHandler) RequestSchemeManagerPermission(manager *irma.SchemeManager, callback func(proceed bool)) {
	callback(false)
}
func (h *backgroundIssuanceHandler) RequestAuthorizationCodeFlowIssuancePermission(request *irma.AuthorizationCodeIssuanceRequest, serverName *irma.RequestorInfo, callback PermissionHandler) {
	callback(false, nil)
}
func (h *backgroundIssuanceHandler) Cancelled() {
	h.fail(errors.New("session unexpectedly cancelled"))
}
func (h *backgroundIssuanceHandler) KeyshareBlocked(manager irma.SchemeManagerIdentifier, duration int) {
	h.fail(errors.New("user is blocked"))
}
func (h *backgroundIssuanceHandler) KeyshareEnrollmentIncomplete(manager irma.SchemeManagerIdentifier) {
	h.fail(errors.New("keyshare registration incomplete"))
}
func (h *backgroundIssuanceHandler) KeyshareEnrollmentDeleted(manager irma.SchemeManagerIdentifier) {
	h.fail(errors.New("keyshare enrollment deleted"))
}
func (h *backgroundIssuanceHandler) KeyshareEnrollmentMissing(manager irma.SchemeManagerIdentifier) {
	h.fail(errors.New("keyshare enrollment missing"))
}
func (h *backgroundIssuanceHandler) ClientReturnURLSet(clientReturnURL string) {
	h.fail(errors.New("unexpectedly found an external return url"))
}
func (h *backgroundIssuanceHandler) PairingRequired(pairingCode string) {
	h.fail(errors.New("device pairing required"))
}
