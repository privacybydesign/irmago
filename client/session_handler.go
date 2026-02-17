package client

import (
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

type PermissionHandler interface {
	Provide(allow bool)
}

type SessionStatus string
type SessionType string

const (
	Session_AskingIssuancePermission   SessionStatus = "issuance_permission"
	Session_AskingDisclosurePermission SessionStatus = "disclosure_permission"
	Session_ShowPairingCode            SessionStatus = "pairing_code"
	Session_Success                    SessionStatus = "success"
	Session_Error                      SessionStatus = "error"
	Session_Dismissed                  SessionStatus = "dismissed"
	Session_PinRequest                 SessionStatus = "pin"

	Type_Disclosure SessionType = "disclosure"
	Type_Issuance   SessionType = "issuance"
	Type_Signature  SessionType = "signature"
)

type DisclosurePlan struct {
	// What to show during issuance during disclosure.
	// If this is nil then no issuances are required before a valid choice can be made.
	// The disclosure flow then only has one step.
	// When it is present it contains both the credentials that have been added during this flow,
	// as well as the credentials left to issuer in order to proceed. This is done to make it possible to
	// show a correct stepper, even after the session state gets updated.
	// When all are satisfied, the value should still be present in updates to the session state, so the stepper is shown correctly.
	IssueDuringDislosure *IssueDuringDislosure
	// What the user can pick for disclosure. This is nil during the issuance step.
	DisclosureMakeChoices *DisclosureMakeChoices
}

type DisclosureChoice struct {
	// The (default) selected choice
	Selected *Credential
	// the user can pick one of these without having to issue
	OwnedOptions []Credential
	// The user can issue one of these and then use it
	ObtainableOptions []CredentialStoreItem
}

type DisclosureMakeChoices struct {
	// The list of choices the user has to make.
	// For each of the choices the user has to pick how to satisfy it.
	Required []DisclosureChoice
}

// What to show during issuance during disclosure
type IssueDuringDislosure struct {
	// What has been issued during this disclosure flow
	IssuedDuringSession []Credential
	// What still has to be issued during this flow before we can continue to the next step
	LeftToIssue []Credential
}

// Snapshot of the state of this session.
// When the session state changes it should create a new instance.
// It has been setup in such a way that it contains all relevant state for
// displaying all stages for this session to the user
type SessionState struct {
	// The identifier for this session
	Id int
	// The protocol used for this session
	Protocol irmaclient.Protocol
	// The type of session this is
	Type SessionType
	// In what stage this session currently is
	Status SessionStatus
	// Who started this session
	Requestor   TrustedParty
	PairingCode string
	// The list of credentials offered to the user. The user has no choice other than accepting or denying them.
	OfferedCredentials []Credential
	// The plan for disclosing credentials to satisfy this disclosure session
	// Nil when no disclosure has to be done
	DisclosurePlan *DisclosurePlan
	// The error when this session has an error
	Error error
	// The client return url when the app should redirect to after the session, if any
	ClientReturnUrl string
}

type Session struct {
	State   *SessionState
	Handler SessionHandler
}

type SessionManager struct {
	Sessions map[int]*Session
}

type SessionHandler interface {
	UpdateTopSession()
	PushSession()
	PopSession()
}
