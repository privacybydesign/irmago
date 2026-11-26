package clientmodels

// SessionStatus represents the current status of a session.
type SessionStatus string

const (
	Status_RequestPermission        SessionStatus = "request_permission"
	Status_ShowPairingCode          SessionStatus = "show_pairing_code"
	Status_Success                  SessionStatus = "success"
	Status_Error                    SessionStatus = "error"
	Status_Dismissed                SessionStatus = "dismissed"
	Status_RequestPin               SessionStatus = "request_pin"
	Status_RequestPreAuthorizedCode SessionStatus = "request_pre_authorized_code"
	Status_RequestAuthorizationCode SessionStatus = "request_authorization_code"
)

// SessionType represents the type of a session.
type SessionType string

const (
	Type_Disclosure SessionType = "disclosure"
	Type_Issuance   SessionType = "issuance"
	Type_Signature  SessionType = "signature"
)

// SessionHandler is the callback interface for receiving session state updates.
type SessionHandler interface {
	UpdateSession(session SessionState)
}

// SessionState is a snapshot of the state of a session.
type SessionState struct {
	// The identifier for this session
	Id int `json:"id"`
	// The protocol used for this session
	Protocol Protocol `json:"protocol"`
	// The type of session this is
	Type SessionType `json:"type"`
	// In what stage this session currently is
	Status SessionStatus `json:"status"`
	// Who started this session
	Requestor TrustedParty `json:"requestor"`
	// The pairing code to show to the user when the status is pairing
	PairingCode string `json:"pairing_code"`
	// The list of credentials offered to the user. The user has no choice other than accepting or denying them.
	OfferedCredentials []*Credential `json:"offered_credentials"`
	// The plan for disclosing credentials to satisfy this disclosure session
	// Nil when no disclosure has to be done. Can also be present during issuance session.
	DisclosurePlan *DisclosurePlan `json:"disclosure_plan"`
	// The message that should be signed during this session, if any
	MessageToSign string `json:"message_to_sign"`
	// The error when this session has an error
	Error *SessionError `json:"error,omitempty"`
	// With Status_Success: the requestor chained a follow-up request (IRMA
	// nextSession). This session is done (shared, logged, closed at the
	// server); the follow-up starts only on UI_ContinueNextSession, and is
	// dropped on UI_DismissSession.
	NextSessionPending bool `json:"next_session_pending"`
	// The client return url when the app should redirect to after the session, if any
	ClientReturnUrl string `json:"client_return_url"`
	// If this is true then the frontend should not return to the browser after the session is done
	ContinueOnSecondDevice bool `json:"continue_on_second_device"`
	// The number of attempts the user still has to enter a correct pin
	RemainingPinAttempts  *int `json:"remaining_pin_attempts,omitempty"`
	PinBlockedTimeSeconds *int `json:"pin_blocked_time_seconds,omitempty"`

	// OpenID4VP: how the response travels to the verifier (e.g.
	// "direct_post.jwt"), for the wallet's technical details. Empty for other
	// protocols.
	ResponseMode string `json:"response_mode,omitempty"`

	// OpenID4VP over the W3C Digital Credentials API: the JSON the app must hand
	// back to the platform as the `data` member of the response. Set on the state
	// that reaches Status_Success; empty for every other session.
	DcApiResponse string `json:"dc_api_response,omitempty"`

	// OID4VCI specific fields
	OfferedCredentialTypes []*CredentialDescriptor `json:"offered_credential_types"`

	// OID4VCI - Authorization Code Flow parameters
	OpenID4VCIState         string `json:"openid4vci_state,omitempty"`
	AuthorizationRequestUrl string `json:"authorization_request_url,omitempty"`

	// OID4VCI - Pre-Authorized Code Flow parameters
	TransactionCodeParameters *PreAuthorizedCodeTransactionCodeParameters `json:"transaction_code_parameters,omitempty"`
	// Remaining transaction-code attempts. Nil on the initial prompt; populated
	// (e.g. 2, then 1) after each rejected attempt so the UI can show "try again".
	RemainingTxCodeAttempts *int `json:"remaining_tx_code_attempts,omitempty"`
}

// RemoteError is a server-side error returned by a remote party.
type RemoteError struct {
	Status      int    `json:"status,omitempty"`
	ErrorName   string `json:"error,omitempty"`
	Description string `json:"description,omitempty"`
	Message     string `json:"message,omitempty"`
	Stacktrace  string `json:"stacktrace,omitempty"`
}

// PreAuthorizedCodeTransactionCodeParameters describes the parameters for a
// pre-authorized code transaction code (OID4VCI).
type PreAuthorizedCodeTransactionCodeParameters struct {
	InputMode   string  `json:"input_mode"`
	Length      *int    `json:"length,omitempty"`
	Description *string `json:"description,omitempty"`
}

// PreAuthorizedCodeFlowPermissionRequest is a request to proceed with a pre-authorized code issuance flow.
type PreAuthorizedCodeFlowPermissionRequest struct {
	Credentials               []*CredentialDescriptor
	TransactionCodeParameters *PreAuthorizedCodeTransactionCodeParameters
	// RemainingAttempts is set when the user is being re-prompted after a wrong
	// transaction code. Nil on the initial prompt.
	RemainingAttempts *int
}

// AuthorizationCodeFlowRequest is a request to proceed with an authorization code issuance flow.
type AuthorizationCodeFlowRequest struct {
	// The state will be the external identifier for this session, so it should be unique and unguessable. The session will generate a random state if this is not set.
	OpenID4VCIState string

	Credentials             []*CredentialDescriptor
	AuthorizationEndpoint   string
	AuthorizationParameters map[string][]string // url.Values
}

// SessionError is a frontend-friendly representation of a session error.
type SessionError struct {
	ErrorType    string       `json:"error_type"`
	WrappedError string       `json:"wrapped_error"`
	Info         string       `json:"info"`
	RemoteError  *RemoteError `json:"remote_error,omitempty"`
	RemoteStatus int          `json:"remote_status"`
	Stack        string       `json:"stack"`
}

// DisclosurePlan describes a disclosure request as choices → options → slots
// → candidates, and what was issued for it while it waited.
type DisclosurePlan struct {
	// One choice per credential set (DCQL), per query without sets (DCQL) or
	// per discon (IRMA), in the order of the request. Never nil once a plan is
	// built. What is still missing follows from the slots without a usable
	// candidate.
	Choices []DisclosureChoice `json:"choices"`
	// Ids of the credential types issued since this request was first shown
	// that the request can use.
	IssuedCredentialIds map[string]struct{} `json:"issued_credential_ids"`
	// Set when a card was issued for this request but does not satisfy it.
	WrongCredentialIssued *Credential `json:"wrong_credential_issued"`
}

// DisclosureChoice is one thing the requestor wants answered: an IRMA discon,
// a DCQL credential set, or a single DCQL query when there are no sets.
type DisclosureChoice struct {
	// The user may answer this choice with nothing (a set with required false,
	// or an IRMA discon holding an empty con; the empty con is not an option).
	Optional bool `json:"optional"`
	// The ways to answer this choice; exactly one of them is shared.
	Options []DisclosureOption `json:"options"`
}

// DisclosureOption is one way to answer a choice: one entry of a DCQL set's
// options, or one non-empty IRMA con. All its slots are shared together.
type DisclosureOption struct {
	Slots []DisclosureSlot `json:"slots"`
}

// DisclosureSlot is one credential an option needs: a DCQL credential query,
// or one credential type of an IRMA con.
type DisclosureSlot struct {
	// DCQL: the query id, sent back as-is; the same query in two options or
	// sets is one slot with one selection. IRMA: "{discon index}:{credential
	// type id}", so the same type in two discons is two independent slots.
	Id string `json:"id"`
	// DCQL `multiple`: the slot takes one or more cards. Always false for IRMA.
	Multiple bool `json:"multiple"`
	// Cards in the app that fit, best first (SortCandidates), each with only the
	// attributes it would share (none when only the card itself is asked for).
	// A card that fits but cannot be used now is included with Usable false; a
	// card whose value is not one of the allowed values is not a candidate.
	Candidates []*SelectableCredentialInstance `json:"candidates"`
	// What can be added for this slot, with the requested values on its
	// attributes. A descriptor without an IssueURL says what is asked for while
	// nothing can be added. Empty when there is nothing to show.
	Obtainable []*CredentialDescriptor `json:"obtainable"`
}
