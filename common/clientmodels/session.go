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
	// The client return url when the app should redirect to after the session, if any
	ClientReturnUrl string `json:"client_return_url"`
	// If this is true then the frontend should not return to the browser after the session is done
	ContinueOnSecondDevice bool `json:"continue_on_second_device"`
	// The number of attempts the user still has to enter a correct pin
	RemainingPinAttempts  *int `json:"remaining_pin_attempts,omitempty"`
	PinBlockedTimeSeconds *int `json:"pin_blocked_time_seconds,omitempty"`

	// OID4VCI specific fields
	OfferedCredentialTypes []*CredentialDescriptor `json:"offered_credential_types"`

	// OID4VCI - Authorization Code Flow parameters
	StateSalt               []byte `json:"-"`
	Oid4VciState            string `json:"oid4_vci_state,omitempty"`
	AuthorizationRequestUrl string `json:"authorization_request_url,omitempty"`

	// OID4VCI - Pre-Authorized Code Flow parameters
	TransactionCodeParameters *PreAuthorizedCodeTransactionCodeParameters `json:"transaction_code_parameters,omitempty"`
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
}

// AuthorizationCodeFlowRequest is a request to proceed with an authorization code issuance flow.
type AuthorizationCodeFlowRequest struct {
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

// DisclosurePlan describes how the user can satisfy a disclosure request.
type DisclosurePlan struct {
	// What to show during issuance during disclosure.
	// If nil then no issuances are required before a valid choice can be made.
	IssueDuringDislosure *IssueDuringDislosure `json:"issue_during_dislosure"`
	// What the user can pick for disclosure. This should never be nil.
	DisclosureChoicesOverview []DisclosurePickOne `json:"disclosure_choices_overview"`
}

// DisclosurePickOne is a disjunction where the user needs to pick one credential.
type DisclosurePickOne struct {
	// If true, the user can skip this because it isn't required
	Optional bool `json:"optional"`
	// The user can pick one of these without having to issue
	OwnedOptions []*SelectableCredentialInstance `json:"owned_options"`
	// The user can issue one of these and then use it
	ObtainableOptions []*CredentialDescriptor `json:"obtainable_options"`
}

// IssuanceStep is one step in the issuance wizard during disclosure flow.
type IssuanceStep struct {
	Options []*CredentialDescriptor `json:"options"`
}

// IssueDuringDislosure describes issuance steps needed during a disclosure flow.
type IssueDuringDislosure struct {
	// The steps to fulfill before we can continue the disclosure
	Steps []IssuanceStep `json:"steps"`
	// The set of credential ids that have been issued during this session
	IssuedCredentialIds map[string]struct{} `json:"issued_credential_ids"`
	// The last credential that was issued with the correct type but with wrong attribute values
	WrongCredentialIssued *Credential `json:"wrong_credential_issued"`
}
