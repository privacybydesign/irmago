package clientmodels

// UserInteractionType identifies the type of user interaction.
type UserInteractionType string

const (
	UI_EnteredPin        UserInteractionType = "entered_pin"
	UI_Permission        UserInteractionType = "permission"
	UI_DismissSession    UserInteractionType = "dismiss"
	UI_AuthorizationCode UserInteractionType = "authorization_code"
	UI_PreAuthorizedCode UserInteractionType = "pre_authorized_code"
	// Start the follow-up of a session that succeeded with
	// NextSessionPending. Has no payload.
	UI_ContinueNextSession UserInteractionType = "continue_next_session"
)

// SessionUserInteraction represents a user interaction with a session.
type SessionUserInteraction struct {
	// The ID corresponding to the session this interaction belongs to
	SessionId int `json:"session_id"`
	// The type of interaction performed by the user
	Type UserInteractionType `json:"type"`
	// The payload for this interaction
	Payload any `json:"payload"`
}

// SessionPermissionInteractionPayload is the payload for a permission interaction.
type SessionPermissionInteractionPayload struct {
	// Whether or not the user agreed to sharing, signing or disclosing
	Granted bool `json:"granted"`
	// The list of discons for each outer con
	DisclosureChoices []DisclosureDisconSelection `json:"disclosure_choices"`
	// The answer per slot: one entry per DisclosurePlan.Choices, in the same
	// order. Replaces DisclosureChoices.
	Choices []ChoiceSelection `json:"choices"`
}

// ChoiceSelection answers one DisclosureChoice.
type ChoiceSelection struct {
	// Index into the choice's Options; -1 shares nothing (only valid for an
	// optional choice).
	Option int `json:"option"`
	// One per slot of the chosen option, in the same order.
	Slots []SlotSelection `json:"slots"`
}

// SlotSelection names the card(s) shared for one DisclosureSlot.
type SlotSelection struct {
	SlotId string `json:"slot_id"`
	// One credential, or one or more when the slot is Multiple.
	Credentials []SelectedCredential `json:"credentials"`
}

// SelectedCredential is a reference to a credential the user has picked for disclosure.
type SelectedCredential struct {
	// The ID for this credential (idemix id or vct)
	CredentialId string `json:"credential_id"`
	// The hash for the specific credential instance
	CredentialHash string `json:"credential_hash"`
	// List of claim path pointers to the attributes the user will share
	AttributePaths [][]any `json:"attribute_paths"`
}

// DisclosureDisconSelection is the list of selected credentials for a disjunction.
type DisclosureDisconSelection struct {
	Credentials []SelectedCredential `json:"credentials"`
}

// PinInteractionPayload is the payload for a PIN entry interaction.
type PinInteractionPayload struct {
	Pin     string `json:"pin"`
	Proceed bool   `json:"proceed"`
}

// SessionAuthCodeInteractionPayload is the payload for an authorization code interaction.
type SessionAuthCodeInteractionPayload struct {
	// CallbackURL is the full redirect URL the authorization server sent to the
	// wallet's redirect_uri. The library parses its query for the authorization
	// code and state on success, or the error/error_description on failure
	// (RFC 6749 §4.1.2). Set only when Proceed is true.
	CallbackURL *string `json:"callback_url,omitempty"`
	Proceed     bool    `json:"proceed"`
}

// SessionPreAuthorizedCodeInteractionPayload is the payload for a pre-authorized code interaction.
type SessionPreAuthorizedCodeInteractionPayload struct {
	TransactionCode *string `json:"transaction_code,omitempty"`
	Proceed         bool    `json:"proceed"`
}
