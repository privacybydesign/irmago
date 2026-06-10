package clientmodels

// UserInteractionType identifies the type of user interaction.
type UserInteractionType string

const (
	UI_EnteredPin        UserInteractionType = "entered_pin"
	UI_Permission        UserInteractionType = "permission"
	UI_DismissSession    UserInteractionType = "dismiss"
	UI_AuthorizationCode UserInteractionType = "authorization_code"
	UI_PreAuthorizedCode UserInteractionType = "pre_authorized_code"
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
	Code    *string `json:"code,omitempty"`
	State   *string `json:"state,omitempty"`
	Proceed bool    `json:"proceed"`
}

// SessionPreAuthorizedCodeInteractionPayload is the payload for a pre-authorized code interaction.
type SessionPreAuthorizedCodeInteractionPayload struct {
	TransactionCode *string `json:"transaction_code,omitempty"`
	Proceed         bool    `json:"proceed"`
}
