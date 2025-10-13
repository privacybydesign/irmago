package openid4vci

type CredentialOffer struct {
	CredentialIssuer           string   `json:"credential_issuer"`
	CredentialConfigurationIds []string `json:"credential_configuration_ids"`
	Grants                     *Grants  `json:"grants,omitempty"`
}

type Grants struct {
	AuthorizationCodeGrant *AuthorizationCodeGrant `json:"authorization_code,omitempty"`
	PreAuthorizedCodeGrant *PreAuthorizedCodeGrant `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

type AuthorizationCodeGrant struct {
	IssuerState         *string `json:"issuer_state,omitempty"`
	AuthorizationServer *string `json:"authorization_server,omitempty"`
}

type PreAuthorizedCodeGrant struct {
	PreAuthorizedCode   string `json:"pre-authorized_code"`
	TxCode              bool   `json:"tx_code,omitempty"`
	AuthorizationServer string `json:"authorization_server,omitempty"`
}

type TransactionCodeInputMode string

const (
	TransactionCodeInputMode_Numeric TransactionCodeInputMode = "numeric"
	TransactionCodeInputMode_Text    TransactionCodeInputMode = "text"
)

type TransactionCode struct {
	InputMode   TransactionCodeInputMode `json:"input_mode,omitempty"` // TODO: make this optional with default "numeric"
	Length      int                      `json:"length,omitempty"`
	Description string                   `json:"description,omitempty"`
}
