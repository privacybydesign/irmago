package openid4vci

import "fmt"

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
	PreAuthorizedCode   string          `json:"pre-authorized_code"`
	TxCode              TransactionCode `json:"tx_code,omitempty"`
	AuthorizationServer string          `json:"authorization_server,omitempty"`
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

type CredentialRequest struct {
	CredentialIdentifier      *string `json:"credential_identifier,omitempty"`
	CredentialConfigurationId *string `json:"credential_configuration_id,omitempty"`
}

type CredentialResponse struct {
	Credentials    []CredentialInstance `json:"credentials,omitempty"`
	TransactionId  *string              `json:"transaction_id,omitempty"`
	Interval       *int                 `json:"interval,omitempty"`
	NotificationId *string              `json:"notification_id,omitempty"`
}

type CredentialInstance struct {
	Credential string `json:"credential"`
}

type CredentialErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func (c *CredentialResponse) Validate(deferred bool) error {
	if deferred {
		if len(c.Credentials) != 0 {
			return fmt.Errorf("credential response should not contain credentials when deferred response is indicated")
		}
		if c.TransactionId == nil || c.Interval == nil {
			return fmt.Errorf("credential response should contain transaction_id and interval when deferred response is indicated")
		}
	} else {
		if len(c.Credentials) == 0 {
			return fmt.Errorf("credential response contains no credentials")
		}
		if c.TransactionId != nil || c.Interval != nil {
			return fmt.Errorf("credential response should not contain transaction_id and interval upon immediate response")
		}
	}
	return nil
}
