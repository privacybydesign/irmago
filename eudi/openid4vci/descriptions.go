package openid4vci

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/oauth2"
)

type CredentialOffer struct {
	CredentialIssuer           string   `json:"credential_issuer"`
	CredentialConfigurationIds []string `json:"credential_configuration_ids"`

	// Grants is OPTIONAL per OID4VCI v1.0 § 4.1.1 and is nil when the offer
	// omits it (or sets it to null). The wallet then has to determine the grant
	// types from the authorization server metadata; see
	// session.configureIssuerSettings.
	Grants *Grants `json:"grants,omitempty"`
}

// Grants holds the grant types the Credential Issuer's authorization server is
// prepared to process for a credential offer, keyed by grant type identifier.
type Grants struct {
	AuthorizationCodeGrant *AuthorizationCodeGrant `json:"authorization_code,omitempty"`
	PreAuthorizedCodeGrant *PreAuthorizedCodeGrant `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`

	// UnsupportedGrantTypes holds the identifiers of offered grant types this
	// wallet does not implement. It exists so an empty grants object, for which
	// OID4VCI v1.0 § 4.1.1 requires deriving the grant types from the
	// authorization server metadata, can be told apart from an offer that does
	// name grant types but none we can use.
	UnsupportedGrantTypes []string `json:"-"`
}

// UnmarshalJSON decodes the offer's grants member. The struct tags above are
// only used for marshalling: grant types are keyed by identifier, and unknown
// identifiers have to be collected rather than dropped.
func (g *Grants) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal grants: %v", err)
	}

	*g = Grants{}
	for grantType, parameters := range raw {
		switch grantType {
		case oauth2.GrantTypeAuthorizationCode:
			var grant AuthorizationCodeGrant
			if err := json.Unmarshal(parameters, &grant); err != nil {
				return fmt.Errorf("failed to unmarshal %s grant: %v", grantType, err)
			}
			g.AuthorizationCodeGrant = &grant
		case oauth2.GrantTypePreAuthorizedCode:
			var grant PreAuthorizedCodeGrant
			if err := json.Unmarshal(parameters, &grant); err != nil {
				return fmt.Errorf("failed to unmarshal %s grant: %v", grantType, err)
			}
			g.PreAuthorizedCodeGrant = &grant
		default:
			g.UnsupportedGrantTypes = append(g.UnsupportedGrantTypes, grantType)
		}
	}
	// Map iteration order is random; sort so error messages are stable.
	slices.Sort(g.UnsupportedGrantTypes)

	return nil
}

// IsEmpty reports whether the grants member named no grant type at all. A nil
// Grants (an absent or null grants member) counts as empty, since OID4VCI v1.0
// § 4.1.1 handles both the same way.
func (g *Grants) IsEmpty() bool {
	if g == nil {
		return true
	}
	return g.AuthorizationCodeGrant == nil &&
		g.PreAuthorizedCodeGrant == nil &&
		len(g.UnsupportedGrantTypes) == 0
}

type GrantType int

const (
	GrantType_AuthorizationCode GrantType = iota
	GrantType_PreAuthorizedCode
)

var grantTypeName = map[GrantType]string{
	GrantType_AuthorizationCode: "authorization_code",
	GrantType_PreAuthorizedCode: "pre-authorized_code",
}

func (gt GrantType) String() string {
	return grantTypeName[gt]
}

type Grant interface {
	GetAuthorizationServer() *string
	GetGrantType() GrantType
}

type AuthorizationCodeGrant struct {
	IssuerState         *string `json:"issuer_state,omitempty"`
	AuthorizationServer *string `json:"authorization_server,omitempty"`
}

func (g *AuthorizationCodeGrant) GetAuthorizationServer() *string {
	return g.AuthorizationServer
}
func (g *AuthorizationCodeGrant) GetGrantType() GrantType {
	return GrantType_AuthorizationCode
}

type PreAuthorizedCodeGrant struct {
	PreAuthorizedCode   string           `json:"pre-authorized_code"`
	TxCode              *TransactionCode `json:"tx_code,omitempty"`
	AuthorizationServer *string          `json:"authorization_server,omitempty"`
}

func (g *PreAuthorizedCodeGrant) GetAuthorizationServer() *string {
	return g.AuthorizationServer
}
func (g *PreAuthorizedCodeGrant) GetGrantType() GrantType {
	return GrantType_PreAuthorizedCode
}

type TransactionCodeInputMode string

const (
	TransactionCodeInputMode_Numeric TransactionCodeInputMode = "numeric"
	TransactionCodeInputMode_Text    TransactionCodeInputMode = "text"
)

type TransactionCode struct {
	InputMode   *TransactionCodeInputMode `json:"input_mode,omitempty"` // TODO: make this optional with default "numeric"
	Length      *int                      `json:"length,omitempty"`
	Description *string                   `json:"description,omitempty"`
}

type CredentialRequest struct {
	CredentialIdentifier      *string          `json:"credential_identifier,omitempty"`
	CredentialConfigurationId *string          `json:"credential_configuration_id,omitempty"`
	Proofs                    *metadata.Proofs `json:"proofs,omitempty"`
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

type NonceResponse struct {
	Nonce string `json:"c_nonce"`
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
