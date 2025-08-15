package openid4vp

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

type Jwk interface{}

type SdJwtVcClientMetadataVpFormat struct {
	KbJwtAlgorithms []string `json:"kb-jwt_alg_values"`
	SdJwtAlgorithms []string `json:"sd-jwt_alg_values"`
}

type MdocClientMedataVpFormat struct {
	Algorithm []string `json:"alg"`
}

func GetMdocFromClientMetadataVpFormats(vpFormats map[string]interface{}) *MdocClientMedataVpFormat {
	result, ok := vpFormats["mso_mdoc"].(MdocClientMedataVpFormat)
	if ok {
		return &result
	}
	return nil
}

func GetSdJwtVcFromClientMedataVpFormats(vpFormats map[string]interface{}) *SdJwtVcClientMetadataVpFormat {
	result, ok := vpFormats["vc+sd-jwt"].(SdJwtVcClientMetadataVpFormat)
	if ok {
		return &result
	}

	result, ok = vpFormats["dc+sd-jwt"].(SdJwtVcClientMetadataVpFormat)
	if ok {
		return &result
	}
	return nil
}

type Jwks struct {
	jwk.Set `json:"-"`
}

func (s *Jwks) UnmarshalJSON(content []byte) error {
	set, err := jwk.Parse(content)
	if err != nil {
		return err
	}
	s.Set = set
	return nil
}

func (s Jwks) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Set)
}

type ClientMetadata struct {
	// OPTIONAL. A JSON Web Key Set, as defined in [RFC7591], that contains one or more public keys,
	// such as those used by the Wallet as an input to a key agreement that may be used for encryption
	// of the Authorization Response (see Section 8.3), or where the Wallet will require the public key
	// of the Verifier to generate a Verifiable Presentation.
	// This allows the Verifier to pass ephemeral keys specific to this Authorization Request.
	// Public keys included in this parameter MUST NOT be used to verify the signature of signed Authorization Requests.
	// Each JWK in the set MUST have a kid (Key ID) parameter that uniquely identifies the key within the context of the request.
	Jwks Jwks `json:"jwks,omitempty"`

	// OPTIONAL. Array of strings, where each string is a JWE [RFC7516] enc algorithm that can be used
	// as the content encryption algorithm for encrypting the Response.
	// When a response_mode requiring encryption of the Response (such as dc_api.jwt or direct_post.jwt) is specified,
	// this MUST be present for anything other than the default single value of A128GCM. Otherwise, this SHOULD be absent.
	EncryptedResponseEncValuesSupported []string `json:"encrypted_response_enc_values_supported"`

	// Legacy
	AuthorizationEncryptedResponseEnc string `json:"authorization_encrypted_response_enc,omitempty"`

	// vp_formats contains some metadata per credential format, which is specific for each credential format.
	// it's therefore modeled with an interface here, and each type of credential can be attempted to be retrieved
	// using a function returning a pointer to the requested credential type
	//
	// "vp_formats": {
	//   "dc+sd-jwt": {
	//     "kb-jwt_alg_values": [
	//       "ES256"
	//     ],
	//     "sd-jwt_alg_values": [
	//       "ES256"
	//     ]
	//   },
	//   "mso_mdoc": {
	//     "alg": [
	//       "ES256"
	//     ]
	//   },
	// }
	VpFormats map[string]any `json:"vp_formats"`
}

type ResponseMode string
type RequestUriMethod string
type ResponseType string

const (
	ResponseMode_DirectPost    ResponseMode = "direct_post"
	ResponseMode_DirectPostJwt ResponseMode = "direct_post.jwt"

	ResponseType_VpToken        ResponseType = "vp_token"
	ResponseType_VpTokenIdToken ResponseType = "vp_token id_token"
	ResponseType_Code           ResponseType = "code"

	RequestUriMethod_Get  RequestUriMethod = "get"
	RequestUriMethod_Post RequestUriMethod = "post"

	Key_Audience         string = "aud"
	Key_Type             string = "type"
	Key_ClientId         string = "client_id"
	Key_ClientMetadata   string = "client_metadata"
	Key_DcqlQuery        string = "dcql_query"
	Key_IssuedAt         string = "iat"
	Key_Nonce            string = "nonce"
	Key_ResponseMode     string = "response_mode"
	Key_ResponseType     string = "response_type"
	Key_ResponseUri      string = "response_uri"
	Key_RequestUriMethod string = "request_uri_method"
	Key_Scope            string = "scope"
	Key_State            string = "state"
)

type AuthorizationRequest struct {
	Audience string `json:"aud"`
	Type     string `json:"type"`

	// REQUIRED:
	ClientId       string         `json:"client_id"`
	ClientMetadata ClientMetadata `json:"client_metadata"`

	// OPTIONAL: A query for credentials using DCQL.
	// MUST NOT exist if `scope` is set, MUST exist if there is no `scope`.
	DcqlQuery dcql.DcqlQuery `json:"dcql_query"`
	IssuedAt  int64          `json:"iat"`

	// REQUIRED: a case-sensitive string representing a value to securely bind verifiable
	// presentations provided by the wallet to the particular transaction.
	// The verifier MUST create a fresh, cryptographically random for every Authorization Request.
	// MUST only contain ASCII URL safe characters.
	Nonce string `json:"nonce"`

	// REQUIRED: ask the wallet to send the response over https connection and demand encryption.
	ResponseMode ResponseMode `json:"response_mode"`

	ResponseType string `json:"response_type"`

	// REQUIRED when `response_mode` is `direct_post`. Contains the URL to which the wallet must
	// send the authorization response. The `response_uri` receives all authorization response parameters
	// as defined by the `response_type`.
	// When `response_uri` is present, the `redirect_uri` must not be present.
	ResponseUri string `json:"response_uri"`

	// OPTIONAL: when this parameter is present, the wallet must redirect the user agent to this
	// uri, allowing the verifier to continue the interaction with the end user.
	RedirectUri string `json:"redirect_uri"`

	// OPTIONAL: A string determining the HTTP method to be used when the `request_uri` parameter
	// is included in the same request.
	RequestUriMethod RequestUriMethod `json:"request_uri_method"`

	// OPTIONAL: The wallet MAY allow verifiers to request presentation by using a predefined scope.
	// MUST NOT exist if `dcql_query` is set, MUST exist if there is no `dcql_query`.
	Scope string `json:"scope"`

	// REQUIRED if at least one presentation without holder binding is requested, OPTIONAL otherwise:
	// MUST only contain ascii url safe characters.
	State string `json:"state"`
}

type EncryptedResponsePayload struct {
	VpToken map[string][]string `json:"vp_token"`
}

// VpToken is a map from dcql query id to a list of credentials (e.g. a list of sd-jwt vc's)
type VpToken map[string][]string

// implement jwt.Claims interface, so we can decode the auth request JWT

func (ar *AuthorizationRequest) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }
func (ar *AuthorizationRequest) GetIssuedAt() (*jwt.NumericDate, error)       { return nil, nil }
func (ar *AuthorizationRequest) GetNotBefore() (*jwt.NumericDate, error)      { return nil, nil }
func (ar *AuthorizationRequest) GetIssuer() (string, error)                   { return "", nil }
func (ar *AuthorizationRequest) GetSubject() (string, error)                  { return "", nil }
func (ar *AuthorizationRequest) GetAudience() (jwt.ClaimStrings, error)       { return nil, nil }

const AuthRequestJwtTyp string = "oauth-authz-req+jwt"
