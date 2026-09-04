package openid4vp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// validateNonce checks that the nonce is non-empty and contains only ASCII
// URL-safe characters as required by OpenID4VP Section 5.2.
func validateNonce(nonce string) error {
	if nonce == "" {
		return fmt.Errorf("nonce is required")
	}
	for _, c := range nonce {
		if !isASCIIURLSafe(c) {
			return fmt.Errorf("nonce contains invalid character: %q", c)
		}
	}
	return nil
}

// isASCIIURLSafe returns true if the rune is an ASCII URL-safe character:
// uppercase/lowercase letters, digits, hyphen, period, underscore, or tilde.
func isASCIIURLSafe(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

type Jwk any

type SdJwtVcClientMetadataVpFormat struct {
	KbJwtAlgorithms []string `json:"kb-jwt_alg_values"`
	SdJwtAlgorithms []string `json:"sd-jwt_alg_values"`
}

type MdocClientMedataVpFormat struct {
	Algorithm []string `json:"alg"`
}

func GetMdocFromClientMetadataVpFormats(vpFormats map[string]any) *MdocClientMedataVpFormat {
	result, ok := vpFormats["mso_mdoc"].(MdocClientMedataVpFormat)
	if ok {
		return &result
	}
	return nil
}

func GetSdJwtVcFromClientMedataVpFormats(vpFormats map[string]any) *SdJwtVcClientMetadataVpFormat {
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
	// jwx v4 by default keeps unparseable set entries as placeholder keys;
	// strict parsing preserves the v3 behavior of rejecting the whole set.
	set, err := jwk.Parse(content, jwk.WithStrictKeySetParsing(true))
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
	// OPTIONAL. Human-readable name of the client (verifier).
	// Defined in RFC 7591 but not part of the OpenID4VP client_metadata spec (which says
	// unrecognized parameters MUST be ignored). Used as a fallback display name when
	// response_uri is absent, to avoid showing a raw did:jwk to the user.
	ClientName *string `json:"client_name,omitempty"`

	// OPTIONAL. URI of a webpage from the client (verifier) providing information about the client.
	// Defined in RFC 7591.
	ClientUri *string `json:"client_uri,omitempty"`

	// OPTIONAL. A URI to the logo of the client (verifier).
	// Defined in RFC 7591.
	LogoUri *string `json:"logo_uri,omitempty"`

	// OPTIONAL. A JSON Web Key Set, as defined in [RFC7591], that contains one or more public keys,
	// such as those used by the Wallet as an input to a key agreement that may be used for encryption
	// of the Authorization Response (see Section 8.3), or where the Wallet will require the public key
	// of the Verifier to generate a Verifiable Presentation.
	// This allows the Verifier to pass ephemeral keys specific to this Authorization Request.
	// Public keys included in this parameter MUST NOT be used to verify the signature of signed Authorization Requests.
	// Each JWK in the set MUST have a kid (Key ID) parameter that uniquely identifies the key within the context of the request.
	Jwks *Jwks `json:"jwks,omitempty"`

	// OPTIONAL. Array of strings, where each string is a JWE [RFC7516] enc algorithm that can be used
	// as the content encryption algorithm for encrypting the Response.
	// When a response_mode requiring encryption of the Response (such as dc_api.jwt or direct_post.jwt) is specified,
	// this MUST be present for anything other than the default single value of A128GCM. Otherwise, this SHOULD be absent.
	EncryptedResponseEncValuesSupported []string `json:"encrypted_response_enc_values_supported"`

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
type ClientIdentifierPrefix string

const (
	ResponseMode_DirectPost    ResponseMode = "direct_post"
	ResponseMode_DirectPostJwt ResponseMode = "direct_post.jwt"

	// The response modes for OpenID4VP over the W3C Digital Credentials API
	// (Appendix A.2): the wallet returns the Authorization Response through the
	// platform API instead of transmitting it to a response_uri itself.
	// dc_api.jwt encrypts the response as described in Section 8.3.
	ResponseMode_DcApi    ResponseMode = "dc_api"
	ResponseMode_DcApiJwt ResponseMode = "dc_api.jwt"

	ResponseType_VpToken        ResponseType = "vp_token"
	ResponseType_VpTokenIdToken ResponseType = "vp_token id_token"
	ResponseType_Code           ResponseType = "code"

	RequestUriMethod_Get  RequestUriMethod = "get"
	RequestUriMethod_Post RequestUriMethod = "post"

	ClientIdentifierPrefix_RedirectUri         ClientIdentifierPrefix = "redirect_uri:"
	ClientIdentifierPrefix_OpenidFederation    ClientIdentifierPrefix = "openid_federation:"
	ClientIdentifierPrefix_DecentralizedDid    ClientIdentifierPrefix = "decentralized_identifier:"
	ClientIdentifierPrefix_VerifierAttestation ClientIdentifierPrefix = "verifier_attestation:"
	ClientIdentifierPrefix_X509SanDns          ClientIdentifierPrefix = "x509_san_dns:"
	ClientIdentifierPrefix_X509Hash            ClientIdentifierPrefix = "x509_hash:"
	ClientIdentifierPrefix_Origin              ClientIdentifierPrefix = "origin:"
)

type AuthorizationRequest struct {
	Audience string `json:"aud"`
	Type     string `json:"type"`

	// REQUIRED:
	ClientId       string          `json:"client_id"`
	ClientMetadata *ClientMetadata `json:"client_metadata"`

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

	// REQUIRED for signed requests over the W3C Digital Credentials API, and not
	// for use in unsigned ones (Appendix A.2). A non-empty array of origins of the
	// verifier making the request. The wallet compares the origin the platform
	// reported against these values to detect replay of the request by a
	// malicious verifier.
	ExpectedOrigins []string `json:"expected_origins,omitempty"`

	// OPTIONAL: the request object's own expiry and not-before. Neither is
	// required by OpenID4VP, but a verifier that sets them is stating how long
	// the request may be used, and RFC 7519 requires a recipient that processes
	// them to honour it. They are read here so that GetExpirationTime and
	// GetNotBefore below can report them to the JWT parser; without the fields
	// there is nothing for the parser to check and a request object never goes
	// stale.
	Expiry    int64 `json:"exp,omitempty"`
	NotBefore int64 `json:"nbf,omitempty"`
}

type EncryptedResponsePayload struct {
	VpToken map[string][]string `json:"vp_token"`
}

// VpToken is a map from dcql query id to a list of credentials (e.g. a list of sd-jwt vc's)
type VpToken map[string][]string

// implement jwt.Claims interface, so we can decode the auth request JWT
//
// These are what the JWT parser validates against, so returning a nil time from
// all of them — as this type used to — means exp, nbf and iat are carried on the
// wire and then ignored: a request object stayed usable forever, and one dated
// in the future was accepted as readily as a current one. Each accessor now
// reports the claim it has, and leaves nil only where the request genuinely
// carries no value, which is the case the parser is meant to skip.

func (ar *AuthorizationRequest) GetExpirationTime() (*jwt.NumericDate, error) {
	return numericDateOrNil(ar.Expiry), nil
}

func (ar *AuthorizationRequest) GetIssuedAt() (*jwt.NumericDate, error) {
	return numericDateOrNil(ar.IssuedAt), nil
}

func (ar *AuthorizationRequest) GetNotBefore() (*jwt.NumericDate, error) {
	return numericDateOrNil(ar.NotBefore), nil
}

func (ar *AuthorizationRequest) GetIssuer() (string, error)  { return "", nil }
func (ar *AuthorizationRequest) GetSubject() (string, error) { return "", nil }

func (ar *AuthorizationRequest) GetAudience() (jwt.ClaimStrings, error) {
	if ar.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{ar.Audience}, nil
}

// numericDateOrNil converts a unix timestamp claim to the parser's type,
// reporting nil for the zero value so an absent claim stays absent rather than
// becoming a 1970 deadline that would reject every request.
func numericDateOrNil(unix int64) *jwt.NumericDate {
	if unix == 0 {
		return nil
	}
	return jwt.NewNumericDate(time.Unix(unix, 0))
}

const AuthRequestJwtTyp string = "oauth-authz-req+jwt"

// The aud claim is parsed into AuthorizationRequest.Audience but deliberately
// not validated. OpenID4VP § 5.8 tells a *verifier* what to put there --
// https://self-issued.me/v2 under static discovery, the wallet's issuer
// identifier under dynamic -- and places no validation duty on the wallet.
//
// A check against the static value was tried and removed. It refused the veramo
// reference verifier, which puts its own client_id in aud
// (decentralized_identifier:did:jwk:...) rather than any wallet identifier, so
// the field in practice says who *sent* the request as often as who it is for.
// Refusing that rejects a verifier doing nothing harmful, and the wallet has no
// issuer identifier of its own to recognise the conformant form by either.
//
// Not an mdoc concern in any case: aud lives in the OpenID4VP request object and
// is the same for every credential format.

// authRequestParserOptions are the validations the JWT parser applies to every
// authorization request object, wherever it arrived from.
//
// WithIssuedAt is what makes a future-dated iat an error; the parser ignores the
// claim otherwise. The leeway absorbs ordinary clock drift between a wallet and
// a verifier, which is not the same thing as a request being stale by a margin
// anyone would notice.
func authRequestParserOptions() []jwt.ParserOption {
	return []jwt.ParserOption{
		jwt.WithIssuedAt(),
		jwt.WithLeeway(2 * time.Minute),
	}
}

// validateRedirectAuthorizationRequest checks the parameters OpenID4VP
// constrains for a session invoked from a URL, and is the counterpart to
// validateDcApiRequest.
//
// The two transports had drifted: the DC API path checked response_type, the
// nonce, scope-versus-dcql_query and a non-empty query, while the redirect path
// checked only the nonce and left the rest to fail — or not fail — further down.
// A verifier could send response_type=code over a URL and still be answered with
// a vp_token, or send both scope and dcql_query, which the spec forbids
// outright. Everything common to both now lives in one place.
func validateRedirectAuthorizationRequest(request *AuthorizationRequest) error {
	if ResponseType(request.ResponseType) != ResponseType_VpToken {
		return fmt.Errorf("response_type must be %q, but got %q", ResponseType_VpToken, request.ResponseType)
	}
	if err := validateNonce(request.Nonce); err != nil {
		return err
	}
	// aud is deliberately not validated -- see the note above AuthRequestJwtTyp.
	//
	// "Either a dcql_query or a scope parameter representing a DCQL Query MUST
	// be present in the Authorization Request, but not both."
	hasQuery := len(request.DcqlQuery.Credentials) > 0
	if request.Scope != "" && hasQuery {
		return fmt.Errorf("scope and dcql_query must not both be present")
	}
	if request.Scope == "" && !hasQuery {
		return fmt.Errorf("request carries neither a dcql_query nor a scope")
	}
	if hasQuery {
		if err := request.DcqlQuery.Validate(); err != nil {
			return fmt.Errorf("invalid dcql_query: %v", err)
		}
	}

	// "When `response_uri` is present, the `redirect_uri` must not be present" —
	// the rule the AuthorizationRequest field comment already states. They name
	// two different places to send the answer, so a request carrying both leaves
	// where the response goes up to whichever the wallet happens to read first.
	if request.ResponseUri != "" && request.RedirectUri != "" {
		return fmt.Errorf("response_uri and redirect_uri must not both be present")
	}

	// direct_post has to say where the response goes. Without this the session
	// failed anyway, but only later and as an unreadable transport error — a POST
	// to the empty string, reported as an unsupported protocol scheme.
	if request.ResponseMode == ResponseMode_DirectPost || request.ResponseMode == ResponseMode_DirectPostJwt {
		if request.ResponseUri == "" {
			return fmt.Errorf("response_mode %s requires a response_uri", request.ResponseMode)
		}
	}
	return nil
}

// validateResponseUriBinding constrains where a response may be sent for the
// x509_san_dns client identifier scheme.
//
// OpenID4VP Section 5.10 lets a wallet allow a freely chosen response location
// only when it can establish trust in the client identifier by some other means,
// such as a list of trusted client identifiers; otherwise the host of the
// response location MUST match the client identifier. This wallet authenticates
// the client identifier against the certificate alone, which binds who is
// asking but says nothing about where the answer goes, so the second rule is the
// applicable one: without this check a certificate valid for one host could
// direct a credential to any other.
//
// Only x509_san_dns is constrained here. x509_hash names a certificate rather
// than a host, and the DC API returns the response through the platform instead
// of transmitting it, so neither carries a host to compare against.
func validateResponseUriBinding(request *AuthorizationRequest) error {
	if !strings.HasPrefix(request.ClientId, string(ClientIdentifierPrefix_X509SanDns)) {
		return nil
	}
	expected := strings.TrimPrefix(request.ClientId, string(ClientIdentifierPrefix_X509SanDns))

	// Whichever of the two the verifier used to say where the response goes.
	target := request.ResponseUri
	if target == "" {
		target = request.RedirectUri
	}
	if target == "" {
		return nil
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("response location %q is not a URL: %v", target, err)
	}
	if !strings.EqualFold(parsed.Hostname(), expected) {
		return fmt.Errorf(
			"response location host %q does not match client_id %q",
			parsed.Hostname(), expected,
		)
	}
	return nil
}
