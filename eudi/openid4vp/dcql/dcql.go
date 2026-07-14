package dcql

import "iter"

type DcqlQuery struct {
	// REQUIRED: A non-empty array of credential queries that specify the requested verifiable credentials.
	Credentials []CredentialQuery `json:"credentials"`

	// OPTIONAL: A non-empty array of credential set queries that specify specific additional constraints
	// on which of the requested verifiable credentials to return.
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"`
}

// CredentialSetQuery is an object representing a request for one or more Credentials
// to satisfy a particular use case with the Verifier.
type CredentialSetQuery struct {
	// REQUIRED: A non-empty array, where each value in the array is a list of Credential Query
	// identifiers representing one set of credentials that satisfies the use case.
	Options [][]string `json:"options"`

	// OPTIONAL: Indicates whether this set of credentials is required to satisfy the particular use case at the verifier.
	// If omitted, the default is true
	Required *bool `json:"required,omitempty"` // TODO: write verification function that makes sure this value is true when not in the json
}

type Meta struct {
	// REQUIRED for mdoc: String that specifies an allowed value for the doctype of the requested Verifiable Credential.
	// It MUST be a valid doctype identifier as defined in [ISO.18013-5]
	DocTypeValue string `json:"doctype_value,omitempty"`
	// REQUIRED for SD-JWT-VC: An array of strings that specifies allowed values for the type of the requested Verifiable Credential.
	// All elements in the array MUST be valid type identifiers as defined in [I-D.ietf-oauth-sd-jwt-vc]
	VctValues []string `json:"vct_values,omitempty"`
}

type CredentialQuery struct {
	// REQUIRED: A string identifying the credential in the response and, if provided,
	// the constraints in the `credential_sets`.
	// Must be a non-empty string consisting of alphanumeric, underscore or hyphen characters.
	// Within the Authorization Request the same id must not be presented more than once.
	Id string `json:"id"`

	// REQUIRED: Specifies the format of the requested verifiable credential.
	Format string `json:"format"`

	// OPTIONAL: Indicates whether multiple credentials can be returned for this credential query.
	// The default is false.
	Multiple bool `json:"multiple,omitempty"`

	// OPTIONAL: An object defining additional properties requested by the verifier that apply to the
	// metadata and validity data of the credential. The properties of this are defined per credential format.
	// If omitted, no specific constraints are placed on the metadata or validity of the requested credential.
	Meta *Meta `json:"meta,omitempty"`

	// OPTIONAL: A non-empty array that specifies the expected authorities or trust frameworks that certify issuers,
	// that the verifier will accept. Every credential returned by the wallet should match at least one of the conditions
	// present in corresponding `trusted_authorities` array if present.
	TrustedAuthorities []TrustedAuthority `json:"trusted_authorities,omitempty"`

	// OPTIONAL: A non-empty array that specifies claims in the requested credential.
	// Verifiers must not point to the same claim more than once in a single query.
	// Wallets should ignore such duplicate claim queries.
	Claims []Claim `json:"claims,omitempty"`

	// OPTIONAL: A non-empty array containing arrays of identifiers for elements in `claims`
	// that specifies which combinations of `claims` for the credential are requested.
	ClaimSets [][]string `json:"claim_sets,omitempty"`

	// OPTIONAL. A boolean which indicates whether the Verifier requires a Cryptographic Holder Binding proof.
	// The default value is true, i.e., a Verifiable Presentation with Cryptographic Holder Binding is required.
	// If set to false, the Verifier accepts a Credential without Cryptographic Holder Binding proof.
	RequireHolderBinding *bool `json:"require_cryptographic_holder_binding,omitempty"`
}

// NeedsHolderBinding returns true if the credential query requires a cryptographic
// holder binding proof. Defaults to true per the OpenID4VP spec when the field is absent.
func (c CredentialQuery) NeedsHolderBinding() bool {
	if c.RequireHolderBinding == nil {
		return true
	}
	return *c.RequireHolderBinding
}

// QueryResponse contains the values required for a response to a query.
// The authorization response contains a `vp_token` parameter with a json object
// where the keys are the IDs of the DCQL queries and the values are an array of
// serialized credentials
type QueryResponse struct {
	// corresponds to a Credential.Id field
	QueryId string
	// the resulting serialized credential
	Credentials []string
}

type Claim struct {
	// REQUIRED if claim_sets is present in the credential query, OPTIONAL otherwise.
	// a string identifying the particular claim. The same id must not be presented more than once.
	Id string `json:"id"`

	// REQUIRED: A claims path pointer that specifies the path to a claim
	// within the verifiable credential. Each component is a string (object key),
	// int/float64 (array index), or nil (all array elements).
	Path []any `json:"path"`

	// OPTIONAL: A list of strings, integers or boolean values that specifies the expected values of the claim
	Values []any `json:"values,omitempty"`
}

type TrustedAuthorityType string

// Trusted Authority types
const (
	TaType_AuthorityKeyIdentifier TrustedAuthorityType = "aki"
	TaType_EtsiTrustedList        TrustedAuthorityType = "etsi_tl"
	TaType_OpenIdFederation       TrustedAuthorityType = "openid_fed"
)

type TrustedAuthority struct {
	Type   TrustedAuthorityType `json:"type"`   // required
	Values []string             `json:"values"` // required
}

func (c CredentialQuery) AllClaimPaths() iter.Seq[string] {
	return func(yield func(string) bool) {
		for _, claim := range c.Claims {
			for _, component := range claim.Path {
				path, ok := component.(string)
				if !ok {
					continue
				}
				if !yield(path) {
					return
				}
			}
		}
	}
}

// VctValues implements scheme.ValidatableCredentialQuery.
func (c CredentialQuery) VctValues() []string {
	if c.Meta == nil {
		return nil
	}
	return c.Meta.VctValues
}

// ClaimPaths implements scheme.ValidatableCredentialQuery.
func (c CredentialQuery) ClaimPaths() iter.Seq[string] {
	return c.AllClaimPaths()
}
