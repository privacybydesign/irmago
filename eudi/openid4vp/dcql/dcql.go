package dcql

import (
	"fmt"
	"iter"
	"slices"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

type DcqlQuery struct {
	// REQUIRED: A non-empty array of credential queries that specify the requested verifiable credentials.
	Credentials []CredentialQuery `json:"credentials"`

	// OPTIONAL: A non-empty array of credential set queries that specify specific additional constraints
	// on which of the requested verifiable credentials to return.
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"`
}

// Validate checks the structural rules a DCQL query must satisfy before any of
// it is matched against what the wallet holds, and is transport-independent: the
// same query is illegal over the redirect flow and over the Digital Credentials
// API.
//
// Uniqueness of the ids is the load-bearing one. The vp_token a wallet returns
// is an object keyed by credential query id, so two queries sharing an id have
// no distinct place to put their answers, and which of the two a verifier
// believes it received is left to chance.
func (q DcqlQuery) Validate() error {
	if len(q.Credentials) == 0 {
		return fmt.Errorf("dcql_query must contain at least one credential query")
	}

	seen := make(map[string]struct{}, len(q.Credentials))
	for _, credential := range q.Credentials {
		if credential.Id == "" {
			return fmt.Errorf("credential query id must not be empty")
		}
		if _, duplicate := seen[credential.Id]; duplicate {
			return fmt.Errorf("credential query id %q is present more than once", credential.Id)
		}
		seen[credential.Id] = struct{}{}
	}

	// A credential set may only reference ids the query actually defines;
	// otherwise a required set can never be satisfied and the wallet would go
	// looking for a credential the verifier never described.
	for _, set := range q.CredentialSets {
		// Options is REQUIRED and non-empty per OID4VP § 6.2. An empty array is the
		// same unsatisfiable-set problem as the check below, reached by a different
		// route: there are no options rather than options naming nothing. It needs
		// its own condition because the loop over Options never runs for an empty
		// one, so every check inside it silently passes — which is how an
		// unsatisfiable required set reached the permission screen.
		if len(set.Options) == 0 {
			return fmt.Errorf("credential set has an empty options array, so it can never be satisfied")
		}
		for _, option := range set.Options {
			for _, id := range option {
				if _, known := seen[id]; !known {
					return fmt.Errorf("credential set references unknown credential query id %q", id)
				}
			}
		}
	}
	return nil
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

	// OPTIONAL, mso_mdoc only: whether the verifier intends to retain the
	// disclosed value beyond the transaction. ISO 18013-5 carries this per data
	// element in the reader's DeviceRequest, and OpenID4VP's mso_mdoc profile
	// carries it here. SD-JWT VC has no equivalent, so it stays absent for every
	// other format; an absent value means false, per the spec's default.
	//
	// The wallet does not act on it: it changes what the user is consenting to,
	// not what is disclosed, so the only correct handling is to carry it to the
	// consent screen.
	IntentToRetain bool `json:"intent_to_retain,omitempty"`
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

// VctValues returns the SD-JWT VC type identifiers this query accepts, or nil
// when it names none (every non-SD-JWT format, and a query without meta).
func (c CredentialQuery) VctValues() []string {
	if c.Meta == nil {
		return nil
	}
	return c.Meta.VctValues
}

// DocTypeValue returns the ISO 18013-5 docType this query accepts, or "" when
// it names none (every non-mdoc format, and a query without meta). It mirrors
// VctValues: the two are how the respective formats name a credential type,
// and a query names exactly one format, so at most one of them is ever set.
func (c CredentialQuery) DocTypeValue() string {
	if c.Meta == nil {
		return ""
	}
	return c.Meta.DocTypeValue
}

// mdocClaimPathLength is the fixed depth of an mso_mdoc claim path,
// [namespace, elementIdentifier]. ISO 18013-5 has no nested claims.
const mdocClaimPathLength = 2

// AuthorizationAttributeNames returns the attribute identifiers this query
// requests, for authorizing it against a relying party's registered attribute
// set (scheme.CredentialQueryInfo.AttributeNames).
//
// Unlike AllClaimPaths it is format-aware, and it has to be. An mso_mdoc claim
// path is always [namespace, elementIdentifier], where the namespace is a
// container — the doctype's own scope — and not an attribute anyone registers.
// Contributing both components, as AllClaimPaths does, would demand every
// relying party register its namespaces as though they were attributes, which
// no scheme does, so every mdoc query would be refused.
//
// A malformed mdoc path (not exactly two string components) contributes no
// name. That cannot be used to smuggle a claim past authorization: the same
// shape check in mdoc_dcql's claim matching rejects the path, so no candidate
// is offered and there is nothing to disclose.
//
// Every other format keeps AllClaimPaths' behaviour of contributing every
// string component of every path.
func (c CredentialQuery) AuthorizationAttributeNames() []string {
	if c.Format != string(clientmodels.Format_MsoMdoc) {
		return slices.Collect(c.AllClaimPaths())
	}

	names := make([]string, 0, len(c.Claims))
	for _, claim := range c.Claims {
		if len(claim.Path) != mdocClaimPathLength {
			continue
		}
		if element, ok := claim.Path[mdocClaimPathLength-1].(string); ok {
			names = append(names, element)
		}
	}
	return names
}
