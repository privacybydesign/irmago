package dcql

import "github.com/privacybydesign/irmago/common/clientmodels"

// CredentialQueryResult contains the results of finding credentials that match a DCQL credential query.
type CredentialQueryResult struct {
	// Owned credential instances that satisfy the query
	OwnedCandidates []*clientmodels.SelectableCredentialInstance
	// Credential descriptors that could be obtained to satisfy the query
	ObtainableDescriptors []*clientmodels.CredentialDescriptor
}

// DisclosureSelection represents the user's selection of which credential and attributes to disclose
// for a single DCQL credential query.
type DisclosureSelection struct {
	// The DCQL credential query ID this selection is for
	QueryId string
	// The hash of the selected credential instance
	CredentialHash string
	// The claim paths the user chose to disclose (e.g., [["given_name"], ["address", "street"]])
	ClaimPaths [][]any
	// Whether the verifier requires a cryptographic holder binding proof for this credential.
	RequireHolderBinding bool
}

// PreparedDisclosure contains the VP token response data and log information
// after the selected credentials have been prepared for disclosure.
type PreparedDisclosure struct {
	// The query responses to include in the VP token
	QueryResponses []QueryResponse
	// Log data for each disclosed credential
	CredentialLogs []clientmodels.LogCredential
}

// DisclosureContext carries the Authorization Request parameters a handler
// may need while building the VP token response. Adding new fields here is
// preferred over widening the method signature again.
type DisclosureContext struct {
	// Nonce is the verifier-supplied Authorization Request nonce.
	Nonce string
	// ClientId is the verifier's Client ID as it appeared in the request.
	ClientId string
	// ResponseUri is the `response_uri` parameter from the Authorization
	// Request. Mdoc needs it to build the OID4VPHandover; SD-JWT ignores it.
	ResponseUri string
}

// DcqlCredentialQueryHandler handles DCQL credential queries for a specific credential format.
type DcqlCredentialQueryHandler interface {
	// CanHandleCredentialQuery returns true if this handler can process the given credential query.
	CanHandleCredentialQuery(query CredentialQuery) bool

	// FindCandidates finds all credential instances that match the given DCQL credential query.
	FindCandidates(query CredentialQuery) (*CredentialQueryResult, error)

	// PrepareDisclosure prepares the selected credentials for inclusion in the VP token.
	PrepareDisclosure(selections []DisclosureSelection, ctx DisclosureContext) (*PreparedDisclosure, error)
}
