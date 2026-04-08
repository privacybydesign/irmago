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
	// The attribute names the user chose to disclose
	AttributeNames []string
}

// PreparedDisclosure contains the VP token response data and log information
// after the selected credentials have been prepared for disclosure.
type PreparedDisclosure struct {
	// The query responses to include in the VP token
	QueryResponses []QueryResponse
	// Log data for each disclosed credential
	CredentialLogs []clientmodels.LogCredential
}

// DcqlCredentialQueryHandler handles DCQL credential queries for a specific credential format.
type DcqlCredentialQueryHandler interface {
	// CanHandleCredentialQuery returns true if this handler can process the given credential query.
	CanHandleCredentialQuery(query CredentialQuery) bool

	// FindCandidates finds all credential instances that match the given DCQL credential query.
	FindCandidates(query CredentialQuery) (*CredentialQueryResult, error)

	// PrepareDisclosure prepares the selected credentials for inclusion in the VP token.
	PrepareDisclosure(selections []DisclosureSelection, nonce string, clientId string) (*PreparedDisclosure, error)
}
