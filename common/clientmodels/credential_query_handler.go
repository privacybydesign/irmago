package clientmodels

import "github.com/privacybydesign/irmago/eudi/openid4vp/dcql"

// CredentialQueryResult contains the results of finding credentials that match a DCQL credential query.
type CredentialQueryResult struct {
	// Owned credential instances that satisfy the query
	OwnedCandidates []*SelectableCredentialInstance
	// Credential descriptors that could be obtained to satisfy the query
	ObtainableDescriptors []*CredentialDescriptor
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
	QueryResponses []dcql.QueryResponse
	// Log data for each disclosed credential
	CredentialLogs []LogCredential
}

// DcqlCredentialQueryHandler handles DCQL credential queries for a specific credential format.
// Implementations combine storage access with display metadata resolution to return
// rich, UI-ready credential information.
type DcqlCredentialQueryHandler interface {
	// Format returns the credential format this handler supports (e.g., "dc+sd-jwt").
	Format() string

	// FindCandidates finds all credential instances that match the given DCQL credential query.
	// Returns owned credential instances with full display metadata and obtainable credential
	// descriptors for credentials the user could issue to satisfy the query.
	FindCandidates(query dcql.CredentialQuery) (*CredentialQueryResult, error)

	// PrepareDisclosure prepares the selected credentials for inclusion in the VP token.
	// This includes selecting the right disclosures, creating key binding JWTs, etc.
	PrepareDisclosure(selections []DisclosureSelection, nonce string, clientId string) (*PreparedDisclosure, error)
}
