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
	// The verifier's response_uri from the Authorization Request. Only used by formats whose
	// holder-binding proof is bound to the OpenID4VP session transcript (e.g. mso_mdoc's
	// deviceAuth, which signs over [audience, nonce, responseUri]) -- SD-JWT's key-binding JWT
	// only needs nonce/audience and ignores this field.
	ResponseUri string

	// ResponseEncryptionKeyThumbprint is the SHA-256 JWK thumbprint of the
	// verifier's response encryption key, or nil when the response is not
	// encrypted. It occupies the third slot of the OpenID4VP handover the
	// session transcript hashes, so an mdoc's deviceAuth signature only verifies
	// if the wallet and the verifier agree on this value -- which in turn means
	// the response must be encrypted to the very key thumbprinted here, not
	// merely to some key the verifier published. Ignored by SD-JWT, like
	// ResponseUri above.
	ResponseEncryptionKeyThumbprint []byte
}

// ResponseBinding carries the transport-level values that a format whose
// holder-binding proof is bound to the session transcript must sign over. They
// travel together because they are decided together, before any disclosure is
// prepared: the response encryption key in particular has to be chosen while the
// device signature is still ahead of us. Formats whose proof is not
// transcript-bound (every SD-JWT one) ignore all of it.
type ResponseBinding struct {
	// ResponseUri is the verifier's response_uri from the Authorization Request.
	ResponseUri string
	// EncryptionKeyThumbprint is the SHA-256 JWK thumbprint of the key the
	// response is encrypted to, nil when it travels unencrypted.
	EncryptionKeyThumbprint []byte
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
	PrepareDisclosure(selections []DisclosureSelection, nonce string, audience string) (*PreparedDisclosure, error)
}
