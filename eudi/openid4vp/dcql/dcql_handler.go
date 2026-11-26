package dcql

import (
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// DcqlHandler orchestrates the handling of a complete DCQL query by delegating
// individual credential queries to the appropriate DcqlCredentialQueryHandler
// based on credential format. It also handles credential_sets aggregation and
// disclosure plan building.
type DcqlHandler struct {
	credentialQueryHandlers []DcqlCredentialQueryHandler
}

// NewDcqlHandler creates a new DcqlHandler with the given credential query handlers.
func NewDcqlHandler(handlers []DcqlCredentialQueryHandler) *DcqlHandler {
	return &DcqlHandler{credentialQueryHandlers: handlers}
}

// DcqlResult contains the results of processing a full DCQL query.
type DcqlResult struct {
	// Per-query results keyed by credential query ID.
	QueryResults map[string]*CredentialQueryResult
}

// FindCandidates processes a complete DCQL query by delegating each credential query
// to the handler matching its format. Returns the per-query results.
func (h *DcqlHandler) FindCandidates(query DcqlQuery) (*DcqlResult, error) {
	queryResults := make(map[string]*CredentialQueryResult, len(query.Credentials))

	for _, credQuery := range query.Credentials {
		handlers := h.findHandlersForQuery(credQuery)
		if len(handlers) == 0 {
			return nil, fmt.Errorf("credential query '%s': no credential query handler for query", credQuery.Id)
		}

		merged := &CredentialQueryResult{}
		for _, handler := range handlers {
			result, err := handler.FindCandidates(credQuery)
			if err != nil {
				return nil, fmt.Errorf("credential query '%s': failed to find candidates: %w", credQuery.Id, err)
			}
			merged.OwnedCandidates = append(merged.OwnedCandidates, result.OwnedCandidates...)
			merged.ObtainableDescriptors = append(merged.ObtainableDescriptors, result.ObtainableDescriptors...)
		}

		queryResults[credQuery.Id] = merged
	}

	return &DcqlResult{QueryResults: queryResults}, nil
}

// BuildDisclosurePlan builds the DisclosurePlan for the DCQL query from the
// candidates found for it (see buildChoices). previousPlan is the plan last
// sent for this request (nil the first time) and preExistingHashes the cards
// held when the request arrived; together they say what was issued for it
// since (clientmodels.TrackIssued).
func (h *DcqlHandler) BuildDisclosurePlan(
	query DcqlQuery,
	result *DcqlResult,
	previousPlan *clientmodels.DisclosurePlan,
	preExistingHashes map[string]struct{},
) (*clientmodels.DisclosurePlan, error) {
	choices, err := buildChoices(query, result.QueryResults)
	if err != nil {
		return nil, err
	}
	plan := &clientmodels.DisclosurePlan{Choices: choices}
	clientmodels.TrackIssued(plan, previousPlan, preExistingHashes)
	return plan, nil
}

// PrepareDisclosure prepares the selected credentials for the VP token by delegating
// to the appropriate handlers based on the credential query.
func (h *DcqlHandler) PrepareDisclosure(
	query DcqlQuery,
	selections []DisclosureSelection,
	nonce string,
	audience string,
	binding ResponseBinding,
) (*PreparedDisclosure, error) {
	// Build a map from queryId -> CredentialQuery
	queryById := make(map[string]CredentialQuery, len(query.Credentials))
	for _, cq := range query.Credentials {
		queryById[cq.Id] = cq
	}

	// Group selections by handler
	type handlerIndex int
	selectionsByHandler := make(map[handlerIndex][]DisclosureSelection)
	presentations := make(map[string]int, len(selections))
	for _, sel := range selections {
		credQuery, ok := queryById[sel.QueryId]
		if !ok {
			return nil, fmt.Errorf("unknown query id %q in selection", sel.QueryId)
		}
		// Without `multiple` a query is answered by exactly one presentation
		// (OpenID4VP 1.0 § 6.1); a second one would be a response the verifier
		// rejects, so it is refused here.
		presentations[sel.QueryId]++
		if presentations[sel.QueryId] > 1 && !credQuery.Multiple {
			return nil, fmt.Errorf("credential query %q takes one credential, but more than one was selected for it", sel.QueryId)
		}
		// Propagate the holder binding requirement from the credential query.
		sel.RequireHolderBinding = credQuery.NeedsHolderBinding()
		sel.Claims = credQuery.Claims
		// Propagate the transport binding -- only formats whose holder-binding
		// proof is bound to the session transcript (e.g. mso_mdoc) read these.
		sel.ResponseUri = binding.ResponseUri
		sel.ResponseEncryptionKeyThumbprint = binding.EncryptionKeyThumbprint
		sel.OverDcApi = binding.OverDcApi
		sel.Origin = binding.Origin

		handlers := h.findHandlersForQuery(credQuery)
		if len(handlers) == 0 {
			return nil, fmt.Errorf("no credential query handler for query %q", sel.QueryId)
		}
		// Use the first matching handler
		for i, handler := range h.credentialQueryHandlers {
			if handler.CanHandleCredentialQuery(credQuery) {
				selectionsByHandler[handlerIndex(i)] = append(selectionsByHandler[handlerIndex(i)], sel)
				break
			}
		}
	}

	result := &PreparedDisclosure{}

	for idx, sels := range selectionsByHandler {
		handler := h.credentialQueryHandlers[idx]
		prepared, err := handler.PrepareDisclosure(sels, nonce, audience)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare disclosure: %w", err)
		}
		result.QueryResponses = append(result.QueryResponses, prepared.QueryResponses...)
		result.CredentialLogs = append(result.CredentialLogs, prepared.CredentialLogs...)
	}

	return result, nil
}

func (h *DcqlHandler) findHandlersForQuery(query CredentialQuery) []DcqlCredentialQueryHandler {
	var result []DcqlCredentialQueryHandler
	for _, handler := range h.credentialQueryHandlers {
		if handler.CanHandleCredentialQuery(query) {
			result = append(result, handler)
		}
	}
	return result
}

// CollectOwnedHashes extracts all credential hashes from query results.
func CollectOwnedHashes(queryResults map[string]*CredentialQueryResult) map[string]struct{} {
	hashes := make(map[string]struct{})
	for _, result := range queryResults {
		for _, owned := range result.OwnedCandidates {
			if owned.Hash != "" {
				hashes[owned.Hash] = struct{}{}
			}
		}
	}
	return hashes
}
