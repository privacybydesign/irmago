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

// AddHandler adds a credential query handler.
func (h *DcqlHandler) AddHandler(handler DcqlCredentialQueryHandler) {
	h.credentialQueryHandlers = append(h.credentialQueryHandlers, handler)
}

// DcqlResult contains the results of processing a full DCQL query.
type DcqlResult struct {
	// Per-query results keyed by credential query ID.
	QueryResults map[string]*CredentialQueryResult
	// Maps credential hashes to their DCQL query IDs.
	HashToQueryId map[string]string
}

// FindCandidates processes a complete DCQL query by delegating each credential query
// to the handler matching its format. Returns per-query results and a hash-to-queryId mapping.
func (h *DcqlHandler) FindCandidates(query DcqlQuery) (*DcqlResult, error) {
	queryResults := make(map[string]*CredentialQueryResult, len(query.Credentials))
	hashToQueryId := make(map[string]string)

	for _, credQuery := range query.Credentials {
		handlers := h.findHandlersForFormat(credQuery.Format)
		if len(handlers) == 0 {
			return nil, fmt.Errorf("credential query '%s': no credential query handler for format %q", credQuery.Id, credQuery.Format)
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

		for _, owned := range merged.OwnedCandidates {
			if owned.Hash != "" {
				hashToQueryId[owned.Hash] = credQuery.Id
			}
		}
	}

	return &DcqlResult{
		QueryResults:  queryResults,
		HashToQueryId: hashToQueryId,
	}, nil
}

// BuildDisclosurePlan builds a DisclosurePlan from the DCQL query and candidate results.
// previousPlan is used to track issuance-during-disclosure state across refreshes.
// preExistingHashes tracks which credentials existed at session start.
func (h *DcqlHandler) BuildDisclosurePlan(
	query DcqlQuery,
	result *DcqlResult,
	previousPlan *clientmodels.DisclosurePlan,
	preExistingHashes map[string]struct{},
) (*clientmodels.DisclosurePlan, error) {
	if query.CredentialSets != nil {
		return buildPlanFromCredentialSets(result.QueryResults, query.CredentialSets, previousPlan, preExistingHashes)
	}
	return buildPlanFromCredentialQueries(query.Credentials, result.QueryResults, previousPlan, preExistingHashes)
}

// PrepareDisclosure prepares the selected credentials for the VP token by delegating
// to the appropriate handlers based on credential format.
func (h *DcqlHandler) PrepareDisclosure(
	query DcqlQuery,
	selections []DisclosureSelection,
	nonce string,
	clientId string,
) (*PreparedDisclosure, error) {
	// Build a map from queryId -> format
	queryFormat := make(map[string]string, len(query.Credentials))
	for _, cq := range query.Credentials {
		queryFormat[cq.Id] = cq.Format
	}

	// Group selections by format
	selectionsByFormat := make(map[string][]DisclosureSelection)
	for _, sel := range selections {
		format, ok := queryFormat[sel.QueryId]
		if !ok {
			return nil, fmt.Errorf("unknown query id %q in selection", sel.QueryId)
		}
		selectionsByFormat[format] = append(selectionsByFormat[format], sel)
	}

	result := &PreparedDisclosure{}

	for format, sels := range selectionsByFormat {
		handlers := h.findHandlersForFormat(format)
		if len(handlers) == 0 {
			return nil, fmt.Errorf("no credential query handler for format %q", format)
		}

		// Try each handler; the first one that succeeds wins.
		var lastErr error
		for _, handler := range handlers {
			prepared, err := handler.PrepareDisclosure(sels, nonce, clientId)
			if err != nil {
				lastErr = err
				continue
			}
			result.QueryResponses = append(result.QueryResponses, prepared.QueryResponses...)
			result.CredentialLogs = append(result.CredentialLogs, prepared.CredentialLogs...)
			lastErr = nil
			break
		}
		if lastErr != nil {
			return nil, fmt.Errorf("failed to prepare disclosure for format %q: %w", format, lastErr)
		}
	}

	return result, nil
}

func (h *DcqlHandler) findHandlersForFormat(format string) []DcqlCredentialQueryHandler {
	var result []DcqlCredentialQueryHandler
	for _, handler := range h.credentialQueryHandlers {
		if handler.Format() == format {
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
