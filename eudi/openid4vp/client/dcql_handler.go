package client

import (
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// DcqlHandler orchestrates the handling of a complete DCQL query by delegating
// individual credential queries to the appropriate DcqlCredentialQueryHandler
// based on credential format. It also handles credential_sets aggregation and
// disclosure plan building.
type DcqlHandler struct {
	credentialQueryHandlers []clientmodels.DcqlCredentialQueryHandler
}

// NewDcqlHandler creates a new DcqlHandler with the given credential query handlers.
func NewDcqlHandler(handlers []clientmodels.DcqlCredentialQueryHandler) *DcqlHandler {
	return &DcqlHandler{credentialQueryHandlers: handlers}
}

// DcqlResult contains the results of processing a full DCQL query.
type DcqlResult struct {
	// Per-query results keyed by credential query ID.
	QueryResults map[string]*clientmodels.CredentialQueryResult
	// Maps credential hashes to their DCQL query IDs.
	HashToQueryId map[string]string
}

// FindCandidates processes a complete DCQL query by delegating each credential query
// to the handler matching its format. Returns per-query results and a hash-to-queryId mapping.
func (h *DcqlHandler) FindCandidates(query dcql.DcqlQuery) (*DcqlResult, error) {
	queryResults := make(map[string]*clientmodels.CredentialQueryResult, len(query.Credentials))
	hashToQueryId := make(map[string]string)

	for _, credQuery := range query.Credentials {
		handler, err := h.findHandlerForFormat(credQuery.Format)
		if err != nil {
			return nil, fmt.Errorf("credential query '%s': %w", credQuery.Id, err)
		}

		result, err := handler.FindCandidates(credQuery)
		if err != nil {
			return nil, fmt.Errorf("credential query '%s': failed to find candidates: %w", credQuery.Id, err)
		}

		queryResults[credQuery.Id] = result

		for _, owned := range result.OwnedCandidates {
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
	query dcql.DcqlQuery,
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
	query dcql.DcqlQuery,
	selections []clientmodels.DisclosureSelection,
	nonce string,
	clientId string,
) (*clientmodels.PreparedDisclosure, error) {
	// Build a map from queryId -> format
	queryFormat := make(map[string]string, len(query.Credentials))
	for _, cq := range query.Credentials {
		queryFormat[cq.Id] = cq.Format
	}

	// Group selections by format
	selectionsByFormat := make(map[string][]clientmodels.DisclosureSelection)
	for _, sel := range selections {
		format, ok := queryFormat[sel.QueryId]
		if !ok {
			return nil, fmt.Errorf("unknown query id %q in selection", sel.QueryId)
		}
		selectionsByFormat[format] = append(selectionsByFormat[format], sel)
	}

	result := &clientmodels.PreparedDisclosure{}

	for format, sels := range selectionsByFormat {
		handler, err := h.findHandlerForFormat(format)
		if err != nil {
			return nil, err
		}

		prepared, err := handler.PrepareDisclosure(sels, nonce, clientId)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare disclosure for format %q: %w", format, err)
		}

		result.QueryResponses = append(result.QueryResponses, prepared.QueryResponses...)
		result.CredentialLogs = append(result.CredentialLogs, prepared.CredentialLogs...)
	}

	return result, nil
}

func (h *DcqlHandler) findHandlerForFormat(format string) (clientmodels.DcqlCredentialQueryHandler, error) {
	for _, handler := range h.credentialQueryHandlers {
		if handler.Format() == format {
			return handler, nil
		}
	}
	return nil, fmt.Errorf("no credential query handler for format %q", format)
}
