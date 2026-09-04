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

// CandidateQuery names the DCQL credential query that one owned candidate of a
// pick-one answers, alongside the claim paths that candidate would disclose.
type CandidateQuery struct {
	// Hash identifies the stored credential the candidate presents.
	Hash string
	// QueryId is the credential query this candidate came from.
	QueryId string
	// PathKeys are the clientmodels.ClaimPathKey values of the attributes this
	// candidate discloses, which is what tells two candidates of the same
	// credential apart.
	PathKeys map[string]struct{}
}

// ChoiceQueryIds lists, in the order of one pick-one's owned options, which
// query each candidate answers.
//
// A list per pick-one, rather than one map for the whole request, because a
// credential hash does not identify a query. One credential can answer several
// queries — a verifier asking for age_over_18 and age_over_21 in two queries is
// answered twice by one age credential — and a single hash-keyed map collapsed
// those onto whichever query was seen last. Every presentation then went back
// under that one query id, the other query went unanswered, and the verifier
// rejected the response as not satisfying its request.
//
// Within one pick-one the hash can be ambiguous too: a credential_sets choice
// whose options are both satisfied by the same credential offers it twice, once
// per option, and the two differ only in the element they would reveal. That is
// why a candidate carries its claim paths.
type ChoiceQueryIds []CandidateQuery

// QueryIdFor resolves which query a selected credential answers: the candidate
// with this hash whose disclosed paths cover the ones selected. Falls back to
// the first candidate with the hash, and to "" when the choice holds none —
// which PrepareDisclosure reports as an unknown query rather than guessing.
func (c ChoiceQueryIds) QueryIdFor(hash string, selectedPaths [][]any) string {
	fallback := ""
	for _, candidate := range c {
		if candidate.Hash != hash {
			continue
		}
		if fallback == "" {
			fallback = candidate.QueryId
		}
		if candidate.covers(selectedPaths) {
			return candidate.QueryId
		}
	}
	return fallback
}

// covers reports whether this candidate would disclose every selected path.
func (c CandidateQuery) covers(paths [][]any) bool {
	for _, path := range paths {
		if _, ok := c.PathKeys[clientmodels.ClaimPathKey(path)]; !ok {
			return false
		}
	}
	return true
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

// BuildDisclosurePlan builds a DisclosurePlan from the DCQL query and candidate results.
// previousPlan is used to track issuance-during-disclosure state across refreshes.
// preExistingHashes tracks which credentials existed at session start.
//
// The second return value runs parallel to the plan's DisclosureChoicesOverview,
// one entry per pick-one, naming the query each of that pick-one's candidates
// answers. It is built here rather than in FindCandidates because this is what
// decides how queries map onto pick-ones, and the two arrangements differ: one
// pick-one per credential query without credential_sets, one per credential set
// with them — and a set merges the candidates of several queries into a single
// pick-one.
func (h *DcqlHandler) BuildDisclosurePlan(
	query DcqlQuery,
	result *DcqlResult,
	previousPlan *clientmodels.DisclosurePlan,
	preExistingHashes map[string]struct{},
) (*clientmodels.DisclosurePlan, []ChoiceQueryIds, error) {
	if query.CredentialSets != nil {
		return buildPlanFromCredentialSets(result.QueryResults, query.CredentialSets, previousPlan, preExistingHashes)
	}
	return buildPlanFromCredentialQueries(query.Credentials, result.QueryResults, previousPlan, preExistingHashes)
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
	for _, sel := range selections {
		credQuery, ok := queryById[sel.QueryId]
		if !ok {
			return nil, fmt.Errorf("unknown query id %q in selection", sel.QueryId)
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
