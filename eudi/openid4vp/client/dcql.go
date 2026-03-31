package client

import (
	"fmt"
	"strings"

	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

type credentialCandidate struct {
	RawCredential irmaclient.SdJwtVcAndInfo
	ClaimMatches  []claimMatch
}

type claimMatch struct {
	Attribute irma.AttributeIdentifier
	Value     irma.TranslatedString
}

type singleCredentialQueryCandidates struct {
	// The dcql.CredentialQuery
	Query dcql.CredentialQuery
	// The names of the attributes requested in this credential query
	RequestedAttributes []string
	// A list of credential info and the instance that satisfy the requirements described by the query
	SatisfyingCredentials []credentialCandidate
}

type DcqlQueryCandidates struct {
	Candidates  [][]irmaclient.DisclosureCandidates
	QueryIdMap  map[irma.AttributeIdentifier]string
	Satisfiable bool
}

func GetCandidatesForDcqlQuery(storage irmaclient.SdJwtVcStorage, query dcql.DcqlQuery) (*DcqlQueryCandidates, error) {
	allAvailableCredentials, err := findAllCandidatesForAllCredentialQueries(storage, query.Credentials)
	if err != nil {
		return nil, err
	}

	if query.CredentialSets != nil {
		return constructCandidatesForCredentialSets(allAvailableCredentials, query.CredentialSets)
	}

	return constructCandidatesFromCredentialQueries(query.Credentials, allAvailableCredentials)
}

// claimKey returns the claim's ID if set, otherwise its dot-joined path.
// DCQL allows claims to omit the id field when claim_sets is absent, so we
// need a stable, unique key that works in both cases.
func claimKey(claim dcql.Claim) string {
	if claim.Id != "" {
		return claim.Id
	}
	return strings.Join(claim.Path, ".")
}

func constructClaimMap(claims []dcql.Claim) map[string]dcql.Claim {
	result := map[string]dcql.Claim{}
	for _, c := range claims {
		result[claimKey(c)] = c
	}
	return result
}

func constructEmptyDisConForQuery(query dcql.CredentialQuery) ([]irmaclient.DisclosureCandidates, error) {
	con := irmaclient.DisclosureCandidates{}
	claimMap := constructClaimMap(query.Claims)
	claimSet := []string{}

	// if there are claim sets involved, construct an empty credential based on the first set only
	// with the first requested value.
	// this is an arbitrary choice.
	if len(query.ClaimSets) != 0 {
		claimSet = query.ClaimSets[0]
	} else {
		for _, c := range query.Claims {
			claimSet = append(claimSet, claimKey(c))
		}
	}

	// TODO: support for multiple VctValues ?
	credId := query.Meta.VctValues[0]
	for _, claimId := range claimSet {
		claim := claimMap[claimId]
		attr := claim.Path[0]
		candidate := &irmaclient.DisclosureCandidate{
			AttributeIdentifier: &irma.AttributeIdentifier{
				Type: irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", credId, attr)),
			},
		}

		if len(claim.Values) != 0 {
			firstValue, ok := claim.Values[0].(string)
			if !ok {
				return nil, fmt.Errorf("claim value not a string while it was expected to be")
			}
			candidate.Value = irma.NewTranslatedString(&firstValue)
		}

		con = append(con, candidate)
	}
	return []irmaclient.DisclosureCandidates{con}, nil
}

func constructCandidatesFromCredentialQueries(
	queries []dcql.CredentialQuery,
	allAvailableCredentials map[string]singleCredentialQueryCandidates,
) (*DcqlQueryCandidates, error) {
	conDisCon := [][]irmaclient.DisclosureCandidates{}
	satisfiable := true
	queryIdMap := map[irma.AttributeIdentifier]string{}

	for _, query := range queries {
		candidates, ok := allAvailableCredentials[query.Id]

		empty, err := constructEmptyDisConForQuery(query)
		if err != nil {
			return nil, err
		}

		if !ok || len(candidates.SatisfyingCredentials) == 0 {
			satisfiable = false
			conDisCon = append(conDisCon, empty)
		} else {
			disCon := []irmaclient.DisclosureCandidates{}
			for _, candidate := range candidates.SatisfyingCredentials {
				con := irmaclient.DisclosureCandidates{}

				for _, match := range candidate.ClaimMatches {
					queryIdMap[match.Attribute] = query.Id
					con = append(con, &irmaclient.DisclosureCandidate{
						AttributeIdentifier: &match.Attribute,
						Value:               match.Value,
					})
				}
				disCon = append(disCon, con)
			}

			// also add empty to this discon so it can be used to issue new credentials in the UI
			disCon = append(disCon, empty...)

			conDisCon = append(conDisCon, disCon)
		}
	}

	return &DcqlQueryCandidates{
		Candidates:  conDisCon,
		Satisfiable: satisfiable,
		QueryIdMap:  queryIdMap,
	}, nil
}

func constructCandidatesForCredentialSets(
	allAvailableCredentials map[string]singleCredentialQueryCandidates,
	credentialSets []dcql.CredentialSetQuery,
) (*DcqlQueryCandidates, error) {
	conDisCon := [][]irmaclient.DisclosureCandidates{}
	conDisConSatisfied := true
	queryIdMap := map[irma.AttributeIdentifier]string{}

	// each purpose (con)
	for _, credentialSet := range credentialSets {
		disCon := []irmaclient.DisclosureCandidates{}
		disConSatisfied := false

		if credentialSet.Required != nil && !*credentialSet.Required {
			disCon = append(disCon, irmaclient.DisclosureCandidates{})
			disConSatisfied = true
		}

		// each option for this purpose (dis)
		for _, option := range credentialSet.Options {
			if len(option) > 1 {
				return nil, fmt.Errorf("credential set `options` field has inner option array that consists of multiple credential queries, which is not supported at the moment")
			}

			requiredCredentialQueryId := option[0]
			queryResult := allAvailableCredentials[requiredCredentialQueryId]

			// add an attribute instance for each of the requested attributes for each of the satisying credentials
			// each satisfying credential should become a dis
			for _, credential := range queryResult.SatisfyingCredentials {
				con := irmaclient.DisclosureCandidates{}
				conSatisfied := true

				for _, match := range credential.ClaimMatches {
					con = append(con, &irmaclient.DisclosureCandidate{AttributeIdentifier: &match.Attribute, Value: match.Value})
					queryIdMap[match.Attribute] = requiredCredentialQueryId
				}
				disCon = append(disCon, con)
				if conSatisfied {
					disConSatisfied = true
				}

			}

			// add empty discon to allow the user to issue new instances of the credential
			empty, err := constructEmptyDisConForQuery(queryResult.Query)
			if err != nil {
				return nil, fmt.Errorf("failed to construct empty discon for query: %s", queryResult.Query.Id)
			}

			disCon = append(disCon, empty...)
		}

		conDisCon = append(conDisCon, disCon)
		if !disConSatisfied {
			conDisConSatisfied = false
		}
	}
	return &DcqlQueryCandidates{
		Candidates:  conDisCon,
		Satisfiable: conDisConSatisfied,
		QueryIdMap:  queryIdMap,
	}, nil
}

func getClaimMatches(info irmaclient.SdJwtVcBatchMetadata, claims []dcql.Claim) (map[string]claimMatch, error) {
	result := make(map[string]claimMatch)
	for _, claim := range claims {
		attributeValue, ok := info.Attributes[claim.Path[0]]
		if !ok {
			continue
		}
		attributeValueString := attributeValue.(string)
		attributeType := irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", info.CredentialType, claim.Path[0]))
		if len(claim.Values) != 0 {
			for _, requestedValueAny := range claim.Values {
				requestedValueString := requestedValueAny.(string)
				if attributeValueString == requestedValueString {
					match := claimMatch{
						Attribute: irma.AttributeIdentifier{
							Type:           attributeType,
							CredentialHash: info.Hash,
						},
						Value: irma.NewTranslatedString(&requestedValueString),
					}
					result[claimKey(claim)] = match
					break
				}
			}
		} else {
			result[claimKey(claim)] = claimMatch{
				Attribute: irma.AttributeIdentifier{
					Type:           attributeType,
					CredentialHash: info.Hash,
				},
			}
		}
	}
	return result, nil
}

// Will return a list of all claim matches corresponding to the provided keys.
// Will return nil when not all of the keys are present in the map.
func getAllMatchesForKeys(matches map[string]claimMatch, keys []string) []claimMatch {
	result := []claimMatch{}
	for _, key := range keys {
		match, ok := matches[key]
		if !ok {
			return nil
		}
		result = append(result, match)
	}
	return result
}

func filterClaimMatches(query dcql.CredentialQuery, matches map[string]claimMatch) []claimMatch {
	if len(query.ClaimSets) != 0 {
		for _, con := range query.ClaimSets {
			// first fully satisfied con is enough
			if result := getAllMatchesForKeys(matches, con); result != nil {
				return result
			}
		}
		return nil
	}

	result := []claimMatch{}
	for _, claim := range query.Claims {
		match, ok := matches[claimKey(claim)]
		if !ok {
			return nil
		}
		result = append(result, match)
	}
	return result
}

// Only returns the credential instances that have ALL attributes required by the list of claims
func filterCredentialsWithClaims(entries []irmaclient.SdJwtVcAndInfo, query dcql.CredentialQuery) ([]credentialCandidate, error) {
	result := []credentialCandidate{}
	for _, e := range entries {
		claimMatches, err := getClaimMatches(e.Metadata, query.Claims)
		if err != nil {
			return nil, err
		}
		if matches := filterClaimMatches(query, claimMatches); matches != nil {
			result = append(result, credentialCandidate{
				RawCredential: e,
				ClaimMatches:  matches,
			})
		}
	}
	return result, nil
}

func findAllCandidatesForCredQuery(storage irmaclient.SdJwtVcStorage, query dcql.CredentialQuery) ([]credentialCandidate, error) {
	// TODO: get credentials for ALL VctValues
	return filterCredentialsWithClaims(storage.GetCredentialsForId(query.Meta.VctValues[0]), query)
}

func findAllCandidatesForAllCredentialQueries(
	storage irmaclient.SdJwtVcStorage,
	queries []dcql.CredentialQuery,
) (map[string]singleCredentialQueryCandidates, error) {
	result := map[string]singleCredentialQueryCandidates{}

	for _, query := range queries {
		if irmaclient.CredentialFormat(query.Format) != irmaclient.Format_SdJwtVc {
			return nil, fmt.Errorf("credential query '%s' contains unsupported format '%s'", query.Id, query.Format)
		}
		candidates, err := findAllCandidatesForCredQuery(storage, query)
		if err != nil {
			return nil, err
		}

		attrs := []string{}
		for _, c := range query.Claims {
			attrs = append(attrs, c.Path[0])
		}

		result[query.Id] = singleCredentialQueryCandidates{
			Query:                 query,
			SatisfyingCredentials: candidates,
			RequestedAttributes:   attrs,
		}
	}
	return result, nil
}
