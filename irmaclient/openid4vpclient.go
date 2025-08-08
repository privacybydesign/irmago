package irmaclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/utils"
)

// ========================================================================

type OpenID4VPClient struct {
	eudiConf          *eudi.Configuration
	keyBinder         sdjwtvc.KeyBinder
	storage           SdJwtVcStorage
	verifierValidator eudi.VerifierValidator
	compatibility     openid4vp.CompatibilityMode
	logsStorage       LogsStorage
}

func NewOpenID4VPClient(
	eudiConf *eudi.Configuration,
	storage SdJwtVcStorage,
	verifierValidator eudi.VerifierValidator,
	keybinder sdjwtvc.KeyBinder,
	logsStorage LogsStorage,
) (*OpenID4VPClient, error) {
	return &OpenID4VPClient{
		eudiConf:          eudiConf,
		keyBinder:         keybinder,
		compatibility:     openid4vp.Compatibility_Draft24,
		storage:           storage,
		verifierValidator: verifierValidator,
		logsStorage:       logsStorage,
	}, nil
}

func (client *OpenID4VPClient) NewSession(fullUrl string, handler Handler) SessionDismisser {
	client.handleSessionAsync(fullUrl, handler)
	return client
}

func (client *OpenID4VPClient) Dismiss() {
	irma.Logger.Info("openid4vp: session dismissed")
}

func handleFailure(handler Handler, message string, fmtArgs ...any) {
	irma.Logger.Errorf(message, fmtArgs...)
	handler.Failure(&irma.SessionError{
		Err: fmt.Errorf(message, fmtArgs...),
	})
}

func (client *OpenID4VPClient) handleSessionAsync(fullUrl string, handler Handler) {
	go func() {
		parsedUrl, err := url.Parse(fullUrl)

		if err != nil {
			handleFailure(handler, "openid4vp: failed to parse request: %v", err)
			return
		}

		requestUri := parsedUrl.Query().Get("request_uri")
		if requestUri == "" {
			handleFailure(handler, "openid4vp: request missing required request_uri")
			return
		}

		irma.Logger.Infof("starting openid4vp session: %v\n", requestUri)
		response, err := http.Get(requestUri)
		if err != nil {
			handleFailure(handler, "openid4vp: failed to get authorization request: %v", err)
			return
		}

		defer response.Body.Close()

		authRequestJwt, err := io.ReadAll(response.Body)

		if err != nil {
			handleFailure(handler, "openid4vp: failed to read authorization request body: %v", err)
			return
		}

		request, endEntityCert, requestorSchemeData, err := client.verifierValidator.ParseAndVerifyAuthorizationRequest(string(authRequestJwt))
		if err != nil {
			handleFailure(handler, "openid4vp: failed to verify authorization request: %v", err)
			return
		}

		// Store the verifier logo in the cache
		filename, path, err := client.eudiConf.CacheVerifierLogo(endEntityCert.Subject.SerialNumber, &requestorSchemeData.Organization.Logo)
		if err != nil {
			handleFailure(handler, "openid4vp: failed to store verifier logo: %v", err)
			return
		}

		// Construct IRMA RequestorInfo from the requestorSchemeData
		requestorInfo := &irma.RequestorInfo{
			//ID:     irma.NewRequestorIdentifier(endEntityCert.Subject.CommonName), // TODO: use the CN, cert thumbprint or something else?
			//Scheme: irma.NewRequestorSchemeIdentifier("eudi"),                     // TODO: do we need/want this for cert-based trust model?
			Name:       requestorSchemeData.Organization.LegalName,
			Industry:   &irma.TranslatedString{},
			Hostnames:  endEntityCert.DNSNames,
			Logo:       &filename,
			LogoPath:   &path,
			ValidUntil: (*irma.Timestamp)(&endEntityCert.NotAfter),
			Unverified: false,
			Languages:  utils.GetMapKeys(requestorSchemeData.Organization.LegalName),
			Wizards:    map[irma.IssueWizardIdentifier]*irma.IssueWizard{},
		}

		irma.Logger.Infof("auth request: %#v\n", request)
		err = client.handleAuthorizationRequest(request, requestorInfo, handler)

		if err != nil {
			handleFailure(handler, "openid4vp: failed to handle authorization request: %v", err)
			return
		}
	}()
}

type AuthorizationResponseConfig struct {
	State             string
	QueryResponses    []dcql.QueryResponse
	ResponseUri       string
	ResponseType      string
	ResponseMode      openid4vp.ResponseMode
	CompatibilityMode openid4vp.CompatibilityMode
	EncryptionKey     *jwk.Key
}

func logMarshalled(message string, value any) {
	jsoon, err := json.MarshalIndent(value, "", "   ")
	if err != nil {
		irma.Logger.Errorf("%s: failed to marshal: %v", message, err)
	} else {
		irma.Logger.Infof("\n%s\n%s\n\n", message, string(jsoon))
	}
}

func (client *OpenID4VPClient) handleAuthorizationRequest(
	request *openid4vp.AuthorizationRequest,
	requestorInfo *irma.RequestorInfo,
	handler Handler,
) error {
	candidates, err := getCandidatesForDcqlQuery(client.storage, request.DcqlQuery)

	if err != nil {
		return err
	}

	choice := client.requestAndAwaitPermission(candidates, requestorInfo, handler)
	if choice == nil {
		irma.Logger.Info("openid4vp: no attributes selected for disclosure, cancelling")
		handler.Cancelled()
		return nil
	}

	logMarshalled("choice:", choice)
	credentials, credLog, err := client.getCredentialsForChoices(candidates.QueryIdMap, choice.Attributes, request.Nonce, request.ClientId)

	if err != nil {
		return err
	}

	logMarshalled("credentials for choice:", credentials)

	httpClient := http.Client{}
	authResponse := AuthorizationResponseConfig{
		CompatibilityMode: client.compatibility,
		State:             request.State,
		QueryResponses:    credentials,
		ResponseUri:       request.ResponseUri,
		ResponseType:      request.ResponseType,
		ResponseMode:      request.ResponseMode,
	}
	responseReq, err := createAuthorizationResponseHttpRequest(authResponse)
	logMarshalled("responsereq:", responseReq)
	if err != nil {
		return err
	}

	response, err := httpClient.Do(responseReq)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("response status was not ok: %v", response)
	}

	// note: we don't add irma.ActionDisclosing, as that's for the irma protocol
	// and will cause problems when deserializing.
	// instead we can just assume a log containing OpenID4VP info to be for disclosure
	logEntry := &LogEntry{
		Time:       irma.Timestamp(time.Now()),
		ServerName: requestorInfo,
		OpenID4VP: &OpenID4VPDisclosureLog{
			DisclosedCredentials: credLog,
		},
	}
	err = client.logsStorage.AddLogEntry(logEntry)
	if err != nil {
		return fmt.Errorf("failed to add log entry: %v", err)
	}

	handler.Success("managed to complete openid4vp session")
	return nil
}

// will return the SdJwtVc instances to be sent as the response to the complete DcqlQuery, based on the users choices.
func (client *OpenID4VPClient) getCredentialsForChoices(
	queryIdMap map[irma.AttributeIdentifier]string,
	choices [][]*irma.AttributeIdentifier,
	nonce string,
	clientId string,
) ([]dcql.QueryResponse, []CredentialLog, error) {
	// map of attribute identifiers by the dcql query id
	attributesByQueryId := map[string][]*irma.AttributeIdentifier{}

	for _, credential := range choices {
		// let's for now assume that all selected attributes for a given credential type all come from
		// the same credential instance
		for _, attribute := range credential {
			queryId, ok := queryIdMap[*attribute]

			if !ok {
				return []dcql.QueryResponse{}, nil, fmt.Errorf("query id map doesn't contain '%v'", *attribute)
			}

			_, ok = attributesByQueryId[queryId]
			if !ok {
				attributesByQueryId[queryId] = []*irma.AttributeIdentifier{attribute}
			} else {
				attributesByQueryId[queryId] = append(attributesByQueryId[queryId], attribute)
			}
		}
	}

	queryResponses := []dcql.QueryResponse{}
	credentialInfos := []CredentialLog{}

	for queryId, attributes := range attributesByQueryId {
		sdjwt, err := client.storage.GetCredentialByHash(attributes[0].CredentialHash)
		if err != nil {
			return []dcql.QueryResponse{}, nil, fmt.Errorf("failed to get credential: %v", err)
		}

		err = client.storage.RemoveLastUsedInstanceOfCredentialByHash(attributes[0].CredentialHash)
		if err != nil {
			return []dcql.QueryResponse{}, nil, fmt.Errorf("failed to remove instance of sdjwtvc credential: %v", err)
		}

		disclosureNames := []string{}
		for _, attr := range attributes {
			disclosureNames = append(disclosureNames, attr.Type.Name())
		}

		sdjwtSelected, err := sdjwtvc.SelectDisclosures(sdjwt.SdJwtVc, disclosureNames)
		if err != nil {
			return []dcql.QueryResponse{}, nil, fmt.Errorf("failed to select disclosures: %v", err)
		}

		kbjwt, err := sdjwtvc.CreateKbJwt(sdjwtSelected, client.keyBinder, nonce, clientId)
		if err != nil {
			return []dcql.QueryResponse{}, nil, fmt.Errorf("failed to create kbjwt: %v", err)
		}

		sdjwtWithKb := sdjwtvc.AddKeyBindingJwtToSdJwtVc(sdjwtSelected, kbjwt)

		queryResponses = append(queryResponses, dcql.QueryResponse{
			QueryId:     queryId,
			Credentials: []string{string(sdjwtWithKb)},
		})
		credentialInfos = append(credentialInfos, createSdJwtCredendtialLog(sdjwt.Info, attributes))
	}
	return queryResponses, credentialInfos, nil
}

func createSdJwtCredendtialLog(info irma.CredentialInfo, disclosures []*irma.AttributeIdentifier) CredentialLog {
	result := CredentialLog{
		CredentialType: info.Identifier().String(),
		Formats:        []CredentialFormat{Format_SdJwtVc},
		Attributes:     map[string]string{},
	}

	for _, attr := range disclosures {
		result.Attributes[attr.Type.Name()] = info.Attributes[attr.Type][""]
	}

	return result
}

func getCandidatesForDcqlQuery(storage SdJwtVcStorage, query dcql.DcqlQuery) (*DcqlQueryCandidates, error) {
	allAvailableCredentials, err := findAllCandidatesForAllCredentialQueries(storage, query.Credentials)
	if err != nil {
		return nil, err
	}

	if query.CredentialSets != nil {
		return constructCandidatesForCredentialSets(allAvailableCredentials, query.CredentialSets)
	}

	return constructCandidatesFromCredentialQueries(query.Credentials, allAvailableCredentials)
}

func constructClaimMap(claims []dcql.Claim) map[string]dcql.Claim {
	result := map[string]dcql.Claim{}
	for _, c := range claims {
		result[c.Id] = c
	}
	return result
}

func constructEmptyDisConForQuery(query dcql.CredentialQuery) ([]DisclosureCandidates, error) {
	con := DisclosureCandidates{}
	claimMap := constructClaimMap(query.Claims)
	claimSet := []string{}

	// if there are claim sets involved, construct an empty credential based on the first set only
	// with the first requested value.
	// this is an arbitrary choice.
	if len(query.ClaimSets) != 0 {
		claimSet = query.ClaimSets[0]
	} else {
		for _, c := range query.Claims {
			claimSet = append(claimSet, c.Id)
		}
	}

	credId := query.Meta.VctValues[0]
	for _, claimId := range claimSet {
		claim := claimMap[claimId]
		attr := claim.Path[0]
		candidate := &DisclosureCandidate{
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
	return []DisclosureCandidates{con}, nil
}

func constructCandidatesFromCredentialQueries(
	queries []dcql.CredentialQuery,
	allAvailableCredentials map[string]SingleCredentialQueryCandidates,
) (*DcqlQueryCandidates, error) {
	conDisCon := [][]DisclosureCandidates{}
	satisfiable := true
	queryIdMap := map[irma.AttributeIdentifier]string{}

	for _, query := range queries {
		candidates, ok := allAvailableCredentials[query.Id]
		if !ok || len(candidates.SatisfyingCredentials) == 0 {
			satisfiable = false
			disCon, err := constructEmptyDisConForQuery(query)
			if err != nil {
				return nil, err
			}
			conDisCon = append(conDisCon, disCon)
		} else {
			disCon := []DisclosureCandidates{}
			for _, candidate := range candidates.SatisfyingCredentials {
				con := DisclosureCandidates{}

				for _, match := range candidate.ClaimMatches {
					queryIdMap[match.Attribute] = query.Id
					con = append(con, &DisclosureCandidate{
						AttributeIdentifier: &match.Attribute,
						Value:               match.Value,
					})
				}
				disCon = append(disCon, con)
			}
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
	allAvailableCredentials map[string]SingleCredentialQueryCandidates,
	credentialSets []dcql.CredentialSetQuery,
) (*DcqlQueryCandidates, error) {
	conDisCon := [][]DisclosureCandidates{}
	conDisConSatisfied := true
	queryIdMap := map[irma.AttributeIdentifier]string{}

	// each purpose (con)
	for _, credentialSet := range credentialSets {
		disCon := []DisclosureCandidates{}
		disConSatisfied := false

		if credentialSet.Required != nil && !*credentialSet.Required {
			disCon = append(disCon, DisclosureCandidates{})
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
				con := DisclosureCandidates{}
				conSatisfied := true

				for _, match := range credential.ClaimMatches {
					con = append(con, &DisclosureCandidate{AttributeIdentifier: &match.Attribute, Value: match.Value})
					queryIdMap[match.Attribute] = requiredCredentialQueryId
				}
				disCon = append(disCon, con)
				if conSatisfied {
					disConSatisfied = true
				}
			}
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

type CredentialCandidate struct {
	RawCredential SdJwtVcAndInfo
	ClaimMatches  []ClaimMatch
}

type ClaimMatch struct {
	Attribute irma.AttributeIdentifier
	Value     irma.TranslatedString
}

func sameTranslatedString(a irma.TranslatedString, b irma.TranslatedString) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		bVal, ok := b[key]
		if !ok {
			return false
		}
		if bVal != value {
			return false
		}
	}
	return true
}

func getClaimMatches(info irma.CredentialInfo, claims []dcql.Claim) (map[string]ClaimMatch, error) {
	result := make(map[string]ClaimMatch)
	for _, claim := range claims {
		attrId := irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", info.Identifier(), claim.Path[0]))
		attributeValue, ok := info.Attributes[attrId]
		if !ok {
			continue
		}
		if len(claim.Values) != 0 {
			for _, requestedValueAny := range claim.Values {
				requestedValueString := requestedValueAny.(string)
				requestedValue := irma.NewTranslatedString(&requestedValueString)
				if sameTranslatedString(attributeValue, requestedValue) {
					match := ClaimMatch{
						Attribute: irma.AttributeIdentifier{
							Type:           attrId,
							CredentialHash: info.Hash,
						},
						Value: requestedValue,
					}
					result[claim.Id] = match
					break
				}
			}
		} else {
			result[claim.Id] = ClaimMatch{
				Attribute: irma.AttributeIdentifier{
					Type:           attrId,
					CredentialHash: info.Hash,
				},
			}
		}
	}
	return result, nil
}

// Will return a list of all claim matches corresponding to the provided keys.
// Will return nil when not all of the keys are present in the map.
func getAllMatchesForKeys(matches map[string]ClaimMatch, keys []string) []ClaimMatch {
	result := []ClaimMatch{}
	for _, key := range keys {
		match, ok := matches[key]
		if !ok {
			return nil
		}
		result = append(result, match)
	}
	return result
}

func filterClaimMatches(query dcql.CredentialQuery, matches map[string]ClaimMatch) []ClaimMatch {
	if len(query.ClaimSets) != 0 {
		for _, con := range query.ClaimSets {
			// first fully satisfied con is enough
			if result := getAllMatchesForKeys(matches, con); result != nil {
				return result
			}
		}
		return nil
	}

	for _, claim := range query.Claims {
		if _, ok := matches[claim.Id]; !ok {
			return nil
		}
	}

	return mapToList(matches)
}

// Only returns the credential instances that have ALL attributes required by the list of claims
func filterCredentialsWithClaims(entries []SdJwtVcAndInfo, query dcql.CredentialQuery) ([]CredentialCandidate, error) {
	result := []CredentialCandidate{}
	for _, e := range entries {
		claimMatches, err := getClaimMatches(e.Info, query.Claims)
		if err != nil {
			return nil, err
		}
		if matches := filterClaimMatches(query, claimMatches); matches != nil {
			result = append(result, CredentialCandidate{
				RawCredential: e,
				ClaimMatches:  matches,
			})
		}
	}
	return result, nil
}

func mapToList[T any](claims map[string]T) []T {
	result := []T{}
	for _, value := range claims {
		result = append(result, value)
	}
	return result
}

func findAllCandidatesForCredQuery(storage SdJwtVcStorage, query dcql.CredentialQuery) ([]CredentialCandidate, error) {
	return filterCredentialsWithClaims(storage.GetCredentialsForId(query.Meta.VctValues[0]), query)
}

type SingleCredentialQueryCandidates struct {
	// The id for the dcql.CredentialQuery
	CredentialQueryId string
	// The names of the attributes requested in this credential query
	RequestedAttributes []string
	// A list of credential info and the instance that satisfy the requirements described by the query
	SatisfyingCredentials []CredentialCandidate
}

func findAllCandidatesForAllCredentialQueries(
	storage SdJwtVcStorage,
	queries []dcql.CredentialQuery,
) (map[string]SingleCredentialQueryCandidates, error) {
	result := map[string]SingleCredentialQueryCandidates{}

	for _, query := range queries {
		if CredentialFormat(query.Format) != Format_SdJwtVc {
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

		result[query.Id] = SingleCredentialQueryCandidates{
			CredentialQueryId:     query.Id,
			SatisfyingCredentials: candidates,
			RequestedAttributes:   attrs,
		}
	}
	return result, nil
}

type DcqlQueryCandidates struct {
	Candidates  [][]DisclosureCandidates
	QueryIdMap  map[irma.AttributeIdentifier]string
	Satisfiable bool
}

func (client *OpenID4VPClient) requestAndAwaitPermission(
	queryResult *DcqlQueryCandidates,
	requestorInfo *irma.RequestorInfo,
	handler Handler,
) *irma.DisclosureChoice {
	disclosureRequest := &irma.DisclosureRequest{}

	choiceChan := make(chan *irma.DisclosureChoice, 1)

	handler.RequestVerificationPermission(
		disclosureRequest,
		queryResult.Satisfiable,
		queryResult.Candidates,
		requestorInfo,
		PermissionHandler(func(proceed bool, choice *irma.DisclosureChoice) {
			if proceed {
				choiceChan <- choice
			} else {
				choiceChan <- nil
			}
		},
		),
	)

	return <-choiceChan
}

func createAuthorizationResponseHttpRequest(config AuthorizationResponseConfig) (*http.Request, error) {
	values := url.Values{}

	if config.ResponseMode == openid4vp.ResponseMode_DirectPost {
		vpToken, err := createDirectPostVpToken(config.CompatibilityMode, config.QueryResponses)
		if err != nil {
			return nil, err
		}
		values.Add("vp_token", vpToken)
	}

	if config.ResponseMode == openid4vp.ResponseMode_DirectPostJwt {
		if config.EncryptionKey == nil {
			return nil, fmt.Errorf("using response mode %v, but the encryption key is nil", openid4vp.ResponseMode_DirectPostJwt)
		}
		jwe, err := createDirectPostJwtEncryptedResponse(config.CompatibilityMode, config.QueryResponses, *config.EncryptionKey)
		if err != nil {
			return nil, err
		}
		values.Add("response", jwe)
	}

	values.Add("state", config.State)

	req, err := http.NewRequest(http.MethodPost, config.ResponseUri, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	return req, nil
}

func createDirectPostJwtEncryptedResponse(compatibility openid4vp.CompatibilityMode, queryResponses []dcql.QueryResponse, encryptionKey jwk.Key) (string, error) {
	vpToken, err := createVpToken(compatibility, queryResponses)
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"vp_token": vpToken,
	}
	return encryptJwe(payload, encryptionKey)
}

func encryptJwe(payload map[string]any, key jwk.Key) (string, error) {
	return "", nil
}

func createVpToken(compatibility openid4vp.CompatibilityMode, queryResponses []dcql.QueryResponse) (any, error) {
	if compatibility == openid4vp.Compatibility_LatestDraft {
		content := map[string][]string{}
		for _, resp := range queryResponses {
			content[resp.QueryId] = resp.Credentials
		}

		return content, nil
	}
	if compatibility == openid4vp.Compatibility_Draft24 {
		content := map[string]string{}
		for _, resp := range queryResponses {
			content[resp.QueryId] = resp.Credentials[0]
		}
		return content, nil
	}
	return nil, fmt.Errorf("%v is not a supported value for compatibility mode", compatibility)
}

func createDirectPostVpToken(compatibility openid4vp.CompatibilityMode, queryResponses []dcql.QueryResponse) (string, error) {
	content, err := createVpToken(compatibility, queryResponses)
	if err != nil {
		return "", err
	}
	result, err := json.Marshal(content)
	return string(result), err
}
