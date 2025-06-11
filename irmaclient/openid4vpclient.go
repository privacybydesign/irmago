package irmaclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// ========================================================================

type OpenID4VPClient struct {
	keyBinder         sdjwtvc.KbJwtCreator
	storage           SdJwtVcStorage
	verifierValidator VerifierValidator
	compatibility     openid4vp.CompatibilityMode
}

func NewOpenID4VPClient(
	storage SdJwtVcStorage,
	verifierValidator VerifierValidator,
	keybinder sdjwtvc.KbJwtCreator,
) (*OpenID4VPClient, error) {
	return &OpenID4VPClient{
		keyBinder:         keybinder,
		compatibility:     openid4vp.Compatibility_Draft24,
		storage:           storage,
		verifierValidator: verifierValidator,
	}, nil
}

func (client *OpenID4VPClient) NewSession(fullUrl string, handler Handler) SessionDismisser {
	client.handleSessionAsync(fullUrl, handler)
	return client
}

func (client *OpenID4VPClient) Dismiss() {
	irma.Logger.Info("openid4vp: session dismissed")
}

func handlerFailure(handler Handler, message string, fmtArgs ...any) {
	irma.Logger.Errorf(message, fmtArgs...)
	handler.Failure(&irma.SessionError{
		Err: fmt.Errorf(message, fmtArgs...),
	})
}

func (client *OpenID4VPClient) handleSessionAsync(fullUrl string, handler Handler) {
	go func() {
		parsedUrl, err := url.Parse(fullUrl)

		if err != nil {
			handlerFailure(handler, "openid4vp: failed to parse request: %v", err)
			return
		}

		requestUri := parsedUrl.Query().Get("request_uri")
		if requestUri == "" {
			handlerFailure(handler, "openid4vp: request missing required request_uri")
			return
		}

		irma.Logger.Infof("starting openid4vp session: %v\n", requestUri)
		response, err := http.Get(requestUri)
		if err != nil {
			handlerFailure(handler, "openid4vp: failed to get authorization request: %v", err)
			return
		}

		defer response.Body.Close()

		jawd, err := io.ReadAll(response.Body)

		if err != nil {
			handlerFailure(handler, "openid4vp: failed to read authorization request body: %v", err)
			return
		}

		request, requestorInfo, err := client.verifierValidator.VerifyAuthorizationRequest(string(jawd))
		if err != nil {
			handlerFailure(handler, "openid4vp: failed to read authorization request jwt: %v", err)
			return
		}
		irma.Logger.Infof("auth request: %#v\n", request)
		err = client.handleAuthorizationRequest(request, requestorInfo, handler)

		if err != nil {
			handlerFailure(handler, "openid4vp: failed to handle authorization request: %v", err)
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
	credentials, err := client.getCredentialsForChoices(candidates.QueryIdMap, choice.Attributes, request.Nonce, request.ClientId)

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
	handler.Success("managed to complete openid4vp session")
	return nil
}

// will return the SdJwtVc instances to be sent as the response to the complete DcqlQuery, based on the users choices.
func (client *OpenID4VPClient) getCredentialsForChoices(
	queryIdMap map[irma.AttributeIdentifier]string,
	choices [][]*irma.AttributeIdentifier,
	nonce string,
	clientId string,
) ([]dcql.QueryResponse, error) {
	// map of attribute identifiers by the dcql query id
	attributesByQueryId := map[string][]*irma.AttributeIdentifier{}

	for _, credential := range choices {
		// let's for now assume that all selected attributes for a given credential type all come from
		// the same credential instance
		for _, attribute := range credential {
			queryId, ok := queryIdMap[*attribute]

			if !ok {
				return []dcql.QueryResponse{}, fmt.Errorf("query id map doesn't contain '%v'", *attribute)
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
	for queryId, attributes := range attributesByQueryId {
		sdjwt, err := client.storage.GetCredentialByHash(attributes[0].CredentialHash)
		if err != nil {
			return []dcql.QueryResponse{}, fmt.Errorf("failed to get credential: %v", err)
		}

		disclosureNames := []string{}
		for _, attr := range attributes {
			disclosureNames = append(disclosureNames, attr.Type.Name())
		}

		sdjwtSelected, err := sdjwtvc.SelectDisclosures(sdjwt.SdJwtVc, disclosureNames)
		if err != nil {
			return []dcql.QueryResponse{}, fmt.Errorf("failed to select disclosures: %v", err)
		}

		kbjwt, err := sdjwtvc.CreateKbJwt(sdjwtSelected, client.keyBinder, nonce, clientId)
		if err != nil {
			return []dcql.QueryResponse{}, fmt.Errorf("failed to create kbjwt: %v", err)
		}

		sdjwtWithKb := sdjwtvc.AddKeyBindingJwtToSdJwtVc(sdjwtSelected, kbjwt)

		queryResponses = append(queryResponses, dcql.QueryResponse{
			QueryId:     queryId,
			Credentials: []string{string(sdjwtWithKb)},
		})
	}
	return queryResponses, nil
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

func constructEmptyDisConForQuery(query dcql.CredentialQuery) ([]DisclosureCandidates, error) {
	con := DisclosureCandidates{}
	for _, claim := range query.Claims {
		credId := query.Meta.VctValues[0]
		attr := claim.Path[0]
		con = append(con, &DisclosureCandidate{
			AttributeIdentifier: &irma.AttributeIdentifier{
				Type: irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", credId, attr)),
			},
		})
	}
	return []DisclosureCandidates{con}, nil
}

func constructCandidatesFromCredentialQueries(
	queries []dcql.CredentialQuery,
	allAvailableCredentials map[string]SingleCredentialQueryCandidates,
) (*DcqlQueryCandidates, error) {
	conDisCon := [][]DisclosureCandidates{}
	satisfiable := true
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
				credId := fmt.Sprintf("%s.%s.%s", candidate.Info.SchemeManagerID, candidate.Info.IssuerID, candidate.Info.ID)
				con := DisclosureCandidates{}

				for _, attribute := range candidates.RequestedAttributes {
					con = append(con, &DisclosureCandidate{
						AttributeIdentifier: &irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", credId, attribute)),
							CredentialHash: candidate.Info.Hash,
						},
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
	}, nil
}

func constructCandidatesForCredentialSets(
	allAvailableCredentials map[string]SingleCredentialQueryCandidates,
	credentialSets []dcql.CredentialSetQuery,
) (*DcqlQueryCandidates, error) {
	conDisCon := [][]DisclosureCandidates{}
	conDisConSatisfied := true

	// each purpose (con)
	for _, credentialSet := range credentialSets {
		disCon := []DisclosureCandidates{}
		disConSatisfied := false

		// each option for this purpose (dis)
		for _, option := range credentialSet.Options {
			con := DisclosureCandidates{}
			conSatisfied := true

			// each requirement for this option (con)
			for _, requiredCredentialQueryId := range option {
				queryResult, ok := allAvailableCredentials[requiredCredentialQueryId]

				if !ok || len(queryResult.SatisfyingCredentials) == 0 {
					conSatisfied = false
				}

				// add an attribute instance for each of the requested attributes for each of the satisying credentials
				for _, credential := range queryResult.SatisfyingCredentials {
					credentialId := fmt.Sprintf("%s.%s.%s", credential.Info.SchemeManagerID, credential.Info.IssuerID, credential.Info.ID)
					for _, attribute := range queryResult.RequestedAttributes {
						attributeId := irma.AttributeIdentifier{
							Type:           irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", credentialId, attribute)),
							CredentialHash: credential.Info.Hash,
						}
						con = append(con, &DisclosureCandidate{AttributeIdentifier: &attributeId})
					}
				}
			}
			disCon = append(disCon, con)
			if conSatisfied {
				disConSatisfied = true
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
	}, nil
}

func attributesSatisfyClaims(
	attributes map[irma.AttributeTypeIdentifier]irma.TranslatedString,
	credentialId string,
	claims []dcql.Claim,
) bool {
	attrs := []irma.AttributeTypeIdentifier{}

	for _, c := range claims {
		attrs = append(attrs, irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", credentialId, c.Path[0])))
	}

	for _, a := range attrs {
		_, ok := attributes[a]
		if !ok {
			return false
		}
	}

	return true
}

// Only returns the credential instances that have ALL attributes required by the list of claims
func filterCredentialsWithClaims(entries []SdJwtVcAndInfo, claims []dcql.Claim) ([]SdJwtVcAndInfo, error) {
	result := []SdJwtVcAndInfo{}
	for _, e := range entries {
		id := fmt.Sprintf("%s.%s.%s", e.Info.SchemeManagerID, e.Info.IssuerID, e.Info.ID)
		if attributesSatisfyClaims(e.Info.Attributes, id, claims) {
			result = append(result, e)
		}
	}
	return result, nil
}

type credQueryResult struct {
	// Match a single credential query object in the dcql query.
	credentialQueryId string
	// All candidates that satisfy the requirements in the dcql.CredentialQuery object.
	candidates []SdJwtVcAndInfo
}

func findAllCandidatesForCredQuery(storage SdJwtVcStorage, query dcql.CredentialQuery) ([]SdJwtVcAndInfo, error) {
	return filterCredentialsWithClaims(storage.GetCredentialsForId(query.Meta.VctValues[0]), query.Claims)
}

type SingleCredentialQueryCandidates struct {
	// The id for the dcql.CredentialQuery
	CredentialQueryId string
	// The names of the attributes requested in this credential query
	RequestedAttributes []string
	// A list of credential info and the instance that satisfy the requirements described by the query
	SatisfyingCredentials []SdJwtVcAndInfo
}

func findAllCandidatesForAllCredentialQueries(
	storage SdJwtVcStorage,
	queries []dcql.CredentialQuery,
) (map[string]SingleCredentialQueryCandidates, error) {
	result := map[string]SingleCredentialQueryCandidates{}

	for _, query := range queries {
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
