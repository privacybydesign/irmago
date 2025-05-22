package irmaclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/testdata"
)

type sdjwtvcStorageEntry struct {
	// A list of strings containing sdjwtvc's (with all disclosures & without kbjwt)
	rawRedentials []sdjwtvc.SdJwtVc
	info          irma.CredentialInfo
}

type SdJwtVcStorage struct {
	entries []sdjwtvcStorageEntry
}

func (s *SdJwtVcStorage) GetCredentialByHash(hash string) (*sdjwtvcStorageEntry, error) {
	for _, entry := range s.entries {
		if entry.info.Hash == hash {
			return &entry, nil
		}
	}
	return nil, fmt.Errorf("no entry found for hash '%s'", hash)
}

func createStorageEntry(vct string, issuerUrl string, claims map[string]any) (sdjwtvcStorageEntry, error) {
	contents, err := sdjwtvc.MultipleNewDisclosureContents(claims)
	if err != nil {
		return sdjwtvcStorageEntry{}, err
	}

	signer := sdjwtvc.NewEcdsaJwtCreatorWithIssuerTestkey()
	sdjwt, err := sdjwtvc.NewSdJwtVcBuilder().
		WithDisclosures(contents).
		WithHolderKey(testdata.ParseHolderPubJwk()).
		WithHashingAlgorithm(sdjwtvc.HashAlg_Sha256).
		WithVerifiableCredentialType(vct).
		WithIssuerUrl(issuerUrl).
		Build(signer)

	if err != nil {
		return sdjwtvcStorageEntry{}, err
	}

	infoAttrs := map[irma.AttributeTypeIdentifier]irma.TranslatedString{}
	for key, value := range claims {
		attrKey := irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", vct, key))
		infoAttrs[attrKey] = irma.TranslatedString{
			"":   value.(string),
			"en": value.(string),
			"nl": value.(string),
		}
	}

	hashContent, err := json.Marshal(claims)
	if err != nil {
		return sdjwtvcStorageEntry{}, err
	}

	hash, err := sdjwtvc.CreateHash(sdjwtvc.HashAlg_Sha256, string(hashContent))
	if err != nil {
		return sdjwtvcStorageEntry{}, err
	}

	ids := strings.Split(vct, ".")
	entry := sdjwtvcStorageEntry{
		rawRedentials: []sdjwtvc.SdJwtVc{
			sdjwt,
		},
		info: irma.CredentialInfo{
			ID:              ids[2],
			IssuerID:        ids[1],
			SchemeManagerID: ids[0],
			SignedOn: irma.Timestamp(
				time.Unix(1747393254, 0),
			),
			Expires: irma.Timestamp(
				time.Unix(1847393254, 0),
			),
			Attributes:          infoAttrs,
			Hash:                hash,
			Revoked:             false,
			RevocationSupported: false,
			CredentialFormat:    "dc+sd-jwt",
		},
	}
	return entry, nil
}

func NewSdJwtVcStorage() (*SdJwtVcStorage, error) {
	mobilephoneEntry, err := createStorageEntry("pbdf.pbdf.mobilenumber", "https://openid4vc.staging.yivi.app",
		map[string]any{
			"mobilenumber": "+31612345678",
		},
	)

	if err != nil {
		return nil, err
	}
	emailEntry, err := createStorageEntry("pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})

	if err != nil {
		return nil, err
	}

	emailEntry2, err := createStorageEntry("pbdf.pbdf.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email":  "yivi@gmail.com",
		"domain": "gmail.com",
	})

	if err != nil {
		return nil, err
	}

	return &SdJwtVcStorage{
		entries: []sdjwtvcStorageEntry{
			mobilephoneEntry,
			emailEntry,
			emailEntry2,
		},
	}, nil
}

func (s *SdJwtVcStorage) GetCredentialInfoList() irma.CredentialInfoList {
	result := irma.CredentialInfoList{}

	for _, entry := range s.entries {
		result = append(result, &entry.info)
	}

	return result
}

// ========================================================================

type OpenID4VPClient struct {
	KeyBinder     sdjwtvc.KbJwtCreator
	Storage       *SdJwtVcStorage
	Compatibility openid4vp.CompatibilityMode
}

func NewOpenID4VPClient(storage *SdJwtVcStorage, keybinder sdjwtvc.KbJwtCreator) (*OpenID4VPClient, error) {
	return &OpenID4VPClient{
		KeyBinder:     keybinder,
		Compatibility: openid4vp.Compatibility_Draft24,
		Storage:       storage,
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
		components, err := url.Parse(fullUrl)

		if err != nil {
			handlerFailure(handler, "openid4vp: failed to parse request: %v", err)
			return
		}

		uri := components.Query().Get("request_uri")
		if uri == "" {
			handlerFailure(handler, "openid4vp: request missing required request_uri")
			return
		}

		irma.Logger.Infof("starting openid4vp session: %v\n", uri)
		response, err := http.Get(uri)
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

		request, err := parseAuthorizationRequestJwt(string(jawd))
		if err != nil {
			handlerFailure(handler, "openid4vp: failed to read authorization request jwt: %v", err)
			return
		}
		irma.Logger.Infof("auth request: %#v\n", request)
		err = client.handleAuthorizationRequest(request, handler)

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

func (client *OpenID4VPClient) handleAuthorizationRequest(request *openid4vp.AuthorizationRequest, handler Handler) error {
	candidates, err := client.getCandidates(request.DcqlQuery)

	if err != nil {
		return err
	}

	choice := client.requestAndAwaitPermission(candidates, handler)
	if choice == nil {
		irma.Logger.Info("openid4vp: no attributes selected for disclosure, cancelling")
		handler.Cancelled()
		return nil
	}

	logMarshalled("choice:", choice)
	credentials, err := client.getCredentialsForChoices(candidates.queryIdMap, choice.Attributes)

	if err != nil {
		return err
	}

	logMarshalled("credentials for choice:", credentials)

	httpClient := http.Client{}
	authResponse := AuthorizationResponseConfig{
		CompatibilityMode: client.Compatibility,
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
		sdjwt, err := client.Storage.GetCredentialByHash(attributes[0].CredentialHash)
		if err != nil {
			return []dcql.QueryResponse{}, fmt.Errorf("failed to get credential: %v", err)
		}

		disclosureNames := []string{}
		for _, attr := range attributes {
			disclosureNames = append(disclosureNames, attr.Type.Name())
		}

		sdjwtSelected, err := sdjwtvc.SelectDisclosures(sdjwt.rawRedentials[0], disclosureNames)
		if err != nil {
			return []dcql.QueryResponse{}, fmt.Errorf("failed to select disclosures: %v", err)
		}

		kbjwt, err := sdjwtvc.CreateKbJwt(sdjwtSelected, client.KeyBinder)
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

// assume for now that there are never two choices for the same set of attributes
func (client *OpenID4VPClient) getCandidates(query dcql.DcqlQuery) (*queryResult, error) {
	result := queryResult{
		candidates:  [][]DisclosureCandidates{},
		queryIdMap:  map[irma.AttributeIdentifier]string{},
		satisfiable: true,
	}

	for _, query := range query.Credentials {
		singleQueryResult, err := client.findCandidatesForCredentialQuery(query)
		if err != nil {
			return nil, err
		}
		for _, candidatesList := range singleQueryResult.candidates {
			for _, attributes := range candidatesList {
				result.queryIdMap[*attributes.AttributeIdentifier] = singleQueryResult.queryId
			}
		}
		result.candidates = append(result.candidates, singleQueryResult.candidates)
		if !singleQueryResult.satisfiable {
			result.satisfiable = false
		}
	}
	return &result, nil
}

type queryResult struct {
	candidates  [][]DisclosureCandidates
	queryIdMap  map[irma.AttributeIdentifier]string
	satisfiable bool
}

type credentialQueryResult struct {
	// the available candidates for this query
	candidates  []DisclosureCandidates
	queryId     string
	satisfiable bool
}

// A credential query is searching only for claims within a single credential.
// If attributes from multiple credentials are required at the same time, they'll
// have separate CredentialQueries for each credential.
func (client *OpenID4VPClient) findCandidatesForCredentialQuery(query dcql.CredentialQuery) (*credentialQueryResult, error) {
	if query.Format != credentials.Format_SdJwtVc && query.Format != credentials.Format_SdJwtVc_Legacy {
		return nil, fmt.Errorf("format not supported: %v", query.Format)
	}

	if len(query.Meta.VctValues) != 1 {
		return nil, fmt.Errorf("the vct_values array must exactly contain one value: %v", query.Meta.VctValues)
	}

	// we're assuming the vct field in the sdjwtvc to be the full credential path, e.g. `pbdf.pbdf.email`
	credentialId := query.Meta.VctValues[0]

	credCandidates := []DisclosureCandidates{}

	entries := client.findInStorage(credentialId)

	// when no entries are found, the query is not satisfiable
	if len(entries) == 0 {
		toAdd := DisclosureCandidates{}
		for _, claim := range query.Claims {
			candidate := DisclosureCandidate{
				AttributeIdentifier: &irma.AttributeIdentifier{
					Type: irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", credentialId, claim.Path[0])),
				},
			}
			toAdd = append(toAdd, &candidate)
		}
		credCandidates = append(credCandidates, toAdd)
	} else {
		for _, entry := range entries {
			toAdd := DisclosureCandidates{}
			for _, claim := range query.Claims {
				candidate := DisclosureCandidate{
					AttributeIdentifier: &irma.AttributeIdentifier{
						Type:           irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", credentialId, claim.Path[0])),
						CredentialHash: entry.info.Hash,
					},
				}
				toAdd = append(toAdd, &candidate)
			}
			credCandidates = append(credCandidates, toAdd)
		}
	}

	return &credentialQueryResult{
		candidates:  credCandidates,
		queryId:     query.Id,
		satisfiable: len(entries) != 0,
	}, nil
}

func (client *OpenID4VPClient) findInStorage(credentialId string) []*sdjwtvcStorageEntry {
	result := []*sdjwtvcStorageEntry{}
	for _, entry := range client.Storage.entries {
		credId := fmt.Sprintf("%s.%s.%s", entry.info.SchemeManagerID, entry.info.IssuerID, entry.info.ID)

		// we have an instance of the requested credential type
		if credentialId == credId {
			result = append(result, &entry)
		}
	}
	return result
}

func (client *OpenID4VPClient) requestAndAwaitPermission(queryResult *queryResult, handler Handler) *irma.DisclosureChoice {
	disclosureRequest := &irma.DisclosureRequest{}

	requestorInfo := irma.RequestorInfo{
		ID:     irma.RequestorIdentifier{},
		Scheme: irma.RequestorSchemeIdentifier{},
		Name: map[string]string{
			"nl": "OpenID4VP Demo Verifier",
			"en": "OpenID4VP Demo Verifier",
		},
		Industry:   &irma.TranslatedString{},
		Hostnames:  []string{},
		Logo:       new(string),
		LogoPath:   new(string),
		ValidUntil: &irma.Timestamp{},
		Unverified: false,
		Languages:  []string{},
		Wizards:    map[irma.IssueWizardIdentifier]*irma.IssueWizard{},
	}

	choiceChan := make(chan *irma.DisclosureChoice, 1)

	handler.RequestVerificationPermission(
		disclosureRequest,
		queryResult.satisfiable,
		queryResult.candidates,
		&requestorInfo,
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

func parseAuthorizationRequestJwt(authReqJwt string) (*openid4vp.AuthorizationRequest, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(string(authReqJwt), &openid4vp.AuthorizationRequest{})

	typ, ok := token.Header["typ"]
	if !ok {
		return nil, errors.New("auth request JWT needs to contain 'typ' in header, but doesn't")
	}
	if typ != openid4vp.AuthRequestJwtTyp {
		return nil, fmt.Errorf("auth request JWT typ in header should be %v but was %v", openid4vp.AuthRequestJwtTyp, typ)
	}

	if err != nil {
		return nil, err
	}

	claims := token.Claims.(*openid4vp.AuthorizationRequest)

	return claims, nil
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
