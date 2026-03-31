package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

// Handler is a narrow interface covering only the callbacks that the OpenID4VP client needs.
// The full irmaclient.Handler satisfies this interface via Go duck typing.
type Handler interface {
	Failure(err *irma.SessionError)
	Cancelled()
	Success(result string)
	RequestVerificationPermission(
		request *irma.DisclosureRequest,
		satisfiable bool,
		candidates [][]irmaclient.DisclosureCandidates,
		requestorInfo *irma.RequestorInfo,
		callback irmaclient.PermissionHandler,
	)
}

// ========================================================================

type Client struct {
	Configuration *eudi.Configuration

	keyBinder         sdjwtvc.KeyBinder
	sdjwtvcStorage    irmaclient.SdJwtVcStorage
	verifierValidator eudi.VerifierValidator
	logsStorage       irmaclient.LogsStorage
	currentSession    *openid4vpSession
}

// RefreshPendingPermissionRequest sends another, updated verification request if there's an active session
func (client *Client) RefreshPendingPermissionRequest() {
	if client.currentSession != nil {
		client.currentSession.requestPermission()
	}
}

func NewClient(
	eudiConf *eudi.Configuration,
	storage irmaclient.SdJwtVcStorage,
	verifierValidator eudi.VerifierValidator,
	keybinder sdjwtvc.KeyBinder,
	logsStorage irmaclient.LogsStorage,
) (*Client, error) {
	return &Client{
		Configuration:     eudiConf,
		keyBinder:         keybinder,
		sdjwtvcStorage:    storage,
		verifierValidator: verifierValidator,
		logsStorage:       logsStorage,
		currentSession:    nil,
	}, nil
}

func (client *Client) NewSession(fullUrl string, handler Handler) irmaclient.SessionDismisser {
	client.handleSessionAsync(fullUrl, handler)
	return client
}

func (client *Client) Dismiss() {
	irma.Logger.Info("openid4vp: session dismissed")
}

func handleFailure(handler Handler, message string, fmtArgs ...any) {
	irma.Logger.Errorf(message, fmtArgs...)
	handler.Failure(&irma.SessionError{
		Err: fmt.Errorf(message, fmtArgs...),
	})
}

func (client *Client) handleSessionAsync(fullUrl string, handler Handler) {
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

		request, endEntityCert, requestorSchemeData, err := client.verifierValidator.
			ParseAndVerifyAuthorizationRequest(string(authRequestJwt))

		if err != nil {
			handleFailure(handler, "openid4vp: failed to verify authorization request: %v", err)
			return
		}

		// Store the verifier logo in the cache
		filename, path, err := client.Configuration.Verifiers.CacheLogo(
			endEntityCert.SerialNumber.String(),
			&requestorSchemeData.Organization.Logo,
		)
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
		}
	}()
}

func (client *Client) handleAuthorizationRequest(
	request *openid4vp.AuthorizationRequest,
	requestorInfo *irma.RequestorInfo,
	handler Handler,
) error {
	client.currentSession = &openid4vpSession{
		request:        request,
		requestorInfo:  requestorInfo,
		handler:        handler,
		sdjwtvcStorage: client.sdjwtvcStorage,
		keyBinder:      client.keyBinder,
		logsStorage:    client.logsStorage,
	}
	defer func() {
		client.currentSession = nil
	}()
	return client.currentSession.perform()
}

// ========================================================================
// Session
// ========================================================================

type openid4vpSession struct {
	request                  *openid4vp.AuthorizationRequest
	requestorInfo            *irma.RequestorInfo
	handler                  Handler
	sdjwtvcStorage           irmaclient.SdJwtVcStorage
	keyBinder                sdjwtvc.KeyBinder
	logsStorage              irmaclient.LogsStorage
	pendingPermissionRequest *permissionRequest
}

type permissionRequest struct {
	channel chan *permissionResponse
}

type permissionResponse struct {
	choice     *irma.DisclosureChoice
	candidates *DcqlQueryCandidates
}

func (session *openid4vpSession) awaitPermission() *permissionResponse {
	return <-session.pendingPermissionRequest.channel
}

func (session *openid4vpSession) requestPermission() error {
	candidates, err := GetCandidatesForDcqlQuery(session.sdjwtvcStorage, session.request.DcqlQuery)

	if err != nil {
		return err
	}
	disclosureRequest := &irma.DisclosureRequest{}
	session.handler.RequestVerificationPermission(
		disclosureRequest,
		candidates.Satisfiable,
		candidates.Candidates,
		session.requestorInfo,
		irmaclient.PermissionHandler(func(proceed bool, choice *irma.DisclosureChoice) {
			if proceed {
				session.pendingPermissionRequest.channel <- &permissionResponse{
					choice:     choice,
					candidates: candidates,
				}
			} else {
				session.pendingPermissionRequest.channel <- nil
			}
		}),
	)
	return nil
}

func (session *openid4vpSession) perform() error {
	session.pendingPermissionRequest = &permissionRequest{
		channel: make(chan *permissionResponse, 1),
	}
	defer func() {
		session.pendingPermissionRequest = nil
	}()

	err := session.requestPermission()
	if err != nil {
		return fmt.Errorf("failed to request permission: %v", err)
	}
	permissionResponse := session.awaitPermission()

	if permissionResponse == nil {
		irma.Logger.Info("openid4vp: no attributes selected for disclosure, cancelling")
		session.handler.Cancelled()
		return nil
	}

	logMarshalled("choice:", permissionResponse)
	credentials, credLog, err := getCredentialsForChoices(
		session.sdjwtvcStorage,
		session.keyBinder,
		permissionResponse.candidates.QueryIdMap,
		permissionResponse.choice.Attributes,
		session.request.Nonce,
		session.request.ClientId,
	)

	if err != nil {
		return err
	}

	logMarshalled("credentials for choice:", credentials)

	httpClient := http.Client{}
	responseConfig := authorizationResponseConfig{
		State:          session.request.State,
		QueryResponses: credentials,
		ResponseUri:    session.request.ResponseUri,
		ResponseType:   session.request.ResponseType,
		ResponseMode:   session.request.ResponseMode,
	}

	if session.request.ResponseMode == openid4vp.ResponseMode_DirectPostJwt {
		if session.request.ClientMetadata.Jwks == nil {
			return fmt.Errorf("client metadata jwks was nil while response_mode %s was used", openid4vp.ResponseMode_DirectPostJwt)
		}
		responseConfig.EncryptionKeys = &session.request.ClientMetadata.Jwks.Set
		responseConfig.EncryptedResponseEncValuesSupported = session.request.ClientMetadata.EncryptedResponseEncValuesSupported
	}

	responseReq, err := createAuthorizationResponseHttpRequest(responseConfig)
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
	logEntry := &irmaclient.LogEntry{
		Time:       irma.Timestamp(time.Now()),
		ServerName: session.requestorInfo,
		OpenID4VP: &irmaclient.OpenID4VPDisclosureLog{
			DisclosedCredentials: credLog,
		},
	}
	err = session.logsStorage.AddLogEntry(logEntry)
	if err != nil {
		return fmt.Errorf("failed to add log entry: %v", err)
	}

	session.handler.Success("managed to complete openid4vp session")
	return nil
}

// ========================================================================
// Helpers
// ========================================================================

// will return the SdJwtVc instances to be sent as the response to the complete DcqlQuery, based on the users choices.
func getCredentialsForChoices(
	storage irmaclient.SdJwtVcStorage,
	keyBinder sdjwtvc.KeyBinder,
	queryIdMap map[irma.AttributeIdentifier]string,
	choices [][]*irma.AttributeIdentifier,
	nonce string,
	clientId string,
) ([]dcql.QueryResponse, []irmaclient.CredentialLog, error) {
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
	credentialInfos := []irmaclient.CredentialLog{}

	for queryId, attributes := range attributesByQueryId {
		sdjwt, err := storage.GetCredentialByHash(attributes[0].CredentialHash)
		if err != nil {
			return []dcql.QueryResponse{}, nil, fmt.Errorf("failed to get credential: %v", err)
		}

		err = storage.RemoveLastUsedInstanceOfCredentialByHash(attributes[0].CredentialHash)
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

		kbjwt, err := sdjwtvc.CreateKbJwt(sdjwtSelected, keyBinder, nonce, clientId)
		if err != nil {
			return []dcql.QueryResponse{}, nil, fmt.Errorf("failed to create kbjwt: %v", err)
		}

		sdjwtWithKb := sdjwtvc.AddKeyBindingJwtToSdJwtVc(sdjwtSelected, kbjwt)

		queryResponses = append(queryResponses, dcql.QueryResponse{
			QueryId:     queryId,
			Credentials: []string{string(sdjwtWithKb)},
		})
		credentialInfos = append(credentialInfos, createSdJwtCredentialLog(sdjwt.Metadata, attributes))
	}
	return queryResponses, credentialInfos, nil
}

func logMarshalled(message string, value any) {
	jsonBytes, err := json.MarshalIndent(value, "", "   ")
	if err != nil {
		irma.Logger.Errorf("%s: failed to marshal: %v", message, err)
	} else {
		irma.Logger.Infof("\n%s\n%s\n\n", message, string(jsonBytes))
	}
}

func createSdJwtCredentialLog(info irmaclient.SdJwtVcBatchMetadata, disclosures []*irma.AttributeIdentifier) irmaclient.CredentialLog {
	result := irmaclient.CredentialLog{
		CredentialType: info.CredentialType,
		Formats:        []irmaclient.CredentialFormat{irmaclient.Format_SdJwtVc},
		Attributes:     map[string]string{},
	}

	for _, attr := range disclosures {
		result.Attributes[attr.Type.Name()] = info.Attributes[attr.Type.Name()].(string)
	}

	return result
}
