package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/irma"
)

// Handler is the callback interface for the OpenID4VP client session lifecycle.
type Handler interface {
	Failure(err *clientmodels.SessionError)
	Cancelled()
	Success(result string, credentialLogs []clientmodels.LogCredential)
	RequestVerificationPermission(
		disclosurePlan *clientmodels.DisclosurePlan,
		requestor *clientmodels.TrustedParty,
		callback PermissionHandler,
	)
}

// PermissionHandler is the callback the UI invokes after the user grants or denies permission.
type PermissionHandler func(proceed bool, selections []clientmodels.DisclosureSelection)

// SessionDismisser allows dismissing the current session.
type SessionDismisser interface {
	Dismiss()
}

// ========================================================================

// Client drives OpenID4VP disclosure sessions.
type Client struct {
	Configuration           *eudi.Configuration
	credentialQueryHandlers []clientmodels.DcqlCredentialQueryHandler
	verifierValidator       eudi.VerifierValidator
	currentSession          *openid4vpSession
}

// RefreshPendingPermissionRequest sends another, updated verification request if there's an active session.
func (client *Client) RefreshPendingPermissionRequest() {
	if client.currentSession != nil {
		client.currentSession.requestPermission()
	}
}

// NewClient creates a new OpenID4VP client.
func NewClient(
	eudiConf *eudi.Configuration,
	handlers []clientmodels.DcqlCredentialQueryHandler,
	verifierValidator eudi.VerifierValidator,
) (*Client, error) {
	return &Client{
		Configuration:           eudiConf,
		credentialQueryHandlers: handlers,
		verifierValidator:       verifierValidator,
		currentSession:          nil,
	}, nil
}

// NewSession starts a new OpenID4VP session from the given URL and returns a SessionDismisser.
func (client *Client) NewSession(fullUrl string, handler Handler) SessionDismisser {
	client.handleSessionAsync(fullUrl, handler)
	return client
}

// Dismiss dismisses the current session.
func (client *Client) Dismiss() {
	irma.Logger.Info("openid4vp: session dismissed")
}

func handleFailure(handler Handler, message string, fmtArgs ...any) {
	irma.Logger.Errorf(message, fmtArgs...)
	handler.Failure(&clientmodels.SessionError{
		WrappedError: fmt.Sprintf(message, fmtArgs...),
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
		_, logoPath, err := client.Configuration.Verifiers.CacheLogo(
			endEntityCert.SerialNumber.String(),
			&requestorSchemeData.Organization.Logo,
		)
		if err != nil {
			handleFailure(handler, "openid4vp: failed to store verifier logo: %v", err)
			return
		}

		requestor := &clientmodels.TrustedParty{
			Name:      clientmodels.TranslatedString(requestorSchemeData.Organization.LegalName),
			ImagePath: &logoPath,
			Verified:  true,
		}

		irma.Logger.Infof("auth request: %#v\n", request)
		err = client.handleAuthorizationRequest(request, requestor, handler)

		if err != nil {
			handleFailure(handler, "openid4vp: failed to handle authorization request: %v", err)
		}
	}()
}

func (client *Client) handleAuthorizationRequest(
	request *openid4vp.AuthorizationRequest,
	requestor *clientmodels.TrustedParty,
	handler Handler,
) error {
	client.currentSession = &openid4vpSession{
		request:                 request,
		requestor:               requestor,
		handler:                 handler,
		credentialQueryHandlers: client.credentialQueryHandlers,
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
	requestor                *clientmodels.TrustedParty
	handler                  Handler
	credentialQueryHandlers  []clientmodels.DcqlCredentialQueryHandler
	pendingPermissionRequest *permissionRequest
}

type permissionRequest struct {
	channel chan *permissionResponse
}

type permissionResponse struct {
	selections []clientmodels.DisclosureSelection
}

func (session *openid4vpSession) awaitPermission() *permissionResponse {
	return <-session.pendingPermissionRequest.channel
}

// findHandlerForFormat returns the DcqlCredentialQueryHandler that supports the given format.
func (session *openid4vpSession) findHandlerForFormat(format string) (clientmodels.DcqlCredentialQueryHandler, error) {
	for _, h := range session.credentialQueryHandlers {
		if h.Format() == format {
			return h, nil
		}
	}
	return nil, fmt.Errorf("no credential query handler for format %q", format)
}

func (session *openid4vpSession) requestPermission() error {
	plan, err := session.buildDisclosurePlan()
	if err != nil {
		return err
	}

	session.handler.RequestVerificationPermission(
		plan,
		session.requestor,
		func(proceed bool, selections []clientmodels.DisclosureSelection) {
			if proceed {
				session.pendingPermissionRequest.channel <- &permissionResponse{
					selections: selections,
				}
			} else {
				session.pendingPermissionRequest.channel <- nil
			}
		},
	)
	return nil
}

// buildDisclosurePlan builds a DisclosurePlan by querying each handler for candidates.
func (session *openid4vpSession) buildDisclosurePlan() (*clientmodels.DisclosurePlan, error) {
	// Build per-query results
	queryResults := map[string]*clientmodels.CredentialQueryResult{}
	queryFormats := map[string]string{} // queryId -> format

	for _, credQuery := range session.request.DcqlQuery.Credentials {
		handler, err := session.findHandlerForFormat(credQuery.Format)
		if err != nil {
			return nil, fmt.Errorf("credential query '%s': %w", credQuery.Id, err)
		}

		result, err := handler.FindCandidates(credQuery)
		if err != nil {
			return nil, fmt.Errorf("credential query '%s': failed to find candidates: %w", credQuery.Id, err)
		}

		queryResults[credQuery.Id] = result
		queryFormats[credQuery.Id] = credQuery.Format
	}

	// Build the disclosure plan
	if session.request.DcqlQuery.CredentialSets != nil {
		return buildPlanFromCredentialSets(queryResults, session.request.DcqlQuery.CredentialSets)
	}

	return buildPlanFromCredentialQueries(session.request.DcqlQuery.Credentials, queryResults)
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
	permResp := session.awaitPermission()

	if permResp == nil {
		irma.Logger.Info("openid4vp: no attributes selected for disclosure, cancelling")
		session.handler.Cancelled()
		return nil
	}

	logMarshalled("selections:", permResp.selections)

	// Group selections by format
	queryResponses, credLogs, err := session.prepareDisclosures(permResp.selections)
	if err != nil {
		return err
	}

	logMarshalled("credentials for choice:", queryResponses)

	httpClient := http.Client{}
	responseConfig := authorizationResponseConfig{
		State:          session.request.State,
		QueryResponses: queryResponses,
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

	session.handler.Success("managed to complete openid4vp session", credLogs)
	return nil
}

// prepareDisclosures groups selections by credential format and calls each handler's
// PrepareDisclosure method, returning aggregated query responses and log data.
func (session *openid4vpSession) prepareDisclosures(
	selections []clientmodels.DisclosureSelection,
) ([]dcql.QueryResponse, []clientmodels.LogCredential, error) {
	// Build a map from queryId -> format using the request's credential queries
	queryFormat := map[string]string{}
	for _, cq := range session.request.DcqlQuery.Credentials {
		queryFormat[cq.Id] = cq.Format
	}

	// Group selections by format
	selectionsByFormat := map[string][]clientmodels.DisclosureSelection{}
	for _, sel := range selections {
		format, ok := queryFormat[sel.QueryId]
		if !ok {
			return nil, nil, fmt.Errorf("unknown query id %q in selection", sel.QueryId)
		}
		selectionsByFormat[format] = append(selectionsByFormat[format], sel)
	}

	var allQueryResponses []dcql.QueryResponse
	var allCredLogs []clientmodels.LogCredential

	for format, sels := range selectionsByFormat {
		handler, err := session.findHandlerForFormat(format)
		if err != nil {
			return nil, nil, err
		}

		prepared, err := handler.PrepareDisclosure(sels, session.request.Nonce, session.request.ClientId)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to prepare disclosure for format %q: %w", format, err)
		}

		allQueryResponses = append(allQueryResponses, prepared.QueryResponses...)
		allCredLogs = append(allCredLogs, prepared.CredentialLogs...)
	}

	return allQueryResponses, allCredLogs, nil
}

// ========================================================================
// Helpers
// ========================================================================

func logMarshalled(message string, value any) {
	jsonBytes, err := json.MarshalIndent(value, "", "   ")
	if err != nil {
		irma.Logger.Errorf("%s: failed to marshal: %v", message, err)
	} else {
		irma.Logger.Infof("\n%s\n%s\n\n", message, string(jsonBytes))
	}
}
