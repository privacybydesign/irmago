package openid4vp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// Handler is the callback interface for the OpenID4VP client session lifecycle.
type Handler interface {
	Failure(err *clientmodels.SessionError)
	Cancelled()
	Success(result string, credentialLogs []clientmodels.LogCredential)
	RequestVerificationPermission(
		disclosurePlan *clientmodels.DisclosurePlan,
		requestor *clientmodels.TrustedParty,
		hashToQueryId map[string]string,
		callback PermissionHandler,
	)
}

// PermissionHandler is the callback the UI invokes after the user grants or denies permission.
type PermissionHandler func(proceed bool, selections []dcql.DisclosureSelection)

// SessionDismisser allows dismissing the current session.
type SessionDismisser interface {
	Dismiss()
}

// ========================================================================

// Client drives OpenID4VP disclosure sessions.
type Client struct {
	Configuration     *eudi.Configuration
	dcqlHandler       *dcql.DcqlHandler
	verifierValidator VerifierValidator
	currentSession    *openid4vpSession
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
	handlers []dcql.DcqlCredentialQueryHandler,
	verifierValidator VerifierValidator,
) (*Client, error) {
	return &Client{
		Configuration:     eudiConf,
		dcqlHandler:       dcql.NewDcqlHandler(handlers),
		verifierValidator: verifierValidator,
		currentSession:    nil,
	}, nil
}

// NewSession starts a new OpenID4VP session from the given URL and returns a SessionDismisser.
func (client *Client) NewSession(fullUrl string, handler Handler) SessionDismisser {
	client.handleSessionAsync(fullUrl, handler)
	return client
}

// Dismiss dismisses the current session.
func (client *Client) Dismiss() {
	eudi.Logger.Info("openid4vp: session dismissed")
}

func handleFailure(handler Handler, message string, fmtArgs ...any) {
	eudi.Logger.Errorf(message, fmtArgs...)
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

		eudi.Logger.Infof("starting openid4vp session: %v", requestUri)
		response, err := http.Get(requestUri)
		if err != nil {
			handleFailure(handler, "openid4vp: failed to get authorization request: %v", err)
			return
		}

		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			handleFailure(handler, "openid4vp: authorization request returned HTTP %d", response.StatusCode)
			return
		}

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

		if err := validateNonce(request.Nonce); err != nil {
			handleFailure(handler, "openid4vp: invalid authorization request: %v", err)
			return
		}

		// Store the verifier logo in the cache (only when a certificate is available, e.g. X.509 trust model)
		if endEntityCert != nil {
			_, err = client.Configuration.Storage.FileSystem().Verifiers().LogoManager().SaveLogo(
				endEntityCert.SerialNumber.String(),
				requestorSchemeData.Organization.Logo.Data,
			)
			if err != nil {
				handleFailure(handler, "openid4vp: failed to store verifier logo: %v", err)
				return
			}
		}

		requestor := &clientmodels.TrustedParty{
			Name:     clientmodels.TranslatedString(requestorSchemeData.Organization.LegalName),
			Verified: endEntityCert != nil,
		}
		if endEntityCert != nil {
			requestor.Id = endEntityCert.SerialNumber.String()
		}

		if len(requestorSchemeData.Organization.Logo.Data) > 0 {
			requestor.Image = &clientmodels.Image{
				Base64: base64.StdEncoding.EncodeToString(requestorSchemeData.Organization.Logo.Data),
			}
		}

		eudi.Logger.Infof("auth request: %#v", request)
		err = client.handleAuthorizationRequest(request, requestor, handler)

		if err != nil {
			handleFailure(handler, "openid4vp: failed to handle authorization request: %v", err)
		}
	}()
}

func (client *Client) handleAuthorizationRequest(
	request *AuthorizationRequest,
	requestor *clientmodels.TrustedParty,
	handler Handler,
) error {
	client.currentSession = &openid4vpSession{
		request:     request,
		requestor:   requestor,
		handler:     handler,
		dcqlHandler: client.dcqlHandler,
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
	request                  *AuthorizationRequest
	requestor                *clientmodels.TrustedParty
	handler                  Handler
	dcqlHandler              *dcql.DcqlHandler
	pendingPermissionRequest *permissionRequest
	lastPlan                 *clientmodels.DisclosurePlan
	lastResult               *dcql.DcqlResult
	// preExistingHashes tracks owned credential hashes at session start,
	// used to detect newly issued credentials for WrongCredentialIssued.
	preExistingHashes map[string]struct{}
}

type permissionRequest struct {
	channel chan *permissionResponse
}

type permissionResponse struct {
	selections []dcql.DisclosureSelection
}

func (session *openid4vpSession) awaitPermission() *permissionResponse {
	return <-session.pendingPermissionRequest.channel
}

func (session *openid4vpSession) requestPermission() error {
	plan, err := session.buildDisclosurePlan()
	if err != nil {
		return err
	}
	session.lastPlan = plan

	session.handler.RequestVerificationPermission(
		plan,
		session.requestor,
		session.lastResult.HashToQueryId,
		func(proceed bool, selections []dcql.DisclosureSelection) {
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

// buildDisclosurePlan builds a DisclosurePlan by delegating to the DcqlHandler.
func (session *openid4vpSession) buildDisclosurePlan() (*clientmodels.DisclosurePlan, error) {
	result, err := session.dcqlHandler.FindCandidates(session.request.DcqlQuery)
	if err != nil {
		return nil, err
	}
	session.lastResult = result

	// Snapshot pre-existing hashes on first call
	if session.preExistingHashes == nil {
		session.preExistingHashes = dcql.CollectOwnedHashes(result.QueryResults)
	}

	return session.dcqlHandler.BuildDisclosurePlan(
		session.request.DcqlQuery, result, session.lastPlan, session.preExistingHashes,
	)
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
		eudi.Logger.Info("openid4vp: no attributes selected for disclosure, cancelling")
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

	if session.request.ResponseMode == ResponseMode_DirectPostJwt {
		if session.request.ClientMetadata.Jwks == nil {
			return fmt.Errorf("client metadata jwks was nil while response_mode %s was used", ResponseMode_DirectPostJwt)
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

// prepareDisclosures delegates to the DcqlHandler to prepare credentials for the VP token.
func (session *openid4vpSession) prepareDisclosures(
	selections []dcql.DisclosureSelection,
) ([]dcql.QueryResponse, []clientmodels.LogCredential, error) {
	prepared, err := session.dcqlHandler.PrepareDisclosure(
		session.request.DcqlQuery, selections, session.request.Nonce, session.request.ClientId,
	)
	if err != nil {
		return nil, nil, err
	}
	return prepared.QueryResponses, prepared.CredentialLogs, nil
}

// ========================================================================
// Helpers
// ========================================================================

func logMarshalled(message string, value any) {
	jsonBytes, err := json.MarshalIndent(value, "", "   ")
	if err != nil {
		eudi.Logger.Errorf("%s: failed to marshal: %v", message, err)
	} else {
		eudi.Logger.Infof("\n%s\n%s\n", message, string(jsonBytes))
	}
}
