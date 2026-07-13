package wallet

import (
	"fmt"
	"net/url"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
)

// AuthCodeResolver drives the OpenID4VCI authorization-code flow. Given the
// fully-built authorization URL the user must visit, it returns the redirect
// (callback) URL the authorization server ultimately sends back to the wallet's
// redirect_uri — the wallet parses the code and state from it. A CLI typically
// prints authURL and reads the pasted callback URL from stdin. Returning an
// error aborts the flow.
//
// It is only consulted for authorization-code offers; pre-authorized-code offers
// never call it.
type AuthCodeResolver func(authURL string) (callbackURL string, err error)

// Receive runs an OpenID4VCI issuance session to completion and returns the
// credentials that were stored. credentialOfferURI is the offer (or a URL that
// resolves to one, e.g. an openid-credential-offer:// deep link). redirectURI
// is the OAuth redirect_uri the wallet presents to the issuer's authorization
// server; it must match a value the issuer accepts.
//
// authCodeResolver may be nil when only pre-authorized-code offers are expected;
// an authorization-code offer without a resolver fails cleanly.
func (w *Wallet) Receive(credentialOfferURI, redirectURI string, authCodeResolver AuthCodeResolver) ([]*clientmodels.Credential, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if redirectURI == "" {
		return nil, fmt.Errorf("wallet: redirectURI is required for issuance")
	}

	h := &issuanceHandler{
		policy:           w.policy,
		logStorage:       w.storage,
		authCodeResolver: authCodeResolver,
		done:             make(chan issuanceResult, 1),
	}
	w.vci.NewSession(w.nextSessionID(), credentialOfferURI, redirectURI, h)

	res := <-h.done
	return res.credentials, res.err
}

type issuanceResult struct {
	credentials []*clientmodels.Credential
	err         error
}

// issuanceHandler is a headless openid4vci.Handler: it resolves every permission
// callback from the wallet's Policy and delivers the terminal outcome on done.
type issuanceHandler struct {
	policy           Policy
	logStorage       storage.Storage
	authCodeResolver AuthCodeResolver
	done             chan issuanceResult

	// requestor is captured from whichever permission callback fires first so
	// Success can attribute the issuance log to the correct issuer.
	requestor *clientmodels.TrustedParty
}

func (h *issuanceHandler) Success(result string, issued []*clientmodels.Credential) {
	// The core OpenID4VCI session verifies and persists the credentials; here we
	// only add the issuance log (parity with client/openid4vci_adapters.go).
	if len(issued) > 0 && h.logStorage != nil {
		logCreds := make([]clientmodels.LogCredential, len(issued))
		for i, c := range issued {
			logCreds[i] = clientmodels.CredentialToLogCredential(c)
		}
		var requestor clientmodels.TrustedParty
		if h.requestor != nil {
			requestor = *h.requestor
		}
		if err := services.NewEudiLogService(h.logStorage).AddIssuanceLog(clientmodels.Protocol_OpenID4VCI, requestor, logCreds); err != nil {
			// Non-fatal: the credentials are already stored.
			fmt.Printf("wallet: failed to write issuance log: %v\n", err)
		}
	}
	h.done <- issuanceResult{credentials: issued}
}

func (h *issuanceHandler) Cancelled() {
	h.done <- issuanceResult{err: fmt.Errorf("wallet: issuance session cancelled")}
}

func (h *issuanceHandler) Failure(err *clientmodels.SessionError) {
	h.done <- issuanceResult{err: sessionErrorToError("issuance", err)}
}

func (h *issuanceHandler) RequestPreAuthorizedCodeFlowPermission(
	request *clientmodels.PreAuthorizedCodeFlowPermissionRequest,
	requestorInfo *clientmodels.TrustedParty,
	callback openid4vci.TokenPermissionHandler,
) {
	h.requestor = requestorInfo
	txCode, ok := h.policy.TransactionCode()
	if ok {
		callback(true, &txCode)
		return
	}
	callback(true, nil)
}

func (h *issuanceHandler) RequestAuthorizationCodeFlowPermission(
	request *clientmodels.AuthorizationCodeFlowRequest,
	requestorInfo *clientmodels.TrustedParty,
	callback openid4vci.AuthCodeHandler,
) {
	h.requestor = requestorInfo
	if h.authCodeResolver == nil {
		callback(false, nil)
		h.done <- issuanceResult{err: fmt.Errorf("wallet: issuer requires the authorization code flow but no AuthCodeResolver was provided")}
		return
	}

	authURL, err := buildAuthorizationURL(request)
	if err != nil {
		callback(false, nil)
		h.done <- issuanceResult{err: err}
		return
	}
	callbackURL, err := h.authCodeResolver(authURL)
	if err != nil {
		callback(false, nil)
		h.done <- issuanceResult{err: fmt.Errorf("wallet: authorization code flow aborted: %w", err)}
		return
	}
	callback(true, &callbackURL)
}

func (h *issuanceHandler) RequestPermission(
	offered []*clientmodels.Credential,
	requestorInfo *clientmodels.TrustedParty,
	callback openid4vci.PermissionHandler,
) {
	if requestorInfo != nil {
		h.requestor = requestorInfo
	}
	callback(h.policy.ApproveIssuance(offered, requestorInfo))
}

// buildAuthorizationURL assembles the URL the user must visit to authorize the
// issuance, mirroring client/openid4vci_adapters.go.
func buildAuthorizationURL(request *clientmodels.AuthorizationCodeFlowRequest) (string, error) {
	authURL, err := url.Parse(request.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("wallet: failed to parse authorization endpoint: %w", err)
	}
	authURL.RawQuery = url.Values(request.AuthorizationParameters).Encode()
	return authURL.String(), nil
}
