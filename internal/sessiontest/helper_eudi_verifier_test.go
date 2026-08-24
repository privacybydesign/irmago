package sessiontest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Helpers for driving the EUDI reference verifier (the eudi_openid4vp* services in
// docker-compose.yml) over its management API. These speak to the verifier's own
// /ui/presentations endpoints, which are not part of OpenID4VP: they are how that
// service is started and queried from the outside.

// EudiVerifierSession holds the session link and transaction ID from starting a session at the EUDI verifier.
type EudiVerifierSession struct {
	SessionLink   string
	TransactionId string
	Host          string
}

func StartTestSessionAtEudiVerifier(openid4vpHost string, startSessionRequest string) (EudiVerifierSession, error) {
	apiUrl := fmt.Sprintf("%s/ui/presentations", openid4vpHost)
	response, err := http.Post(apiUrl,
		"application/json",
		bytes.NewReader([]byte(startSessionRequest)))

	if err != nil {
		return EudiVerifierSession{}, fmt.Errorf("failed to post session request to eudi verifier: %v", err)
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return EudiVerifierSession{}, fmt.Errorf("failed to read body of response from eudi verifier while starting session: %v", err)
	}

	var requestRequest map[string]string

	err = json.Unmarshal(body, &requestRequest)
	if err != nil {
		return EudiVerifierSession{}, fmt.Errorf("failed to parse request request body into json: %v (%v)", err, string(body))
	}

	transactionId := requestRequest["transaction_id"]

	queryParams := url.Values{}

	for key, value := range requestRequest {
		queryParams.Add(key, value)
	}

	sessionUrl := url.URL{
		Scheme:   "eudi-openid4vp://",
		RawQuery: queryParams.Encode(),
	}

	return EudiVerifierSession{
		SessionLink:   sessionUrl.String(),
		TransactionId: transactionId,
		Host:          openid4vpHost,
	}, nil
}

// EudiDcApiVerifierSession holds the signed authorization request and the transaction ID
// from starting a Digital Credentials API session at the EUDI verifier. There is no session
// link: over the DC API the platform hands the request to the wallet and posts the response
// back to the verifier itself.
type EudiDcApiVerifierSession struct {
	EudiVerifierSession
	Request string
}

// StartDcApiTestSessionAtEudiVerifier starts a session at the EUDI verifier that is to be
// served over the Digital Credentials API, and returns the signed authorization request the
// platform is expected to deliver to the wallet.
func StartDcApiTestSessionAtEudiVerifier(openid4vpHost string, startSessionRequest string) (EudiDcApiVerifierSession, error) {
	apiUrl := fmt.Sprintf("%s/ui/presentations/dc-api", openid4vpHost)
	response, err := http.Post(apiUrl,
		"application/json",
		bytes.NewReader([]byte(startSessionRequest)))

	if err != nil {
		return EudiDcApiVerifierSession{}, fmt.Errorf("failed to post dc api session request to eudi verifier: %v", err)
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return EudiDcApiVerifierSession{}, fmt.Errorf("failed to read body of response from eudi verifier while starting dc api session: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		return EudiDcApiVerifierSession{}, fmt.Errorf("unexpected status %d from eudi verifier: %s", response.StatusCode, string(body))
	}

	var parsed struct {
		Request       string `json:"request"`
		TransactionId string `json:"transaction_id"`
	}

	if err := json.Unmarshal(body, &parsed); err != nil {
		return EudiDcApiVerifierSession{}, fmt.Errorf("failed to parse dc api session response into json: %v (%v)", err, string(body))
	}

	return EudiDcApiVerifierSession{
		TransactionId: parsed.TransactionId,
		Host:          openid4vpHost,
		Request:       parsed.Request,
	}, nil
}

// PostDcApiWalletResponseToEudiVerifier delivers a wallet response to the EUDI verifier the
// way the platform does over the Digital Credentials API: every member of the response object
// the wallet handed back is posted as a form parameter.
func PostDcApiWalletResponseToEudiVerifier(session EudiDcApiVerifierSession, walletResponse string) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal([]byte(walletResponse), &members); err != nil {
		return fmt.Errorf("failed to parse dc api wallet response: %v (%v)", err, walletResponse)
	}

	values := url.Values{}
	for name, member := range members {
		// String members are posted verbatim, everything else (vp_token is an object)
		// as the JSON it was.
		var text string
		if err := json.Unmarshal(member, &text); err == nil {
			values.Set(name, text)
		} else {
			values.Set(name, string(member))
		}
	}

	apiUrl := fmt.Sprintf("%s/ui/presentations/%s/dc-api", session.Host, session.TransactionId)
	response, err := http.Post(apiUrl,
		"application/x-www-form-urlencoded",
		bytes.NewReader([]byte(values.Encode())))

	if err != nil {
		return fmt.Errorf("failed to post dc api wallet response to eudi verifier: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read response of eudi verifier while posting dc api wallet response: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from eudi verifier: %s", response.StatusCode, string(body))
	}

	return nil
}

// GetWalletResponseFromEudiVerifier fetches the wallet response (disclosed VP token) from the EUDI verifier.
func GetWalletResponseFromEudiVerifier(session EudiVerifierSession) (map[string]any, error) {
	apiUrl := fmt.Sprintf("%s/ui/presentations/%s", session.Host, session.TransactionId)
	response, err := http.Get(apiUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet response from eudi verifier: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read wallet response body: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from eudi verifier: %s", response.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse wallet response: %v (%s)", err, string(body))
	}

	return result, nil
}
