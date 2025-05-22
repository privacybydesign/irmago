package irmaclient

import (
	"encoding/json"

	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
)

type Client struct {
	sdjwtvcStorage  *InMemorySdJwtVcStorage
	openid4vpClient *OpenID4VPClient
	irmaClient      *IrmaClient
}

func New(
	storagePath string,
	irmaConfigurationPath string,
	handler ClientHandler,
	signer Signer,
	aesKey [32]byte,
) (*Client, error) {
	sdjwtvcStorage, err := NewSdJwtVcStorage()
	if err != nil {
		return nil, err
	}

	jwtCreator, err := sdjwtvc.NewDefaultEcdsaJwtCreatorWithHolderPrivateKey()
	if err != nil {
		return nil, err
	}

	kbjwtCreator := sdjwtvc.DefaultKbJwtCreator{
		Clock:      sdjwtvc.NewSystemClock(),
		JwtCreator: jwtCreator,
	}

	openid4vpClient, err := NewOpenID4VPClient(sdjwtvcStorage, &kbjwtCreator)
	if err != nil {
		return nil, err
	}

	irmaClient, err := NewIrmaClient(storagePath, irmaConfigurationPath, handler, signer, aesKey)
	if err != nil {
		return nil, err
	}

	return &Client{
		sdjwtvcStorage:  sdjwtvcStorage,
		openid4vpClient: openid4vpClient,
		irmaClient:      irmaClient,
	}, nil
}

func (client *Client) Close() error {
	return client.irmaClient.Close()
}

type sessionRequestData struct {
	irma.Qr
	Protocol string `json:"protocol,omitempty"`
}

func (client *Client) NewSession(sessionrequest string, handler Handler) SessionDismisser {
	var sessionReq sessionRequestData
	err := json.Unmarshal([]byte(sessionrequest), &sessionReq)
	if err != nil {
		irma.Logger.Errorf("failed to parse session request: %v\n", err)
		handler.Failure(nil)
		return nil
	}

	if sessionReq.Protocol == "openid4vp" {
		return client.openid4vpClient.NewSession(sessionReq.URL, handler)
	}

	return client.irmaClient.NewSession(sessionrequest, handler)
}

func (client *Client) GetIrmaConfiguration() *irma.Configuration {
	return client.irmaClient.Configuration
}

func (client *Client) UnenrolledSchemeManagers() []irma.SchemeManagerIdentifier {
	return client.irmaClient.UnenrolledSchemeManagers()
}

func (client *Client) EnrolledSchemeManagers() []irma.SchemeManagerIdentifier {
	return client.irmaClient.EnrolledSchemeManagers()
}

func (client *Client) CredentialInfoList() irma.CredentialInfoList {
	sdjwtvcs := client.sdjwtvcStorage.GetCredentialInfoList()
	idemix := client.irmaClient.CredentialInfoList()

	result := irma.CredentialInfoList{}
	result = append(result, sdjwtvcs...)
	result = append(result, idemix...)

	return result
}

func (client *Client) KeyshareVerifyPin(pin string, schemeid irma.SchemeManagerIdentifier) (bool, int, int, error) {
	return client.irmaClient.KeyshareVerifyPin(pin, schemeid)
}

func (client *Client) KeyshareChangePin(oldPin, newPin string) {
	client.irmaClient.KeyshareChangePin(oldPin, newPin)
}

func (client *Client) KeyshareEnroll(manager irma.SchemeManagerIdentifier, email *string, pin string, lang string) {
	client.irmaClient.KeyshareEnroll(manager, email, pin, lang)
}

func (client *Client) RemoveCredentialByHash(hash string) error {
	return client.irmaClient.RemoveCredentialByHash(hash)
}

func (client *Client) UpdateSchemes() {
	client.irmaClient.Configuration.UpdateSchemes()
}

func (client *Client) RemoveScheme(id irma.SchemeManagerIdentifier) error {
	return client.irmaClient.RemoveScheme(id)
}

func (client *Client) RemoveRequestorScheme(id irma.RequestorSchemeIdentifier) error {
	return client.irmaClient.RemoveRequestorScheme(id)
}

func (client *Client) InstallScheme(url string, publickey []byte) error {
	return client.irmaClient.Configuration.InstallScheme(url, publickey)
}

func (client *Client) RemoveStorage() error {
	return client.irmaClient.RemoveStorage()
}

func (client *Client) LoadNewestLogs(max int) ([]*LogEntry, error) {
	return client.irmaClient.LoadNewestLogs(max)
}

func (client *Client) LoadLogsBefore(beforeIndex uint64, max int) ([]*LogEntry, error) {
	return client.irmaClient.LoadLogsBefore(beforeIndex, max)
}

func (client *Client) SetPreferences(prefs Preferences) {
	client.irmaClient.SetPreferences(prefs)
}

func (client *Client) GetPreferences() Preferences {
	return client.irmaClient.Preferences
}

// Preferences contains the preferences of the user of this client.
// TODO: consider if we should save irmamobile preferences here, because they would automatically
// be part of any backup and syncing solution we implement at a later time
type Preferences struct {
	DeveloperMode bool
}

var defaultPreferences = Preferences{
	DeveloperMode: false,
}

// KeyshareHandler is used for asking the user for his email address and PIN,
// for enrolling at a keyshare server.
type KeyshareHandler interface {
	EnrollmentFailure(manager irma.SchemeManagerIdentifier, err error)
	EnrollmentSuccess(manager irma.SchemeManagerIdentifier)
}

type ChangePinHandler interface {
	ChangePinFailure(manager irma.SchemeManagerIdentifier, err error)
	ChangePinSuccess()
	ChangePinIncorrect(manager irma.SchemeManagerIdentifier, attempts int)
	ChangePinBlocked(manager irma.SchemeManagerIdentifier, timeout int)
}

// ClientHandler informs the user that the configuration or the list of attributes
// that this client uses has been updated.
type ClientHandler interface {
	KeyshareHandler
	ChangePinHandler

	UpdateConfiguration(new *irma.IrmaIdentifierSet)
	UpdateAttributes()
	Revoked(cred *irma.CredentialIdentifier)
	ReportError(err error)
}

type credLookup struct {
	id      irma.CredentialTypeIdentifier
	counter int
}

type credCandidateSet [][]*credCandidate

type credCandidate irma.CredentialIdentifier

type DisclosureCandidate struct {
	*irma.AttributeIdentifier
	Value        irma.TranslatedString
	Expired      bool
	Revoked      bool
	NotRevokable bool
}

type DisclosureCandidates []*DisclosureCandidate

type secretKey struct {
	Key *big.Int
}
