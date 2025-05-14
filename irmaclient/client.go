package irmaclient

import (
	"encoding/json"
	"fmt"

	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

type SdJwtVcCredentialQueryHandler struct{}

func (qh *SdJwtVcCredentialQueryHandler) SupportsFormat(format credentials.CredentialFormat) bool {
	return format == credentials.Format_SdJwtVc || format == credentials.Format_SdJwtVc_Legacy
}

func (qh *SdJwtVcCredentialQueryHandler) Handle(query dcql.CredentialQuery) (dcql.QueryResponse, error) {
	sdjwt, err := createFullSdJwtVc()
	if err != nil {
		return dcql.QueryResponse{}, err
	}
	return dcql.QueryResponse{
		QueryId:     query.Id,
		Credentials: []string{string(sdjwt)},
	}, nil
}

func createFullSdJwtVc() (sdjwtvc.SdJwtVc, error) {
	sdjwt, err := sdjwtvc.CreateTestSdJwtVc()

	if err != nil {
		return "", err
	}

	kbJwtCreator, err := sdjwtvc.NewKbJwtCreatorWithHolderTestKey()

	if err != nil {
		return "", err
	}

	kbjwt, err := sdjwtvc.CreateKbJwt(sdjwt, kbJwtCreator)

	if err != nil {
		return "", err
	}
	fullCredential := sdjwtvc.AddKeyBindingJwtToSdJwtVc(sdjwt, kbjwt)
	fmt.Printf("sdjwt: \n\n%v\n\n\n", fullCredential)
	return fullCredential, nil
}

type Client struct {
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
	openid4vpClient, err := NewOpenID4VPClient([]dcql.CredentialQueryHandler{
		&SdJwtVcCredentialQueryHandler{},
	})
	if err != nil {
		return nil, err
	}

	irmaClient, err := NewIrmaClient(storagePath, irmaConfigurationPath, handler, signer, aesKey)
	if err != nil {
		return nil, err
	}

	return &Client{
		irmaClient:      irmaClient,
		openid4vpClient: openid4vpClient,
	}, nil
}

func (client *Client) Close() error {
	return client.irmaClient.Close()
}

func (client *Client) NewSession(sessionrequest string, handler Handler) SessionDismisser {
	var result irma.Qr
	err := json.Unmarshal([]byte(sessionrequest), &result)
	if err != nil {
		irma.Logger.Errorf("failed to parse session request: %v\n", err)
		handler.Failure(nil)
		return nil
	}

	if result.Type == "disclosing" {
		return client.openid4vpClient.NewSession(result.URL, handler)
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
	return client.irmaClient.CredentialInfoList()
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
