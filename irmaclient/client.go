package irmaclient

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/testdata"
)

type Client struct {
	sdjwtvcStorage  SdJwtVcStorage
	openid4vpClient *OpenID4VPClient
	irmaClient      *IrmaClient
	logsStorage     LogsStorage
	keyBinder       sdjwtvc.KeyBinder
}

func New(
	storagePath string,
	irmaConfigurationPath string,
	handler ClientHandler,
	signer Signer,
	aesKey [32]byte,
) (*Client, error) {
	if err := common.AssertPathExists(storagePath); err != nil {
		return nil, err
	}
	if err := common.AssertPathExists(irmaConfigurationPath); err != nil {
		return nil, err
	}

	conf, err := irma.NewConfiguration(
		filepath.Join(storagePath, "irma_configuration"),
		irma.ConfigurationOptions{Assets: irmaConfigurationPath, IgnorePrivateKeys: true},
	)
	if err != nil {
		return nil, fmt.Errorf("instantiating configuration failed: %v", err)
	}

	storage := NewIrmaStorage(storagePath, conf, aesKey)

	// Ensure storage path exists, and populate it with necessary files
	if err = storage.Open(); err != nil {
		return nil, fmt.Errorf("failed to open irma storage: %v", err)
	}

	keybindingStorage := NewBboltKeybindingStorage(storage.db, aesKey)
	keyBinder := sdjwtvc.NewDefaultKeyBinder(keybindingStorage)

	verifierValidator := NewRequestorSchemeVerifierValidator()

	sdjwtvcStorage := NewBboltSdJwtVcStorage(storage.db, aesKey)
	openid4vpClient, err := NewOpenID4VPClient(sdjwtvcStorage, verifierValidator, keyBinder, storage)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new openid4vp client: %v", err)
	}

	x509Options, err := sdjwtvc.CreateX509VerifyOptionsFromCertChain(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create verify options: %v", err)
	}

	context := sdjwtvc.VerificationContext{
		IssuerMetadataFetcher:   sdjwtvc.NewHttpIssuerMetadataFetcher(),
		Clock:                   sdjwtvc.NewSystemClock(),
		JwtVerifier:             sdjwtvc.NewJwxJwtVerifier(),
		AllowNonHttpsIssuer:     false,
		X509VerificationOptions: x509Options,
	}

	irmaClient, err := NewIrmaClient(conf, handler, signer, storage, context, sdjwtvcStorage, keyBinder)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate irma client: %v", err)
	}

	return &Client{
		sdjwtvcStorage:  sdjwtvcStorage,
		openid4vpClient: openid4vpClient,
		irmaClient:      irmaClient,
		logsStorage:     storage,
		keyBinder:       keyBinder,
	}, nil
}

func (client *Client) Close() error {
	return client.irmaClient.Close()
}

type SessionRequestData struct {
	irma.Qr
	Protocol Protocol `json:"protocol,omitempty"`
}

func (client *Client) NewSession(sessionrequest string, handler Handler) SessionDismisser {
	var sessionReq SessionRequestData
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

type intermediateCredentialInfo struct {
	info *irma.CredentialInfo
	// map from format to instance hash, can be used for deleting
	formatHashes map[string]string
}

// Combines credential infos when their attributes & credential type match (so when only the format differs)
func constructCredentialMap(infoList irma.CredentialInfoList) map[string]intermediateCredentialInfo {
	result := make(map[string]intermediateCredentialInfo)

	for _, info := range infoList {
		hash := hashAttributesAndCredType(info)
		existingEntry, ok := result[hash]
		if ok {
			existingEntry.info.CredentialFormats = append(existingEntry.info.CredentialFormats, info.CredentialFormats...)
			existingEntry.formatHashes[info.CredentialFormats[0]] = info.Hash
		} else {
			newEntry := intermediateCredentialInfo{
				formatHashes: map[string]string{
					info.CredentialFormats[0]: info.Hash,
				},
			}
			infoCopy := *info
			infoCopy.Hash = hash
			newEntry.info = &infoCopy
			result[hash] = newEntry
		}
	}
	return result
}

func hashAttributesAndCredType(info *irma.CredentialInfo) string {
	toHash := info.Identifier().String()
	for attrType, attrValue := range info.Attributes {
		toHash += attrType.String() + attrValue[""]
	}
	hashBytes := sha256.Sum256([]byte(toHash))
	return string(hashBytes[:])
}

// Returns all credential info instances separately per format
func (client *Client) getAllCredentialInfosSeperately() irma.CredentialInfoList {
	sdjwtvcs := client.sdjwtvcStorage.GetCredentialInfoList()
	idemix := client.irmaClient.CredentialInfoList()

	result := irma.CredentialInfoList{}
	result = append(result, sdjwtvcs...)
	result = append(result, idemix...)

	return result
}

func (client *Client) CredentialInfoList() irma.CredentialInfoList {
	all := client.getAllCredentialInfosSeperately()
	combined := constructCredentialMap(all)
	result := irma.CredentialInfoList{}
	for _, value := range combined {
		result = append(result, value.info)
	}
	return result
}

func (client *Client) KeyshareVerifyPin(
	pin string,
	schemeid irma.SchemeManagerIdentifier,
) (success bool, triesRemaing int, blockedSecs int, err error) {
	return client.irmaClient.KeyshareVerifyPin(pin, schemeid)
}

func (client *Client) KeyshareChangePin(oldPin, newPin string) {
	client.irmaClient.KeyshareChangePin(oldPin, newPin)
}

func (client *Client) KeyshareEnroll(manager irma.SchemeManagerIdentifier, email *string, pin string, lang string) {
	client.irmaClient.KeyshareEnroll(manager, email, pin, lang)
}

func (client *Client) RemoveCredentialByHash(hash string) error {
	allCredentials := client.getAllCredentialInfosSeperately()
	combined := constructCredentialMap(allCredentials)

	toDelete := combined[hash]

	for format, credHash := range toDelete.formatHashes {
		if format == "idemix" {
			if err := client.irmaClient.RemoveCredentialByHash(credHash); err != nil {
				return err
			}
		}
		if format == "dc+sd-jwt" {
			holderPubKeys, err := client.sdjwtvcStorage.RemoveCredentialByHash(credHash)
			if err != nil {
				return fmt.Errorf("error while deleting sdjwtvc credential: %v", err)
			}
			if err = client.keyBinder.RemovePrivateKeys(holderPubKeys); err != nil {
				return fmt.Errorf("failed to remove holder private keys: %v", err)
			}
		}
	}
	logEntry, err := createRemovalLog(toDelete.info)
	if err != nil {
		return fmt.Errorf("failed to create delete log: %v", err)
	}
	return client.logsStorage.AddLogEntry(logEntry)
}

func createRemovalLog(info *irma.CredentialInfo) (*LogEntry, error) {
	attrs := []irma.TranslatedString{}
	for _, attr := range info.Attributes {
		attrs = append(attrs, attr)
	}
	formats := make([]CredentialFormat, len(info.CredentialFormats))

	for index, format := range info.CredentialFormats {
		formats[index] = CredentialFormat(format)
	}

	return &LogEntry{
		Time: irma.Timestamp(time.Now()),
		Type: ActionRemoval,
		Removed: map[irma.CredentialTypeIdentifier][]irma.TranslatedString{
			info.Identifier(): attrs,
		},
		RemovedFormats: formats,
	}, nil
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
	if err := client.sdjwtvcStorage.RemoveAll(); err != nil {
		return fmt.Errorf("failed to remove sdjwtvc storage: %v", err)
	}
	if err := client.keyBinder.RemoveAllPrivateKeys(); err != nil {
		return fmt.Errorf("failed to remove all holder private keys: %v", err)
	}

	return client.irmaClient.RemoveStorage()
}

func (client *Client) LoadNewestLogs(max int) ([]LogInfo, error) {
	rawLogs, err := client.irmaClient.LoadNewestLogs(max)
	if err != nil {
		return nil, err
	}
	return client.rawLogEntriesToLogInfo(rawLogs)
}

func (client *Client) LoadLogsBefore(beforeIndex uint64, max int) ([]LogInfo, error) {
	rawLogs, err := client.irmaClient.LoadLogsBefore(beforeIndex, max)
	if err != nil {
		return nil, err
	}
	return client.rawLogEntriesToLogInfo(rawLogs)
}

func (client *Client) rawLogEntryToLogInfo(entry *LogEntry) (LogInfo, error) {
	if entry.OpenID4VP != nil {
		return LogInfo{
			ID:   entry.ID,
			Type: LogType_Disclosure,
			Time: entry.Time,
			DisclosureLog: &DisclosureLog{
				Protocol:    Protocol_OpenID4VP,
				Credentials: entry.OpenID4VP.DisclosedCredentials,
				Verifier:    entry.ServerName,
			},
		}, nil
	}

	switch entry.Type {
	case irma.ActionDisclosing, irma.ActionSigning:
		attributes, err := entry.GetDisclosedCredentials(client.GetIrmaConfiguration())
		if err != nil {
			return LogInfo{}, err
		}
		credLog, err := disclosedAttributesToCredentialLogs(attributes)
		if err != nil {
			return LogInfo{}, err
		}
		disclosureLog := &DisclosureLog{
			Protocol:    Protocol_Irma,
			Credentials: credLog,
			Verifier:    entry.ServerName,
		}

		if entry.Type == irma.ActionSigning {
			return LogInfo{
				ID:   entry.ID,
				Type: LogType_Signature,
				Time: entry.Time,
				SignedMessageLog: &SignedMessageLog{
					Message:       string(entry.SignedMessage),
					DisclosureLog: *disclosureLog,
				},
			}, nil
		}
		return LogInfo{
			ID:            entry.ID,
			Type:          LogType_Disclosure,
			Time:          entry.Time,
			DisclosureLog: disclosureLog,
		}, nil
	case irma.ActionIssuing:
		attributes, err := entry.GetDisclosedCredentials(client.GetIrmaConfiguration())
		if err != nil {
			return LogInfo{}, err
		}
		credLog, err := disclosedAttributesToCredentialLogs(attributes)
		if err != nil {
			return LogInfo{}, err
		}
		issued, err := entry.GetIssuedCredentials(client.GetIrmaConfiguration())
		if err != nil {
			return LogInfo{}, err
		}
		session, err := entry.SessionRequest()
		if err != nil {
			return LogInfo{}, err
		}
		issReq, ok := session.(*irma.IssuanceRequest)
		if !ok {
			return LogInfo{}, fmt.Errorf("failed to get issuance request")
		}
		issuedLog, err := issuedCredentialsToCredentialLog(issued, issReq.RequestSdJwts)
		if err != nil {
			return LogInfo{}, err
		}
		return LogInfo{
			ID:   entry.ID,
			Time: entry.Time,
			Type: LogType_Issuance,
			IssuanceLog: &IssuanceLog{
				Protocol:             Protocol_Irma,
				Credentials:          issuedLog,
				DisclosedCredentials: credLog,
			},
		}, nil
	case ActionRemoval:
		removedCreds := []CredentialLog{}

		for credentialTypeId, attributeValues := range entry.Removed {
			removed := CredentialLog{
				Formats:        entry.RemovedFormats,
				CredentialType: credentialTypeId.String(),
				Attributes:     map[string]string{},
			}

			attributeTypes := client.GetIrmaConfiguration().CredentialTypes[credentialTypeId].AttributeTypes
			for index, attributeValue := range attributeValues {
				typ := attributeTypes[index]
				if typ.RevocationAttribute {
					continue
				}

				removed.Attributes[typ.ID] = attributeValue[""]
			}

			removedCreds = append(removedCreds, removed)
		}
		return LogInfo{
			ID:   entry.ID,
			Time: entry.Time,
			Type: LogType_CredentialRemoval,
			RemovalLog: &RemovalLog{
				Credentials: removedCreds,
			},
		}, nil
	}

	return LogInfo{}, nil
}

func issuedCredentialsToCredentialLog(creds irma.CredentialInfoList, issuedSdJwts bool) ([]CredentialLog, error) {
	result := []CredentialLog{}
	for _, cred := range creds {
		if cred == nil {
			continue
		}
		entry := CredentialLog{
			Formats:        []CredentialFormat{Format_Idemix},
			CredentialType: cred.Identifier().String(),
			Attributes:     map[string]string{},
		}
		if issuedSdJwts {
			entry.Formats = append(entry.Formats, Format_SdJwtVc)
		}
		for key, attr := range cred.Attributes {
			entry.Attributes[key.Name()] = attr[""]
		}
		result = append(result, entry)
	}
	return result, nil
}

func disclosedAttributesToCredentialLogs(attributes [][]*irma.DisclosedAttribute) ([]CredentialLog, error) {
	result := []CredentialLog{}
	for _, creds := range attributes {
		if creds == nil {
			continue
		}
		entry := CredentialLog{
			// this function is only used for idemix credentials
			Formats:        []CredentialFormat{Format_Idemix},
			CredentialType: creds[0].Identifier.Parent(),
			Attributes:     map[string]string{},
		}
		for _, attr := range creds {
			entry.Attributes[attr.Identifier.Name()] = attr.Value[""]
		}
		result = append(result, entry)
	}
	return result, nil
}

func (client *Client) rawLogEntriesToLogInfo(entries []*LogEntry) ([]LogInfo, error) {
	result := []LogInfo{}
	for _, e := range entries {
		info, err := client.rawLogEntryToLogInfo(e)
		if err != nil {
			return nil, fmt.Errorf("failed to convert log entry to info: %v", err)
		}
		result = append(result, info)
	}
	return result, nil
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
