package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-co-op/gocron/v2"

	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/internal/clientstorage"
	"github.com/privacybydesign/irmago/internal/common"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

type Client struct {
	storage          *clientstorage.Storage
	sdjwtvcStorage   irmaclient.SdJwtVcStorage
	openid4vpClient  *irmaclient.OpenID4VPClient
	openid4vciClient *irmaclient.OpenID4VciClient
	irmaClient       *irmaclient.IrmaClient
	logsStorage      irmaclient.LogsStorage
	keyBinder        sdjwtvc.KeyBinder
	scheduler        gocron.Scheduler
	sessionManager   sessionManager
	// TODO: move preferences from IrmaClient to here
	//Preferences      clientsettings.Preferences
}

func New(
	storagePath string,
	irmaConfigurationPath string,
	handler irmaclient.ClientHandler,
	sessionHandler SessionHandler,
	signer irmaclient.Signer,
	aesKey [32]byte,
) (*Client, error) {
	if err := common.AssertPathExists(storagePath); err != nil {
		return nil, err
	}
	if err := common.AssertPathExists(irmaConfigurationPath); err != nil {
		return nil, err
	}

	eudiConfigurationPath := filepath.Join(storagePath, "eudi_configuration")

	if err := common.EnsureDirectoryExists(eudiConfigurationPath); err != nil {
		return nil, err
	}

	// Load IRMA + EUDI configuration
	irmaConf, err := irma.NewConfiguration(
		filepath.Join(storagePath, "irma_configuration"),
		irma.ConfigurationOptions{Assets: irmaConfigurationPath, IgnorePrivateKeys: true},
	)
	if err != nil {
		return nil, fmt.Errorf("instantiating configuration failed: %v", err)
	}

	eudi.Logger = irma.Logger
	eudiConf, err := eudi.NewConfiguration(eudiConfigurationPath)
	if err != nil {
		return nil, fmt.Errorf("instantiating eudi configuration failed: %v", err)
	}

	// Initialize DB storage
	storage := clientstorage.NewStorage(storagePath, aesKey)
	irmaStorage := irmaclient.NewIrmaStorage(storage, irmaConf)

	// Ensure storage path exists, and populate it with necessary files
	if err = storage.Open(); err != nil {
		return nil, fmt.Errorf("failed to open irma storage: %v", err)
	}

	keyBindingStorage := irmaclient.NewBboltKeyBindingStorage(storage)
	keyBinder := sdjwtvc.NewDefaultKeyBinder(keyBindingStorage)

	// Verifier verification checks if the verifier is trusted
	verifierValidator := eudi.NewRequestorCertificateStoreVerifierValidator(&eudiConf.Verifiers, &eudi.DefaultQueryValidatorFactory{})
	sdjwtvcStorage := irmaclient.NewBboltSdJwtVcStorage(storage)

	openid4vpClient, err := irmaclient.NewOpenID4VPClient(eudiConf, sdjwtvcStorage, verifierValidator, keyBinder, irmaStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new openid4vp client: %v", err)
	}

	// SD-JWT verification checks if the SD-JWT (and the issuing party) can be trusted
	sdJwtVcVerificationContext := sdjwtvc.SdJwtVcVerificationContext{
		X509VerificationContext: &eudiConf.Issuers,
		Clock:                   eudi_jwt.NewSystemClock(),
		JwtVerifier:             sdjwtvc.NewJwxJwtVerifier(),
		VerifyVerifiableCredentialTypeInRequestorInfo: true,
	}

	irmaClient, err := irmaclient.NewIrmaClient(irmaConf, handler, signer, irmaStorage, sdJwtVcVerificationContext, sdjwtvcStorage, keyBinder)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate irma client: %v", err)
	}

	// When developer mode is enabled we want to load the staging trust anchors in addition
	// to the production trust anchors
	if irmaClient.Preferences.DeveloperMode {
		openid4vpClient.Configuration.EnableStagingTrustAnchors()
	}

	if err := openid4vpClient.Configuration.Reload(); err != nil {
		return nil, fmt.Errorf("reloading eudi configuration failed: %v", err)
	}

	scheduler, err := gocron.NewScheduler()
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new scheduler: %v", err)
	}
	scheduler.Start()

	// Fow now, create a new SD-JWT verification context, which skips the VCT check against the requestor info
	sdJwtVcVerificationContextOpenId4Vci := sdjwtvc.SdJwtVcVerificationContext{
		X509VerificationContext: &eudiConf.Issuers,
		Clock:                   eudi_jwt.NewSystemClock(),
		JwtVerifier:             sdjwtvc.NewJwxJwtVerifier(),
		VerifyVerifiableCredentialTypeInRequestorInfo: false,
	}

	// Initiate the OpenID4VCI client
	openid4vciClient := irmaclient.NewOpenID4VciClient(
		&http.Client{},
		eudiConf,
		sdjwtvcStorage,
		sdjwtvc.NewHolderVerificationProcessor(sdJwtVcVerificationContextOpenId4Vci),
		keyBinder,
	)

	// When IRMA issuance sessions are done, an inprogress OpenID4VP session
	// should again ask for verification permission,
	// so we do this by listening for session-done events
	irmaClient.SetOnSessionDoneCallback(openid4vpClient.RefreshPendingPermissionRequest)

	client := &Client{
		storage:          storage,
		sdjwtvcStorage:   sdjwtvcStorage,
		openid4vpClient:  openid4vpClient,
		openid4vciClient: openid4vciClient,
		irmaClient:       irmaClient,
		logsStorage:      irmaStorage,
		keyBinder:        keyBinder,
		scheduler:        scheduler,
		sessionManager: sessionManager{
			Sessions:       map[int]*session{},
			NextId:         0,
			SessionHandler: sessionHandler,
		},
	}

	client.sessionManager.Client = client
	return client, nil
}

func (client *Client) Close() error {
	client.scheduler.Shutdown()
	client.irmaClient.Close()
	return client.storage.Close()
}

type SessionRequestData struct {
	irma.Qr
	Protocol               irmaclient.Protocol `json:"protocol,omitempty"`
	ContinueOnSecondDevice bool                `json:"continue_on_second_device"`
}

func (client *Client) DeleteKeyshareTokens() {
	client.irmaClient.DeleteKeyshareTokens()
}

func (client *Client) GetIrmaConfiguration() *irma.Configuration {
	return client.irmaClient.Configuration
}

func (client *Client) GetEudiConfiguration() *eudi.Configuration {
	return client.openid4vciClient.Configuration
}

func (client *Client) UnenrolledSchemeManagers() []irma.SchemeManagerIdentifier {
	return client.irmaClient.UnenrolledSchemeManagers()
}

func (client *Client) EnrolledSchemeManagers() []irma.SchemeManagerIdentifier {
	return client.irmaClient.EnrolledSchemeManagers()
}

func sdjwtBatchMetadataToIrmaCredentialInfo(metadata irmaclient.SdJwtVcBatchMetadata) *irma.CredentialInfo {
	credIdSegments := strings.Split(metadata.CredentialType, ".")

	attrs := map[irma.AttributeTypeIdentifier]irma.TranslatedString{}
	for name, value := range metadata.Attributes {
		id := irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", metadata.CredentialType, name))
		valueStr := value.(string)
		translatedValue := irma.NewTranslatedString(&valueStr)
		attrs[id] = translatedValue
	}

	return &irma.CredentialInfo{
		ID:                  credIdSegments[2],
		IssuerID:            credIdSegments[1],
		SchemeManagerID:     credIdSegments[0],
		SignedOn:            metadata.SignedOn,
		Expires:             metadata.Expires,
		Attributes:          attrs,
		Hash:                metadata.Hash,
		Revoked:             false,
		RevocationSupported: false,
		CredentialFormat:    string(irmaclient.Format_SdJwtVc),
		InstanceCount:       &metadata.RemainingInstanceCount,
	}
}

func (client *Client) credentialInfoList() irma.CredentialInfoList {
	sdjwtvcs := client.sdjwtvcStorage.GetCredentialMetdataList()
	idemix := client.irmaClient.CredentialInfoList()

	result := irma.CredentialInfoList{}

	for _, sdjwt := range sdjwtvcs {
		result = append(result, sdjwtBatchMetadataToIrmaCredentialInfo(sdjwt))
	}

	result = append(result, idemix...)

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

func hashAttributesAndCredType(info *irma.CredentialInfo) (string, error) {
	var hashContent strings.Builder
	hashContent.WriteString(info.Identifier().String())

	sortedKeys := []string{}
	for key := range info.Attributes {
		sortedKeys = append(sortedKeys, key.String())
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		valueStr, err := json.Marshal(info.Attributes[irma.NewAttributeTypeIdentifier(key)])
		if err != nil {
			return "", err
		}
		hashContent.WriteString(key + string(valueStr))
	}

	return sdjwtvc.CreateUrlEncodedHash(iana.SHA256, hashContent.String())
}

func sameCredentialAndAttributesCombi(creds []*irma.CredentialInfo) (bool, error) {
	typeAndAttrsHashes := map[string]struct{}{}

	for _, c := range creds {
		hash, err := hashAttributesAndCredType(c)
		if err != nil {
			return false, err
		}
		typeAndAttrsHashes[hash] = struct{}{}
	}
	return len(typeAndAttrsHashes) == 1, nil
}

func (client *Client) RemoveCredentialsByHash(hashByFormat map[irmaclient.CredentialFormat]string) error {
	allCreds := client.credentialInfoList()
	relevantCreds := []*irma.CredentialInfo{}
	for _, hash := range hashByFormat {
		relevantCreds = append(relevantCreds, allCreds[slices.IndexFunc(allCreds, func(info *irma.CredentialInfo) bool {
			return info.Hash == hash
		})])
	}

	if len(relevantCreds) == 0 {
		return fmt.Errorf("trying to delete credential that doesn't exist")
	}

	if same, err := sameCredentialAndAttributesCombi(relevantCreds); !same || err != nil {
		if !same {
			return fmt.Errorf("deleting two different credential instances at once is not supported")
		} else {
			return fmt.Errorf("error while comparing credential attributes: %v", err)
		}
	}

	formats := []irmaclient.CredentialFormat{}
	for format, hash := range hashByFormat {
		formats = append(formats, format)
		if format == irmaclient.Format_Idemix {
			if err := client.irmaClient.RemoveCredentialByHash(hash); err != nil {
				return err
			}
		}
		if format == irmaclient.Format_SdJwtVc {
			holderPubKeys, err := client.sdjwtvcStorage.RemoveCredentialByHash(hash)
			if err != nil {
				return fmt.Errorf("error while deleting sdjwtvc credential: %v", err)
			}
			if err = client.keyBinder.RemovePrivateKeys(holderPubKeys); err != nil {
				return fmt.Errorf("failed to remove holder private keys: %v", err)
			}
		}
	}

	info := relevantCreds[0]
	logEntry, err := createRemovalLog(client.GetIrmaConfiguration(), info.Identifier(), info.Attributes, formats)
	if err != nil {
		return fmt.Errorf("failed to create delete log: %v", err)
	}

	return client.logsStorage.AddLogEntry(logEntry)
}

func createRemovalLog(
	irmaConfiguration *irma.Configuration,
	credentialType irma.CredentialTypeIdentifier,
	attributes map[irma.AttributeTypeIdentifier]irma.TranslatedString,
	formats []irmaclient.CredentialFormat,
) (*irmaclient.LogEntry, error) {
	attrs := []irma.TranslatedString{}

	// loop over it in the order as defined in the scheme
	for _, t := range irmaConfiguration.CredentialTypes[credentialType].AttributeTypes {
		id := t.GetAttributeTypeIdentifier()
		attrs = append(attrs, attributes[id])
	}

	return &irmaclient.LogEntry{
		Time: irma.Timestamp(time.Now()),
		Type: irmaclient.ActionRemoval,
		Removed: map[irma.CredentialTypeIdentifier][]irma.TranslatedString{
			credentialType: attrs,
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

func (client *Client) rawLogEntryToLogInfo(entry *irmaclient.LogEntry) (LogInfo, error) {
	// NOTE: iOS builds change the container ID of the app, meaning that after every compilation/app update the location
	// of all app data changes. Logs store an absolute path to requestor logo's, which becomes invalid when the data is moved,
	// resulting in the logo's not being found for existing logs when an iOS app is updated.
	// Solving this issue correctly would require a deep refactor of many components and would likely introduce some very obscure bugs.
	// This hacky solution works around the issue by assuming the image path to be invalid and resolving it based on other information:
	//  - For OpenID4VP sessions the logo path is resolved based on the image name
	//  - For IRMA sessions the logo path is resolved based on the requestor ID and using the requestor schemes
	if entry.OpenID4VP != nil {
		requestor := entry.ServerName
		if requestor != nil && requestor.Logo != nil {
			path, err := client.openid4vpClient.Configuration.ResolveVerifierLogoPath(*entry.ServerName.Logo)
			if err == nil {
				requestor.LogoPath = &path
			}
		}
		return LogInfo{
			ID:   entry.ID,
			Type: irmaclient.LogType_Disclosure,
			Time: entry.Time,
			DisclosureLog: &DisclosureLog{
				Protocol:    irmaclient.Protocol_OpenID4VP,
				Credentials: openid4vpCredentialLogsToLogCredentials(client.GetIrmaConfiguration(), entry.OpenID4VP.DisclosedCredentials),
				Verifier:    requestor,
			},
		}, nil
	}

	// resolve the image for an irma session
	requestor := entry.ServerName
	if requestor != nil && requestor.Logo != nil {
		requestorScheme, ok := client.GetIrmaConfiguration().RequestorSchemes[requestor.ID.RequestorSchemeIdentifier()]
		if ok && requestorScheme != nil {
			path := requestor.ResolveLogoPath(requestorScheme)
			requestor.LogoPath = &path
		}
	}

	irmaConfig := client.GetIrmaConfiguration()

	switch entry.Type {
	case irma.ActionDisclosing, irma.ActionSigning:
		attributes, err := entry.GetDisclosedCredentials(irmaConfig)
		if err != nil {
			return LogInfo{}, err
		}
		credLog, err := disclosedAttributesToLogCredentials(irmaConfig, attributes)
		if err != nil {
			return LogInfo{}, err
		}
		disclosureLog := &DisclosureLog{
			Protocol:    irmaclient.Protocol_Irma,
			Credentials: credLog,
			Verifier:    requestor,
		}

		if entry.Type == irma.ActionSigning {
			return LogInfo{
				ID:   entry.ID,
				Type: irmaclient.LogType_Signature,
				Time: entry.Time,
				SignedMessageLog: &SignedMessageLog{
					Message:       string(entry.SignedMessage),
					DisclosureLog: *disclosureLog,
				},
			}, nil
		}
		return LogInfo{
			ID:            entry.ID,
			Type:          irmaclient.LogType_Disclosure,
			Time:          entry.Time,
			DisclosureLog: disclosureLog,
		}, nil

	case irma.ActionIssuing:
		attributes, err := entry.GetDisclosedCredentials(irmaConfig)
		if err != nil {
			return LogInfo{}, err
		}
		credLog, err := disclosedAttributesToLogCredentials(irmaConfig, attributes)
		if err != nil {
			return LogInfo{}, err
		}
		issued, err := entry.GetIssuedCredentials(irmaConfig)
		if err != nil {
			return LogInfo{}, err
		}
		issuedLog, err := issuedCredentialsToLogCredentials(irmaConfig, issued)
		if err != nil {
			return LogInfo{}, err
		}
		return LogInfo{
			ID:   entry.ID,
			Time: entry.Time,
			Type: irmaclient.LogType_Issuance,
			IssuanceLog: &IssuanceLog{
				Protocol:             irmaclient.Protocol_Irma,
				Credentials:          issuedLog,
				DisclosedCredentials: credLog,
				Issuer:               requestor,
			},
		}, nil

	case irmaclient.ActionRemoval:
		removedCreds := []LogCredential{}

		for credentialTypeId, attributeValues := range entry.Removed {
			credTypeInfo := irmaConfig.CredentialTypes[credentialTypeId]
			issuer := irmaConfig.Issuers[credTypeInfo.IssuerIdentifier()]

			formats := make([]CredentialFormat, len(entry.RemovedFormats))
			for i, f := range entry.RemovedFormats {
				formats[i] = CredentialFormat(f)
			}

			attributes := []Attribute{}
			for index, atType := range credTypeInfo.AttributeTypes {
				if atType.RevocationAttribute {
					continue
				}
				tsVal := TranslatedString(attributeValues[index])
				attributes = append(attributes, Attribute{
					Id:          atType.ID,
					DisplayName: TranslatedString(atType.Name),
					Description: TranslatedString(atType.Description),
					Value: &AttributeValue{
						Type:             displayHintToAttributeType(atType.DisplayHint),
						TranslatedString: &tsVal,
					},
				})
			}

			removedCreds = append(removedCreds, LogCredential{
				CredentialId: credentialTypeId.String(),
				Formats:      formats,
				ImagePath:    credTypeInfo.Logo(irmaConfig),
				Name:         TranslatedString(credTypeInfo.Name),
				Issuer: TrustedParty{
					Id:   issuer.Identifier().String(),
					Name: TranslatedString(issuer.Name),
				},
				Attributes: attributes,
				IssueURL:   convertOptionalTranslatedString(credTypeInfo.IssueURL),
			})
		}
		return LogInfo{
			ID:   entry.ID,
			Time: entry.Time,
			Type: irmaclient.LogType_CredentialRemoval,
			RemovalLog: &RemovalLog{
				Credentials: removedCreds,
			},
		}, nil
	}

	return LogInfo{}, nil
}

// disclosedAttributesToLogCredentials converts IRMA disclosed attributes to LogCredential list.
// Attributes are ordered per the credential type definition.
func disclosedAttributesToLogCredentials(irmaConfig *irma.Configuration, attributes [][]*irma.DisclosedAttribute) ([]LogCredential, error) {
	// Group disclosed attributes by credential type, preserving per-attr metadata
	grouped := map[irma.CredentialTypeIdentifier]map[string]*irma.DisclosedAttribute{}
	issuanceTimes := map[irma.CredentialTypeIdentifier]int64{}

	for _, con := range attributes {
		for _, attr := range con {
			credTypeId := attr.Identifier.CredentialTypeIdentifier()
			if _, ok := grouped[credTypeId]; !ok {
				grouped[credTypeId] = map[string]*irma.DisclosedAttribute{}
				issuanceTimes[credTypeId] = time.Time(attr.IssuanceTime).Unix()
			}
			grouped[credTypeId][attr.Identifier.Name()] = attr
		}
	}

	result := []LogCredential{}
	for credTypeId, disclosedByName := range grouped {
		credTypeInfo := irmaConfig.CredentialTypes[credTypeId]
		issuer := irmaConfig.Issuers[credTypeInfo.IssuerIdentifier()]

		// Build attributes in schema-defined order, only for those that were disclosed
		attributes := []Attribute{}
		for _, atType := range credTypeInfo.AttributeTypes {
			if atType.RevocationAttribute {
				continue
			}
			attr, disclosed := disclosedByName[atType.ID]
			if !disclosed {
				continue
			}
			tsVal := TranslatedString(attr.Value)
			attributes = append(attributes, Attribute{
				Id:          atType.ID,
				DisplayName: TranslatedString(atType.Name),
				Description: TranslatedString(atType.Description),
				Value: &AttributeValue{
					Type:             displayHintToAttributeType(atType.DisplayHint),
					TranslatedString: &tsVal,
				},
			})
		}

		result = append(result, LogCredential{
			CredentialId: credTypeId.String(),
			Formats:      []CredentialFormat{irmaclient.Format_Idemix},
			ImagePath:    credTypeInfo.Logo(irmaConfig),
			Name:         TranslatedString(credTypeInfo.Name),
			Issuer: TrustedParty{
				Id:   issuer.Identifier().String(),
				Name: TranslatedString(issuer.Name),
			},
			Attributes:   attributes,
			IssuanceDate: issuanceTimes[credTypeId],
			IssueURL:     convertOptionalTranslatedString(credTypeInfo.IssueURL),
		})
	}
	return result, nil
}

// issuedCredentialsToLogCredentials converts an IRMA credential info list to LogCredential list.
func issuedCredentialsToLogCredentials(irmaConfig *irma.Configuration, creds irma.CredentialInfoList) ([]LogCredential, error) {
	result := []LogCredential{}
	for _, cred := range creds {
		if cred == nil {
			continue
		}

		credTypeId := cred.Identifier()
		credTypeInfo := irmaConfig.CredentialTypes[credTypeId]
		issuer := irmaConfig.Issuers[credTypeInfo.IssuerIdentifier()]

		formats := []CredentialFormat{irmaclient.Format_Idemix}
		if cred.InstanceCount != nil && *cred.InstanceCount > 0 {
			formats = append(formats, irmaclient.Format_SdJwtVc)
		}

		attributes := []Attribute{}
		for _, atType := range credTypeInfo.AttributeTypes {
			if atType.RevocationAttribute {
				continue
			}
			attrVal := TranslatedString(cred.Attributes[atType.GetAttributeTypeIdentifier()])
			attributes = append(attributes, Attribute{
				Id:          atType.ID,
				DisplayName: TranslatedString(atType.Name),
				Description: TranslatedString(atType.Description),
				Value: &AttributeValue{
					Type:             displayHintToAttributeType(atType.DisplayHint),
					TranslatedString: &attrVal,
				},
			})
		}

		result = append(result, LogCredential{
			CredentialId: credTypeId.String(),
			Formats:      formats,
			ImagePath:    credTypeInfo.Logo(irmaConfig),
			Name:         TranslatedString(credTypeInfo.Name),
			Issuer: TrustedParty{
				Id:   issuer.Identifier().String(),
				Name: TranslatedString(issuer.Name),
			},
			Attributes:          attributes,
			IssuanceDate:        time.Time(cred.SignedOn).Unix(),
			ExpiryDate:          time.Time(cred.Expires).Unix(),
			Revoked:             cred.Revoked,
			RevocationSupported: cred.RevocationSupported,
			IssueURL:            convertOptionalTranslatedString(credTypeInfo.IssueURL),
		})
	}
	return result, nil
}

// openid4vpCredentialLogsToLogCredentials converts stored SD-JWT credential logs (name→value map)
// to LogCredential list, enriched with display metadata from irmaConfig.
func openid4vpCredentialLogsToLogCredentials(irmaConfig *irma.Configuration, logs []irmaclient.CredentialLog) []LogCredential {
	result := []LogCredential{}
	for _, log := range logs {
		credTypeId := irma.NewCredentialTypeIdentifier(log.CredentialType)
		credTypeInfo := irmaConfig.CredentialTypes[credTypeId]
		issuer := irmaConfig.Issuers[credTypeInfo.IssuerIdentifier()]

		formats := make([]CredentialFormat, len(log.Formats))
		for i, f := range log.Formats {
			formats[i] = CredentialFormat(f)
		}

		attributes := []Attribute{}
		for _, atType := range credTypeInfo.AttributeTypes {
			if atType.RevocationAttribute {
				continue
			}
			rawVal, disclosed := log.Attributes[atType.ID]
			if !disclosed {
				continue
			}
			v := rawVal
			tsVal := TranslatedString(irma.NewTranslatedString(&v))
			attributes = append(attributes, Attribute{
				Id:          atType.ID,
				DisplayName: TranslatedString(atType.Name),
				Description: TranslatedString(atType.Description),
				Value: &AttributeValue{
					Type:             displayHintToAttributeType(atType.DisplayHint),
					TranslatedString: &tsVal,
				},
			})
		}

		result = append(result, LogCredential{
			CredentialId: log.CredentialType,
			Formats:      formats,
			ImagePath:    credTypeInfo.Logo(irmaConfig),
			Name:         TranslatedString(credTypeInfo.Name),
			Issuer: TrustedParty{
				Id:   issuer.Identifier().String(),
				Name: TranslatedString(issuer.Name),
			},
			Attributes: attributes,
			IssueURL:   convertOptionalTranslatedString(credTypeInfo.IssueURL),
		})
	}
	return result
}

func (client *Client) rawLogEntriesToLogInfo(entries []*irmaclient.LogEntry) ([]LogInfo, error) {
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

func (client *Client) SetPreferences(prefs clientsettings.Preferences) {
	client.irmaClient.SetPreferences(prefs)
	if prefs.DeveloperMode {
		client.openid4vciClient.Configuration.SetCertificateVerificationMode(eudi.DeveloperModeCertificateVerification)
		client.openid4vpClient.Configuration.EnableStagingTrustAnchors()

		if err := client.openid4vpClient.Configuration.Reload(); err != nil {
			common.Logger.Warnf("error while reloading eudi config: %v", err)
		}
		if err := client.openid4vpClient.Configuration.UpdateCertificateRevocationLists(); err != nil {
			common.Logger.Warnf("error while updating CRLs: %v", err)
		}
	}
}

func (client *Client) GetPreferences() clientsettings.Preferences {
	return client.irmaClient.Preferences
}

func (client *Client) InitJobs(eudiRevocationListUpdateInterval time.Duration) {
	// Future TODO: add Context so we can check for cancellation of the job ?
	_, err := client.scheduler.NewJob(
		gocron.DurationJob(eudiRevocationListUpdateInterval),
		gocron.NewTask(client.openid4vpClient.Configuration.UpdateCertificateRevocationLists),
		gocron.WithStartAt(gocron.WithStartImmediately()),
	)

	if err != nil {
		common.Logger.Warnf("failed to create new cron job for updating CLRs: %v", err)
	}
}
