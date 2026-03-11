package client

import (
	"encoding/json"
	"fmt"
	"maps"
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
	// TODO: move preferences from IrmaClient to here
	//Preferences      clientsettings.Preferences
}

func New(
	storagePath string,
	irmaConfigurationPath string,
	handler irmaclient.ClientHandler,
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
	openid4vciClient := irmaclient.NewOpenID4VciClient(&http.Client{}, eudiConf, sdjwtvcStorage, sdjwtvc.NewHolderVerificationProcessor(sdJwtVcVerificationContextOpenId4Vci), keyBinder)

	// When IRMA issuance sessions are done, an inprogress OpenID4VP session
	// should again ask for verification permission,
	// so we do this by listening for session-done events
	irmaClient.SetOnSessionDoneCallback(openid4vpClient.RefreshPendingPermissionRequest)

	return &Client{
		storage:          storage,
		sdjwtvcStorage:   sdjwtvcStorage,
		openid4vpClient:  openid4vpClient,
		openid4vciClient: openid4vciClient,
		irmaClient:       irmaClient,
		logsStorage:      irmaStorage,
		keyBinder:        keyBinder,
		scheduler:        scheduler,
	}, nil
}

func (client *Client) Close() error {
	client.scheduler.Shutdown()
	client.irmaClient.Close()
	return client.storage.Close()
}

type SessionRequestData struct {
	irma.Qr
	Protocol irmaclient.Protocol `json:"protocol,omitempty"`
}

func (client *Client) NewSession(sessionrequest string, handler irmaclient.Handler) irmaclient.SessionDismisser {
	var sessionReq SessionRequestData
	err := json.Unmarshal([]byte(sessionrequest), &sessionReq)
	if err != nil {
		irma.Logger.Errorf("failed to parse session request: %v\n", err)
		handler.Failure(nil)
		return nil
	}

	switch sessionReq.Protocol {
	case irmaclient.Protocol_OpenID4VP:
		return client.openid4vpClient.NewSession(sessionReq.URL, handler)
	case irmaclient.Protocol_OpenID4VCI:
		return client.openid4vciClient.NewSession(sessionReq.URL, handler)
	}

	return client.irmaClient.NewSession(sessionrequest, handler)
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

func (client *Client) CredentialInfoList() irma.CredentialInfoList {
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
	allCreds := client.CredentialInfoList()
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

func (client *Client) LoadNewestLogs(max int) ([]irmaclient.LogInfo, error) {
	rawLogs, err := client.irmaClient.LoadNewestLogs(max)
	if err != nil {
		return nil, err
	}
	return client.rawLogEntriesToLogInfo(rawLogs)
}

func (client *Client) LoadLogsBefore(beforeIndex uint64, max int) ([]irmaclient.LogInfo, error) {
	rawLogs, err := client.irmaClient.LoadLogsBefore(beforeIndex, max)
	if err != nil {
		return nil, err
	}
	return client.rawLogEntriesToLogInfo(rawLogs)
}

func (client *Client) rawLogEntryToLogInfo(entry *irmaclient.LogEntry) (irmaclient.LogInfo, error) {
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
		return irmaclient.LogInfo{
			ID:   entry.ID,
			Type: irmaclient.LogType_Disclosure,
			Time: entry.Time,
			DisclosureLog: &irmaclient.DisclosureLog{
				Protocol:    irmaclient.Protocol_OpenID4VP,
				Credentials: entry.OpenID4VP.DisclosedCredentials,
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

	switch entry.Type {
	case irma.ActionDisclosing, irma.ActionSigning:
		attributes, err := entry.GetDisclosedCredentials(client.GetIrmaConfiguration())
		if err != nil {
			return irmaclient.LogInfo{}, err
		}
		credLog, err := disclosedAttributesToCredentialLogs(attributes)
		if err != nil {
			return irmaclient.LogInfo{}, err
		}
		disclosureLog := &irmaclient.DisclosureLog{
			Protocol:    irmaclient.Protocol_Irma,
			Credentials: credLog,
			Verifier:    requestor,
		}

		if entry.Type == irma.ActionSigning {
			return irmaclient.LogInfo{
				ID:   entry.ID,
				Type: irmaclient.LogType_Signature,
				Time: entry.Time,
				SignedMessageLog: &irmaclient.SignedMessageLog{
					Message:       string(entry.SignedMessage),
					DisclosureLog: *disclosureLog,
				},
			}, nil
		}
		return irmaclient.LogInfo{
			ID:            entry.ID,
			Type:          irmaclient.LogType_Disclosure,
			Time:          entry.Time,
			DisclosureLog: disclosureLog,
		}, nil
	case irma.ActionIssuing:
		attributes, err := entry.GetDisclosedCredentials(client.GetIrmaConfiguration())
		if err != nil {
			return irmaclient.LogInfo{}, err
		}
		credLog, err := disclosedAttributesToCredentialLogs(attributes)
		if err != nil {
			return irmaclient.LogInfo{}, err
		}
		issued, err := entry.GetIssuedCredentials(client.GetIrmaConfiguration())
		if err != nil {
			return irmaclient.LogInfo{}, err
		}
		issuedLog, err := issuedCredentialsToCredentialLog(issued)
		if err != nil {
			return irmaclient.LogInfo{}, err
		}
		return irmaclient.LogInfo{
			ID:   entry.ID,
			Time: entry.Time,
			Type: irmaclient.LogType_Issuance,
			IssuanceLog: &irmaclient.IssuanceLog{
				Protocol:             irmaclient.Protocol_Irma,
				Credentials:          issuedLog,
				DisclosedCredentials: credLog,
				Issuer:               requestor,
			},
		}, nil
	case irmaclient.ActionRemoval:
		removedCreds := []irmaclient.CredentialLog{}

		for credentialTypeId, attributeValues := range entry.Removed {
			removed := irmaclient.CredentialLog{
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
		return irmaclient.LogInfo{
			ID:   entry.ID,
			Time: entry.Time,
			Type: irmaclient.LogType_CredentialRemoval,
			RemovalLog: &irmaclient.RemovalLog{
				Credentials: removedCreds,
			},
		}, nil
	}

	return irmaclient.LogInfo{}, nil
}

func issuedCredentialsToCredentialLog(creds irma.CredentialInfoList) ([]irmaclient.CredentialLog, error) {
	result := []irmaclient.CredentialLog{}
	for _, cred := range creds {
		if cred == nil {
			continue
		}
		entry := irmaclient.CredentialLog{
			Formats:        []irmaclient.CredentialFormat{irmaclient.Format_Idemix},
			CredentialType: cred.Identifier().String(),
			Attributes:     map[string]string{},
		}
		if cred.InstanceCount != nil && *cred.InstanceCount > 0 {
			entry.Formats = append(entry.Formats, irmaclient.Format_SdJwtVc)
		}
		for key, attr := range cred.Attributes {
			entry.Attributes[key.Name()] = attr[""]
		}
		result = append(result, entry)
	}
	return result, nil
}

func disclosedAttributesToCredentialLogs(attributes [][]*irma.DisclosedAttribute) ([]irmaclient.CredentialLog, error) {
	result := map[string]irmaclient.CredentialLog{}
	for _, con := range attributes {
		for _, attr := range con {
			credId := attr.Identifier.Parent()

			_, exists := result[credId]
			if exists {
				result[credId].Attributes[attr.Identifier.Name()] = *attr.RawValue
			} else {
				result[credId] = irmaclient.CredentialLog{
					// this function is only used for idemix credentials
					Formats:        []irmaclient.CredentialFormat{irmaclient.Format_Idemix},
					CredentialType: credId,
					Attributes: map[string]string{
						attr.Identifier.Name(): *attr.RawValue,
					},
				}
			}
		}
	}
	return slices.Collect(maps.Values(result)), nil
}

func (client *Client) rawLogEntriesToLogInfo(entries []*irmaclient.LogEntry) ([]irmaclient.LogInfo, error) {
	result := []irmaclient.LogInfo{}
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
