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
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/eudi_sdjwt_dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/irma_sdjwt_dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/internal/clientstorage"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

type Client struct {
	storage          *clientstorage.Storage
	eudiStorage      storage.Storage
	sdjwtvcStorage   irmaclient.SdJwtVcStorage
	openid4vpClient  *openid4vp.Client
	openid4vciClient *openid4vci.Client
	irmaClient       *irmaclient.IrmaClient
	logsStorage      irmaclient.LogsStorage
	keyBinder        sdjwtvc.KeyBinder
	didValidator     *openid4vp.DidVerifierValidator
	scheduler        gocron.Scheduler
	sessionManager   sessionManager
	// TODO: move preferences from IrmaClient to here
	//Preferences      clientsettings.Preferences
}

func New(
	storagePath string,
	irmaConfigurationPath string,
	eudiAppDataPath string,
	handler irmaclient.ClientHandler,
	sessionHandler clientmodels.SessionHandler,
	signer irmaclient.Signer,
	aesKey [32]byte,
) (*Client, error) {
	if err := common.AssertPathExists(storagePath); err != nil {
		return nil, err
	}
	if err := common.AssertPathExists(irmaConfigurationPath); err != nil {
		return nil, err
	}
	if err := common.EnsureDirectoryExists(eudiAppDataPath); err != nil {
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

	// Create the encryption middleware, used for all storage components, so that all data is encrypted at rest
	encryptionMiddleware := encryption.NewAESEncryptionMiddleware(aesKey)

	// Create the EUDI storage (will be used by both the OpenID4VP and OpenID4VCI clients later)
	dbPath := filepath.Join(eudiAppDataPath, storage.DbFilename)
	eudiStorage, err := storage.NewStorage(aesKey, encryptionMiddleware, dbPath, eudiAppDataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate eudi storage: %v", err)
	}

	eudiConf, err := eudi.NewConfiguration(eudiStorage)
	if err != nil {
		return nil, fmt.Errorf("instantiating eudi configuration failed: %v", err)
	}

	// Initialize DB storage
	s := clientstorage.NewStorage(storagePath, encryptionMiddleware)
	irmaStorage := irmaclient.NewIrmaStorage(s, irmaConf)

	// Ensure storage path exists, and populate it with necessary files
	if err = s.Open(); err != nil {
		return nil, fmt.Errorf("failed to open irma storage: %v", err)
	}

	keyBindingStorage := irmaclient.NewBboltKeyBindingStorage(s)
	irmaKeyBinder := sdjwtvc.NewDefaultKeyBinder(keyBindingStorage)

	// Verifier verification checks if the verifier is trusted
	x509Validator := openid4vp.NewRequestorCertificateStoreVerifierValidator(&eudiConf.Verifiers, &openid4vp.DefaultQueryValidatorFactory{})
	didValidator := openid4vp.NewDidVerifierValidator(false)
	verifierValidator := openid4vp.NewCompositeVerifierValidator(x509Validator, didValidator)
	sdjwtvcStorage := irmaclient.NewBboltSdJwtVcStorage(s)

	// Register the EUDI SD-JWT handler for credentials issued via OID4VCI
	eudiSdJwtDcqlHandler := eudi_sdjwt_dcql.NewSdJwtVcDcqlHandler(eudiStorage)
	irmaSdJwtDcqlHandler := irma_sdjwt_dcql.NewIrmaSdJwtVcDcqlHandler(sdjwtvcStorage, irmaConf, irmaKeyBinder)

	openid4vpClient, err := openid4vp.NewClient(eudiConf, []dcql.DcqlCredentialQueryHandler{irmaSdJwtDcqlHandler, eudiSdJwtDcqlHandler}, verifierValidator)
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

	irmaClient, err := irmaclient.NewIrmaClient(irmaConf, handler, signer, irmaStorage, sdJwtVcVerificationContext, sdjwtvcStorage, irmaKeyBinder)
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
	openid4vciClient, err := openid4vci.NewClient(
		&http.Client{},
		eudiConf,
		sdjwtvc.NewHolderVerificationProcessor(sdJwtVcVerificationContextOpenId4Vci),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to instantiate openid4vci client: %v", err)
	}

	// When IRMA issuance sessions are done, an inprogress OpenID4VP session
	// should again ask for verification permission,
	// so we do this by listening for session-done events
	irmaClient.SetOnSessionDoneCallback(openid4vpClient.RefreshPendingPermissionRequest)

	client := &Client{
		storage:          s,
		sdjwtvcStorage:   sdjwtvcStorage,
		eudiStorage:      eudiStorage,
		openid4vpClient:  openid4vpClient,
		openid4vciClient: openid4vciClient,
		irmaClient:       irmaClient,
		logsStorage:      irmaStorage,
		keyBinder:        irmaKeyBinder,
		didValidator:     didValidator,
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
	client.eudiStorage.Close()
	return client.storage.Close()
}

type SessionRequestData struct {
	irma.Qr
	Protocol               clientmodels.Protocol `json:"protocol,omitempty"`
	ContinueOnSecondDevice bool                  `json:"continue_on_second_device"`
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
		CredentialFormat:    clientmodels.Format_SdJwtVc,
		InstanceCount:       &metadata.RemainingInstanceCount,
	}
}

func (client *Client) getIrmaCredentialInfoList() irma.CredentialInfoList {
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

func (client *Client) RemoveCredentialsByHash(hashByFormat map[clientmodels.CredentialFormat]string) error {
	// Partition hashes into those found in IRMA storage vs those in EUDI storage.
	allIrmaCreds := client.getIrmaCredentialInfoList()
	irmaRelevantCreds := []*irma.CredentialInfo{}
	eudiHashes := map[clientmodels.CredentialFormat]string{}

	for format, hash := range hashByFormat {
		idx := slices.IndexFunc(allIrmaCreds, func(info *irma.CredentialInfo) bool {
			return info.Hash == hash
		})
		if idx >= 0 {
			irmaRelevantCreds = append(irmaRelevantCreds, allIrmaCreds[idx])
		} else {
			eudiHashes[format] = hash
		}
	}

	if len(irmaRelevantCreds) == 0 && len(eudiHashes) == 0 {
		return fmt.Errorf("trying to delete credential that doesn't exist")
	}

	// Validate that all IRMA-side credentials refer to the same credential+attributes combo.
	if len(irmaRelevantCreds) > 0 {
		if same, err := sameCredentialAndAttributesCombi(irmaRelevantCreds); !same || err != nil {
			if !same {
				return fmt.Errorf("deleting two different credential instances at once is not supported")
			}
			return fmt.Errorf("error while comparing credential attributes: %v", err)
		}
	}

	// Delete IRMA credentials (existing path).
	irmaFormats := []clientmodels.CredentialFormat{}
	for format, hash := range hashByFormat {
		if _, isEudi := eudiHashes[format]; isEudi {
			continue
		}
		irmaFormats = append(irmaFormats, format)
		if format == clientmodels.Format_Idemix {
			if err := client.irmaClient.RemoveCredentialByHash(hash); err != nil {
				return err
			}
		}
		if format == clientmodels.Format_SdJwtVc {
			holderPubKeys, err := client.sdjwtvcStorage.RemoveCredentialByHash(hash)
			if err != nil {
				return fmt.Errorf("error while deleting sdjwtvc credential: %v", err)
			}
			if err = client.keyBinder.RemovePrivateKeys(holderPubKeys); err != nil {
				return fmt.Errorf("failed to remove holder private keys: %v", err)
			}
		}
	}

	// Delete EUDI credentials (read metadata first for the removal log).
	if len(eudiHashes) > 0 {
		credentialService := services.NewCredentialService(client.eudiStorage)
		allEudiCreds, err := credentialService.GetCredentialMetadataList()
		if err != nil {
			return fmt.Errorf("failed to read eudi credentials for removal log: %v", err)
		}

		// Find the credentials being deleted.
		hashSet := map[string]struct{}{}
		for _, h := range eudiHashes {
			hashSet[h] = struct{}{}
		}
		var removedCreds []*clientmodels.Credential
		for _, c := range allEudiCreds {
			if _, ok := hashSet[c.Hash]; ok {
				removedCreds = append(removedCreds, c)
			}
		}

		credentialStore := db.NewCredentialStore(client.eudiStorage.Db())
		for _, hash := range eudiHashes {
			if err := credentialStore.DeleteBatchByHash(hash); err != nil {
				return fmt.Errorf("error while deleting eudi credential: %v", err)
			}
		}

		// Create removal log for EUDI credentials.
		if len(removedCreds) > 0 {
			logService := services.NewEudiLogService(client.eudiStorage)
			if err := logService.AddRemovalLog(removedCreds); err != nil {
				return fmt.Errorf("failed to create eudi removal log: %v", err)
			}
		}
	}

	// Create removal log for IRMA credentials.
	if len(irmaRelevantCreds) > 0 {
		info := irmaRelevantCreds[0]
		logEntry, err := createRemovalLog(client.GetIrmaConfiguration(), info.Identifier(), info.Attributes, irmaFormats)
		if err != nil {
			return fmt.Errorf("failed to create delete log: %v", err)
		}
		return client.logsStorage.AddLogEntry(logEntry)
	}

	return nil
}

func createRemovalLog(
	irmaConfiguration *irma.Configuration,
	credentialType irma.CredentialTypeIdentifier,
	attributes map[irma.AttributeTypeIdentifier]irma.TranslatedString,
	formats []clientmodels.CredentialFormat,
) (*irmaclient.LogEntry, error) {
	attrs := []irma.TranslatedString{}

	// loop over it in display order
	for _, t := range sortedAttributeTypes(irmaConfiguration.CredentialTypes[credentialType].AttributeTypes) {
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

	client.sessionManager.Clear()

	return client.irmaClient.RemoveStorage()
}

func (client *Client) LoadNewestLogs(max int) ([]clientmodels.LogInfo, error) {
	// Load IRMA logs from bbolt.
	rawLogs, err := client.irmaClient.LoadNewestLogs(max)
	if err != nil {
		return nil, err
	}
	irmaLogs, err := client.rawLogEntriesToLogInfo(rawLogs)
	if err != nil {
		return nil, err
	}

	// Load EUDI logs from SQLCipher.
	logService := services.NewEudiLogService(client.eudiStorage)
	eudiLogs, err := logService.GetNewestLogs(max)
	if err != nil {
		return nil, err
	}

	return mergeLogsByTime(irmaLogs, eudiLogs, max), nil
}

func (client *Client) LoadLogsBefore(beforeIndex uint64, max int) ([]clientmodels.LogInfo, error) {
	rawLogs, err := client.irmaClient.LoadLogsBefore(beforeIndex, max)
	if err != nil {
		return nil, err
	}
	return client.rawLogEntriesToLogInfo(rawLogs)
}

// mergeLogsByTime merges two log slices (each already sorted newest-first) into
// a single newest-first slice of at most max entries.
func mergeLogsByTime(a, b []clientmodels.LogInfo, max int) []clientmodels.LogInfo {
	merged := append(a, b...)
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].Time.After(merged[j].Time)
	})
	if len(merged) > max {
		merged = merged[:max]
	}
	return merged
}

func (client *Client) rawLogEntryToLogInfo(entry *irmaclient.LogEntry) (clientmodels.LogInfo, error) {
	// NOTE: iOS builds change the container ID of the app, meaning that after every compilation/app update the location
	// of all app data changes. Logs store an absolute path to requestor logo's, which becomes invalid when the data is moved,
	// resulting in the logo's not being found for existing logs when an iOS app is updated.
	// Solving this issue correctly would require a deep refactor of many components and would likely introduce some very obscure bugs.
	// This hacky solution works around the issue by assuming the image path to be invalid and resolving it based on other information:
	//  - For OpenID4VP sessions the logo path is resolved based on the image name
	//  - For IRMA sessions the logo path is resolved based on the requestor ID and using the requestor schemes
	requestor := entry.ServerName

	if entry.OpenID4VP != nil {
		verifier := requestorInfoToTrustedPartyPtr(requestor)

		if requestor != nil && requestor.Logo != nil {
			data, err := client.openid4vpClient.Configuration.ResolveVerifierLogo(*requestor.Logo)
			if err == nil {
				verifier.Image = &clientmodels.Image{
					Base64: *data,
				}
			}
		}

		return clientmodels.LogInfo{
			ID:   entry.ID,
			Type: clientmodels.LogType_Disclosure,
			Time: time.Time(entry.Time),
			DisclosureLog: &clientmodels.DisclosureLog{
				Protocol:    clientmodels.Protocol_OpenID4VP,
				Credentials: openid4vpCredentialLogsToLogCredentials(client.GetIrmaConfiguration(), entry.OpenID4VP.DisclosedCredentials),
				Verifier:    verifier,
			},
		}, nil
	}

	// resolve the image for an irma session
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
			return clientmodels.LogInfo{}, err
		}
		credLog, err := disclosedAttributesToLogCredentials(irmaConfig, attributes)
		if err != nil {
			return clientmodels.LogInfo{}, err
		}
		disclosureLog := &clientmodels.DisclosureLog{
			Protocol:    clientmodels.Protocol_Irma,
			Credentials: credLog,
			Verifier:    requestorInfoToTrustedPartyPtr(requestor),
		}

		if entry.Type == irma.ActionSigning {
			return clientmodels.LogInfo{
				ID:   entry.ID,
				Type: clientmodels.LogType_Signature,
				Time: time.Time(entry.Time),
				SignedMessageLog: &clientmodels.SignedMessageLog{
					Message:       string(entry.SignedMessage),
					DisclosureLog: *disclosureLog,
				},
			}, nil
		}
		return clientmodels.LogInfo{
			ID:            entry.ID,
			Type:          clientmodels.LogType_Disclosure,
			Time:          time.Time(entry.Time),
			DisclosureLog: disclosureLog,
		}, nil

	case irma.ActionIssuing:
		attributes, err := entry.GetDisclosedCredentials(irmaConfig)
		if err != nil {
			return clientmodels.LogInfo{}, err
		}
		credLog, err := disclosedAttributesToLogCredentials(irmaConfig, attributes)
		if err != nil {
			return clientmodels.LogInfo{}, err
		}
		issued, err := entry.GetIssuedCredentials(irmaConfig)
		if err != nil {
			return clientmodels.LogInfo{}, err
		}
		issuedLog, err := issuedCredentialsToLogCredentials(irmaConfig, issued)
		if err != nil {
			return clientmodels.LogInfo{}, err
		}
		return clientmodels.LogInfo{
			ID:   entry.ID,
			Time: time.Time(entry.Time),
			Type: clientmodels.LogType_Issuance,
			IssuanceLog: &clientmodels.IssuanceLog{
				Protocol:             clientmodels.Protocol_Irma,
				Credentials:          issuedLog,
				DisclosedCredentials: credLog,
				Issuer:               requestorInfoToTrustedPartyPtr(requestor),
			},
		}, nil

	case irmaclient.ActionRemoval:
		removedCreds := []clientmodels.LogCredential{}

		for credentialTypeId, attributeValues := range entry.Removed {
			credTypeInfo := irmaConfig.CredentialTypes[credentialTypeId]
			issuer := irmaConfig.Issuers[credTypeInfo.IssuerIdentifier()]

			formats := make([]clientmodels.CredentialFormat, len(entry.RemovedFormats))
			for i, f := range entry.RemovedFormats {
				formats[i] = clientmodels.CredentialFormat(f)
			}

			attributes := []clientmodels.Attribute{}
			for _, atType := range sortedAttributeTypes(credTypeInfo.AttributeTypes) {
				if atType.RevocationAttribute {
					continue
				}
				rawVal := irma.TranslatedString(attributeValues[atType.Index])
				description := clientmodels.TranslatedString(atType.Description)
				name := clientmodels.TranslatedString(atType.Name)
				attributes = append(attributes, clientmodels.Attribute{
					ClaimPath:   []any{atType.ID},
					DisplayName: &name,
					Description: &description,
					Value:       buildAttributeValue(atType.DisplayHint, &rawVal),
				})
			}

			removedCreds = append(removedCreds, clientmodels.LogCredential{
				CredentialId: credentialTypeId.String(),
				Formats:      formats,
				ImagePath:    credTypeInfo.Logo(irmaConfig),
				Name:         clientmodels.TranslatedString(credTypeInfo.Name),
				Issuer: clientmodels.TrustedParty{
					Id:   issuer.Identifier().String(),
					Name: clientmodels.TranslatedString(issuer.Name),
				},
				Attributes: attributes,
				IssueURL:   convertOptionalTranslatedString(credTypeInfo.IssueURL),
			})
		}
		return clientmodels.LogInfo{
			ID:   entry.ID,
			Time: time.Time(entry.Time),
			Type: clientmodels.LogType_CredentialRemoval,
			RemovalLog: &clientmodels.RemovalLog{
				Credentials: removedCreds,
			},
		}, nil
	}

	return clientmodels.LogInfo{}, nil
}

// disclosedAttributesToLogCredentials converts IRMA disclosed attributes to LogCredential list.
// Attributes are ordered per the credential type definition.
func disclosedAttributesToLogCredentials(irmaConfig *irma.Configuration, attributes [][]*irma.DisclosedAttribute) ([]clientmodels.LogCredential, error) {
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

	result := []clientmodels.LogCredential{}
	for credTypeId, disclosedByName := range grouped {
		credTypeInfo := irmaConfig.CredentialTypes[credTypeId]
		issuer := irmaConfig.Issuers[credTypeInfo.IssuerIdentifier()]

		// Build attributes in display order, only for those that were disclosed
		attributes := []clientmodels.Attribute{}
		for _, atType := range sortedAttributeTypes(credTypeInfo.AttributeTypes) {
			if atType.RevocationAttribute {
				continue
			}
			attr, disclosed := disclosedByName[atType.ID]
			if !disclosed {
				continue
			}
			rawVal := irma.TranslatedString(attr.Value)
			description := clientmodels.TranslatedString(atType.Description)
			name := clientmodels.TranslatedString(atType.Name)
			attributes = append(attributes, clientmodels.Attribute{
				ClaimPath:   []any{atType.ID},
				DisplayName: &name,
				Description: &description,
				Value:       buildAttributeValue(atType.DisplayHint, &rawVal),
			})
		}

		result = append(result, clientmodels.LogCredential{
			CredentialId: credTypeId.String(),
			Formats:      []clientmodels.CredentialFormat{clientmodels.Format_Idemix},
			ImagePath:    credTypeInfo.Logo(irmaConfig),
			Name:         clientmodels.TranslatedString(credTypeInfo.Name),
			Issuer:       buildIssuerTrustedParty(irmaConfig, issuer),
			Attributes:   attributes,
			IssuanceDate: issuanceTimes[credTypeId],
			IssueURL:     convertOptionalTranslatedString(credTypeInfo.IssueURL),
		})
	}
	return result, nil
}

// issuedCredentialsToLogCredentials converts an IRMA credential info list to LogCredential list.
func issuedCredentialsToLogCredentials(irmaConfig *irma.Configuration, creds irma.CredentialInfoList) ([]clientmodels.LogCredential, error) {
	result := []clientmodels.LogCredential{}
	for _, cred := range creds {
		if cred == nil {
			continue
		}

		credTypeId := cred.Identifier()
		credTypeInfo := irmaConfig.CredentialTypes[credTypeId]
		issuer := irmaConfig.Issuers[credTypeInfo.IssuerIdentifier()]

		formats := []clientmodels.CredentialFormat{clientmodels.Format_Idemix}
		if cred.InstanceCount != nil && *cred.InstanceCount > 0 {
			formats = append(formats, clientmodels.Format_SdJwtVc)
		}

		attributes := []clientmodels.Attribute{}
		for _, atType := range sortedAttributeTypes(credTypeInfo.AttributeTypes) {
			if atType.RevocationAttribute {
				continue
			}
			rawVal := irma.TranslatedString(cred.Attributes[atType.GetAttributeTypeIdentifier()])
			description := clientmodels.TranslatedString(atType.Description)
			name := clientmodels.TranslatedString(atType.Name)
			attributes = append(attributes, clientmodels.Attribute{
				ClaimPath:   []any{atType.ID},
				DisplayName: &name,
				Description: &description,
				Value:       buildAttributeValue(atType.DisplayHint, &rawVal),
			})
		}

		result = append(result, clientmodels.LogCredential{
			CredentialId:        credTypeId.String(),
			Formats:             formats,
			ImagePath:           credTypeInfo.Logo(irmaConfig),
			Name:                clientmodels.TranslatedString(credTypeInfo.Name),
			Issuer:              buildIssuerTrustedParty(irmaConfig, issuer),
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
func openid4vpCredentialLogsToLogCredentials(irmaConfig *irma.Configuration, logs []irmaclient.CredentialLog) []clientmodels.LogCredential {
	result := []clientmodels.LogCredential{}
	for _, log := range logs {
		credTypeId := irma.NewCredentialTypeIdentifier(log.CredentialType)
		credTypeInfo := irmaConfig.CredentialTypes[credTypeId]
		issuer := irmaConfig.Issuers[credTypeInfo.IssuerIdentifier()]

		formats := make([]clientmodels.CredentialFormat, len(log.Formats))
		for i, f := range log.Formats {
			formats[i] = clientmodels.CredentialFormat(f)
		}

		attributes := []clientmodels.Attribute{}
		for _, atType := range sortedAttributeTypes(credTypeInfo.AttributeTypes) {
			if atType.RevocationAttribute {
				continue
			}
			rawVal, disclosed := log.Attributes[atType.ID]
			if !disclosed {
				continue
			}
			v := rawVal
			irmaVal := irma.NewTranslatedString(&v)
			description := clientmodels.TranslatedString(atType.Description)
			name := clientmodels.TranslatedString(atType.Name)
			attributes = append(attributes, clientmodels.Attribute{
				ClaimPath:   []any{atType.ID},
				DisplayName: &name,
				Description: &description,
				Value:       buildAttributeValue(atType.DisplayHint, &irmaVal),
			})
		}

		result = append(result, clientmodels.LogCredential{
			CredentialId: log.CredentialType,
			Formats:      formats,
			ImagePath:    credTypeInfo.Logo(irmaConfig),
			Name:         clientmodels.TranslatedString(credTypeInfo.Name),
			Issuer:       buildIssuerTrustedParty(irmaConfig, issuer),
			Attributes:   attributes,
			IssueURL:     convertOptionalTranslatedString(credTypeInfo.IssueURL),
		})
	}
	return result
}

func (client *Client) rawLogEntriesToLogInfo(entries []*irmaclient.LogEntry) ([]clientmodels.LogInfo, error) {
	result := []clientmodels.LogInfo{}
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
		client.openid4vciClient.AllowInsecureHttpForTesting()
		client.openid4vciClient.Configuration.SetCertificateVerificationMode(eudi.DeveloperModeCertificateVerification)
		client.didValidator.SetAllowInsecureDidWeb(true)
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
