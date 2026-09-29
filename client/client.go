package client

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/eudi_sdjwt_dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/irma_sdjwt_dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/mdoc_dcql"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipherstorage"
	"github.com/privacybydesign/irmago/internal/clientstorage"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/walletprovider"
)

type Client struct {
	storage           *clientstorage.Storage
	eudiStorage       storage.Storage
	sdjwtvcStorage    irmaclient.SdJwtVcStorage
	openid4vpClient   *openid4vp.Client
	openid4vciClient  *openid4vci.Client
	irmaClient        *irmaclient.IrmaClient
	logsStorage       irmaclient.LogsStorage
	keyBinder         sdjwt.KeyBinder
	didValidator      *openid4vp.DidVerifierValidator
	scheduler         gocron.Scheduler
	sessionManager    sessionManager
	credentialFormats services.CredentialFormats
	revocationService *services.RevocationService

	// walletProvider is the wallet's wallet provider, nil when it has none,
	// behind an activationGuard. Every OpenID4VC session gets its own wallet
	// unit session over it; see session.context.
	walletProvider walletprovider.WalletProvider
	// enrollmentPin holds the PIN of a keyshare enrollment in progress.
	enrollmentPin enrollmentPin
	// pinChange holds the PINs of a PIN change in flight.
	pinChange pinChange

	// handler is how the wallet wakes the app when what it has already rendered
	// went stale. Required: IrmaClient calls it unguarded too, so a nil one
	// cannot survive a session.
	handler ClientHandler

	// currentLocale is the locale used to resolve all app-facing text and
	// logos. The app owns it: it supplies the initial value via New and
	// updates it through SetLocale; irmago does not persist it.
	currentLocale *clientmodels.CurrentLocale

	// logoBackfill fetches the logos the current locale resolves to but that
	// were never downloaded, in the background. Closed before eudiStorage.
	logoBackfill *services.LogoBackfiller
	// TODO: move preferences from IrmaClient to here
	//Preferences      clientsettings.Preferences
}

// Config is everything a wallet needs to exist. Named rather than positional
// because three of the paths are plain strings, and transposing two would build a
// wallet that looks fine and stores its data in the wrong place. Every zero value
// takes the documented default.
type Config struct {
	// StoragePath and IrmaConfigurationPath must exist; EudiAppDataPath is created.
	StoragePath           string
	IrmaConfigurationPath string
	EudiAppDataPath       string

	// How the wallet wakes the app when what it rendered went stale. Required:
	// background jobs call it without a nil guard.
	Handler        ClientHandler
	SessionHandler clientmodels.SessionHandler
	Signer         irmaclient.Signer
	AesKey         [32]byte

	// Locale is the initial current locale; see SetLocale.
	Locale string

	// WalletProvider gives the wallet a wallet provider: OpenID4VC credentials
	// are then bound to keys in the provider's HSM, unlocked with the PIN. Nil
	// means none, and credentials are bound with software keys. The app gives
	// the provider its possession key itself, when it builds the factory.
	WalletProvider walletprovider.Factory
}

// walletProviderHost is what the wallet offers its wallet provider.
type walletProviderHost struct {
	storage walletprovider.Storage
}

func (h walletProviderHost) Storage() walletprovider.Storage { return h.storage }

func New(cfg Config) (*Client, error) {
	// Required: the wallet calls it from background jobs and from IrmaClient
	// without a nil guard, so a nil one would panic on a goroutine no caller
	// can recover from. Fail here instead, where the app can see it.
	if cfg.Handler == nil {
		return nil, fmt.Errorf("handler is required")
	}
	if err := common.AssertPathExists(cfg.StoragePath); err != nil {
		return nil, err
	}
	if err := common.AssertPathExists(cfg.IrmaConfigurationPath); err != nil {
		return nil, err
	}
	if err := common.EnsureDirectoryExists(cfg.EudiAppDataPath); err != nil {
		return nil, err
	}

	// Load IRMA + EUDI configuration
	irmaConf, err := irma.NewConfiguration(
		filepath.Join(cfg.StoragePath, "irma_configuration"),
		irma.ConfigurationOptions{Assets: cfg.IrmaConfigurationPath, IgnorePrivateKeys: true},
	)
	if err != nil {
		return nil, fmt.Errorf("instantiating configuration failed: %v", err)
	}

	eudi.Logger = irma.Logger

	currentLocale := clientmodels.NewCurrentLocale(cfg.Locale)

	// Create the encryption middleware, used by the IRMA classic clientstorage so all data is encrypted at rest.
	// The EUDI storage layer derives its own AES middleware (and a separate filename-MAC sub-key) directly from the aesKey.
	encryptionMiddleware := encryption.NewAESEncryptionMiddleware(cfg.AesKey)

	// Create the EUDI storage (will be used by both the OpenID4VP and OpenID4VCI clients later)
	dbPath := filepath.Join(cfg.EudiAppDataPath, storage.DbFilename)
	eudiStorage, err := sqlcipherstorage.New(cfg.AesKey, dbPath, cfg.EudiAppDataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate eudi storage: %v", err)
	}

	eudiConf, err := eudi.NewConfiguration(eudiStorage)
	if err != nil {
		return nil, fmt.Errorf("instantiating eudi configuration failed: %v", err)
	}

	// The wallet provider is built as soon as the storage it keeps its state
	// in exists.
	var walletProvider walletprovider.WalletProvider
	if cfg.WalletProvider != nil {
		walletProvider, err = cfg.WalletProvider(walletProviderHost{
			storage: db.NewWalletProviderStorage(eudiStorage.Db()),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate wallet provider: %v", err)
		}
		walletProvider = &activationGuard{WalletProvider: walletProvider, handler: cfg.Handler}
	}

	// Initialize DB storage
	s := clientstorage.NewStorage(cfg.StoragePath, encryptionMiddleware)
	irmaStorage := irmaclient.NewIrmaStorage(s, irmaConf)

	// Ensure storage path exists, and populate it with necessary files
	if err = s.Open(); err != nil {
		return nil, fmt.Errorf("failed to open irma storage: %v", err)
	}

	keyBindingStorage := irmaclient.NewBboltKeyBindingStorage(s)
	irmaKeyBinder := sdjwt.NewDefaultKeyBinder(keyBindingStorage)

	credStore := db.NewSdJwtVcStore(eudiStorage.Db())

	// Token Status List checker + the single revocation service built on it.
	// The checker is also shared with the holder-side verifier
	// (sdJwtVcVerificationContext below). The revocation service is the one home
	// for revocation: the background sweep, the credential list's flags, and the
	// OpenID4VP disclosure planner's cached Revoked flag all go through it.
	statusListCache := db.NewStatusListCacheStore(eudiStorage.Db())
	statusChecker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: &eudiConf.Issuers,
		Clock:       eudi_jwt.NewSystemClock(),
	}, statusListCache)
	revocationService := services.NewRevocationService(statusChecker, credStore)

	// Rewrite any credential hash still computed without the issuer. Runs before
	// the wallet can be asked about its credentials, because a stale hash makes a
	// re-issuance look like a credential the wallet does not hold, which would
	// silently store a second copy. Idempotent, so it costs one query on a wallet
	// that is already current; a failure here is not fatal, since the wallet works
	// with old-style hashes and only its duplicate detection is degraded.
	if err := services.MigrateCredentialHashes(credStore); err != nil {
		common.Logger.Warnf("could not migrate credential hashes: %v", err)
	}

	// Verifier verification checks if the verifier is trusted
	x509Validator := openid4vp.NewRequestorCertificateStoreVerifierValidator(&eudiConf.Verifiers, &openid4vp.DefaultQueryValidatorFactory{})
	didValidator := openid4vp.NewDidVerifierValidator(false)
	verifierValidator := openid4vp.NewCompositeVerifierValidator(x509Validator, didValidator)
	sdjwtvcStorage := irmaclient.NewBboltSdJwtVcStorage(s)

	// Register the EUDI SD-JWT handler for credentials issued via OID4VCI.
	// The fetchers describe credentials the wallet has never seen so the
	// frontend can tell the user what is missing instead of stalling on a
	// blank permission prompt.
	eudiSdJwtDcqlHandler := eudi_sdjwt_dcql.NewSdJwtVcDcqlHandler(
		eudiStorage,
		credStore,
		typemetadata.NewDefaultVctFetcher(nil),
		typemetadata.NewDefaultIssuerFetcher(nil),
		services.NewHolderBindingKeyService(eudiStorage.Db(), walletProvider),
		currentLocale,
		revocationService,
	)
	irmaSdJwtDcqlHandler := irma_sdjwt_dcql.NewIrmaSdJwtVcDcqlHandler(sdjwtvcStorage, irmaConf, irmaKeyBinder, currentLocale)

	// Register the mso_mdoc handler for credentials issued via OID4VCI (e.g. the AV
	// Blueprint's proof_of_age credential). No fetchers here (unlike the SD-JWT
	// handler above): there's no standardized online discovery document for an mdoc
	// doctype to describe credentials the wallet has never seen.
	// The device key resolver hands back the stored software key, or the wallet
	// provider's reference to a key in its HSM; the holder signer signs either.
	mdocDcqlHandler := mdoc_dcql.NewMdocDcqlHandler(eudiStorage, currentLocale,
		services.NewMdocDeviceKeyResolver(db.NewMdocDeviceKeyStore(eudiStorage.Db())))

	openid4vpClient, err := openid4vp.NewClient(
		eudiConf,
		[]dcql.DcqlCredentialQueryHandler{irmaSdJwtDcqlHandler, eudiSdJwtDcqlHandler, mdocDcqlHandler},
		services.NewHolderSigner(walletProvider),
		verifierValidator,
		currentLocale,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new openid4vp client: %v", err)
	}

	// SD-JWT verification checks if the SD-JWT (and the issuing party) can be trusted
	sdJwtVcVerificationContext := sdjwtvc.SdJwtVcVerificationContext{
		X509VerificationContext: &eudiConf.Issuers,
		Clock:                   eudi_jwt.NewSystemClock(),
		JwtVerifier:             sdjwt.NewJwxJwtVerifier(),
		VerifyVerifiableCredentialTypeInRequestorInfo: true,
		StatusChecker: statusChecker,
	}

	irmaHandler := newIrmaHandler(cfg.Handler)
	irmaClient, err := irmaclient.NewIrmaClient(irmaConf, irmaHandler, cfg.Signer, irmaStorage, sdJwtVcVerificationContext, sdjwtvcStorage, irmaKeyBinder)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate irma client: %v", err)
	}

	// The developer mode preference is persisted, so a client that starts up
	// with it already enabled never passes through SetPreferences. Apply the
	// same relaxations here, or a restart silently returns the wallet to
	// production-strict behaviour. The configuration half goes before the
	// Reload below: that is what validates the stored chains.
	developerMode := irmaClient.Preferences.DeveloperMode
	setDeveloperModeOnConfiguration(eudiConf, developerMode)

	if err := openid4vpClient.Configuration.Reload(); err != nil {
		return nil, fmt.Errorf("reloading eudi configuration failed: %v", err)
	}

	scheduler, err := gocron.NewScheduler()
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate new scheduler: %v", err)
	}
	scheduler.Start()

	// Fow now, create a new SD-JWT verification context, which skips the VCT check against the requestor info
	sdJwtVcVerificationContextOpenID4VCI := sdjwtvc.SdJwtVcVerificationContext{
		X509VerificationContext: &eudiConf.Issuers,
		Clock:                   eudi_jwt.NewSystemClock(),
		JwtVerifier:             sdjwt.NewJwxJwtVerifier(),
		VerifyVerifiableCredentialTypeInRequestorInfo: false,
		StatusChecker: statusChecker,
	}

	// The per-format registry: how each credential format is verified, which
	// keys it is bound to, and where it is stored. Derived in one place
	// (services.NewCredentialFormats), so adding a format is one entry there and
	// nothing to register here.
	holderVerifier := sdjwtvc.NewHolderVerificationProcessor(sdJwtVcVerificationContextOpenID4VCI)
	credentialFormats := services.NewCredentialFormats(eudiConf, holderVerifier, eudiStorage.Db(), eudiStorage.FileSystem(), revocationService, currentLocale, walletProvider)
	openid4vciClient, err := openid4vci.NewClient(
		common.HTTPClient,
		eudiConf,
		holderVerifier,
		credentialFormats,
		currentLocale,
		services.NewClientAttester(walletProvider),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to instantiate openid4vci client: %v", err)
	}

	setDeveloperModeOnClients(openid4vciClient, didValidator, developerMode)

	// When IRMA issuance sessions are done, an inprogress OpenID4VP session
	// should again ask for verification permission,
	// so we do this by listening for session-done events
	irmaClient.SetOnSessionDoneCallback(openid4vpClient.RefreshPendingPermissionRequest)

	client := &Client{
		storage:           s,
		sdjwtvcStorage:    sdjwtvcStorage,
		eudiStorage:       eudiStorage,
		openid4vpClient:   openid4vpClient,
		openid4vciClient:  openid4vciClient,
		irmaClient:        irmaClient,
		logsStorage:       irmaStorage,
		keyBinder:         irmaKeyBinder,
		didValidator:      didValidator,
		scheduler:         scheduler,
		handler:           cfg.Handler,
		currentLocale:     currentLocale,
		credentialFormats: credentialFormats,
		revocationService: revocationService,
		walletProvider:    walletProvider,
		sessionManager: sessionManager{
			Sessions:       map[int]*session{},
			SessionHandler: cfg.SessionHandler,
		},
	}

	client.sessionManager.Client = client
	// Enrollment activates the wallet unit with the PIN just enrolled with;
	// either way the PIN is not kept.
	irmaHandler.pinChangeEnded = client.keysharePinChangeEnded
	irmaHandler.enrollmentEnded = func(success bool) {
		if pin := client.enrollmentPin.take(); success && pin != "" {
			client.activateWalletUnitInBackground(pin)
		}
	}
	client.logoBackfill = services.NewLogoBackfiller(eudiStorage, common.HTTPClient, func(cached int) {
		// Re-read the credentials the app has already rendered, but only when
		// the sweep put new logos on disk — nothing new, nothing to redraw.
		if cached > 0 {
			client.handler.CredentialsChanged()
		}
	})

	// Startup backfill: fetch logos that resolve for the current locale but
	// are missing from the cache (credentials issued before the wallet became
	// locale-aware, or whose issuance-time download failed).
	client.logoBackfill.Request(currentLocale.Get())

	return client, nil
}

// SetLocale changes the locale used to resolve all app-facing text and logos.
// Non-blocking: text resolves offline from stored metadata on the next pull;
// logos missing for the new locale are fetched by a background backfill that
// signals ClientHandler.CredentialsChanged on completion. Re-setting the locale
// the wallet already uses does nothing.
func (client *Client) SetLocale(locale string) {
	if client.currentLocale.Set(locale) {
		client.logoBackfill.Request(client.currentLocale.Get())
	}
}

// locale returns the current locale for resolving app-facing text and logos.
func (client *Client) locale() string {
	return client.currentLocale.Get()
}

func (client *Client) Close() error {
	// Before the stores close under it, so Close is deterministic and a sweep
	// cannot outlive the database it reads.
	client.logoBackfill.Close()
	client.scheduler.Shutdown()
	client.irmaClient.Close()
	client.eudiStorage.Close()
	return client.storage.Close()
}

// RefreshStatuses re-fetches the Token Status List for one representative
// instance per stored SD-JWT VC batch and updates its LastKnownStatus column.
// Use this on app resume or when the UI exposes an explicit refresh action.
// Errors during the sweep are logged; the previous LastKnownStatus persists for
// any URI that fails to refresh.
//
// A status change signals ClientHandler.CredentialsChanged, on the calling
// goroutine — for the scheduled sweep, the job's own, so a handler that blocks
// delays the next sweep. Re-confirming a status the wallet already had is
// silent.
//
// A cancelled ctx cuts the sweep short but does not suppress the signal: what
// the sweep wrote back before it stopped is committed, and a later sweep sees a
// re-confirmation, so a change dropped here is a change the app never hears
// about. It is signalled even though the caller gave up, and err reports the
// cancellation.
func (client *Client) RefreshStatuses(ctx context.Context) error {
	changed, err := client.revocationService.RefreshStatuses(ctx)
	if changed > 0 {
		client.handler.CredentialsChanged()
	}
	return err
}

type SessionRequestData struct {
	irma.Qr
	Protocol               clientmodels.Protocol `json:"protocol,omitempty"`
	ContinueOnSecondDevice bool                  `json:"continue_on_second_device"`
	// OpenID4VCIRedirectUri is the OAuth `redirect_uri` to use for this
	// OpenID4VCI session. The wallet derives it from the host of the inbound
	// universal link (production vs staging). Required when Protocol is
	// OpenID4VCI; ignored otherwise.
	OpenID4VCIRedirectUri string `json:"openid4vci_redirect_uri,omitempty"`
	// DcApi carries an OpenID4VP request the platform delivered through the W3C
	// Digital Credentials API rather than through a URL. When set, Protocol must be
	// OpenID4VP and URL is ignored; the resulting Authorization Response is
	// reported back on SessionState.DcApiResponse instead of being transmitted by
	// the wallet.
	DcApi *openid4vp.DcApiRequest `json:"dc_api,omitempty"`
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

func sdjwtvcBatchMetadataToIrmaCredentialInfo(metadata irmaclient.SdJwtVcBatchMetadata) *irma.CredentialInfo {
	credIdSegments := strings.Split(metadata.CredentialType, ".")

	attrs := map[irma.AttributeTypeIdentifier]irma.TranslatedString{}
	for name, value := range metadata.Attributes {
		id := irma.NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s", metadata.CredentialType, name))
		valueStr := value.(string)
		translatedValue := irma.NewTranslatedString(&valueStr)
		attrs[id] = translatedValue
	}

	info := irma.CredentialInfo{
		ID:                  credIdSegments[2],
		IssuerID:            credIdSegments[1],
		SchemeManagerID:     credIdSegments[0],
		Attributes:          attrs,
		Hash:                metadata.Hash,
		Revoked:             false,
		RevocationSupported: false,
		CredentialFormat:    clientmodels.Format_SdJwtVc,
		InstanceCount:       &metadata.RemainingInstanceCount,
	}

	if metadata.SignedOn != nil {
		info.SignedOn = *metadata.SignedOn
	}
	if metadata.Expires != nil {
		info.Expires = *metadata.Expires
	}

	return &info
}

func (client *Client) getIrmaCredentialInfoList() irma.CredentialInfoList {
	sdjwtvcs := client.sdjwtvcStorage.GetCredentialMetdataList()
	idemix := client.irmaClient.CredentialInfoList()

	result := irma.CredentialInfoList{}

	for _, sdjwtvcMeta := range sdjwtvcs {
		result = append(result, sdjwtvcBatchMetadataToIrmaCredentialInfo(sdjwtvcMeta))
	}

	result = append(result, idemix...)

	return result
}

// KeyshareVerifyPin verifies the PIN at the keyshare server. A verified PIN
// also activates a wallet unit that is still pending activation, which is how
// wallets enrolled before they had a wallet provider get one.
func (client *Client) KeyshareVerifyPin(
	pin string,
	schemeid irma.SchemeManagerIdentifier,
) (success bool, triesRemaing int, blockedSecs int, err error) {
	success, triesRemaing, blockedSecs, err = client.irmaClient.KeyshareVerifyPin(pin, schemeid)
	if success && err == nil {
		client.activateWalletUnitInBackground(pin)
	}
	return
}

// KeyshareEnroll enrolls at the keyshare server. With a wallet provider, a
// successful enrollment then activates the wallet unit with the same PIN, in
// the background; the app hears of it through WalletUnitActivated or
// WalletUnitActivationPending, after EnrollmentSuccess.
func (client *Client) KeyshareEnroll(manager irma.SchemeManagerIdentifier, email *string, pin string, lang string) {
	if client.walletProvider != nil {
		client.enrollmentPin.set(pin)
	}
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

	return iana.CreateUrlEncodedHash(iana.SHA256, hashContent.String())
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

	// Delete EUDI credentials. The removal log is best-effort: the metadata read
	// only enriches the log, and a corrupt credential — the very case that makes
	// deletion necessary — is exactly what can make that read fail. A failed or
	// empty log must never block the deletion itself.
	if len(eudiHashes) > 0 {
		allEudiCreds, err := client.listEudiCredentials()
		if err != nil {
			irma.Logger.Warnf("could not read eudi credentials for removal log; deleting without it: %v", err)
			allEudiCreds = nil
		}

		// Find the credentials being deleted.
		hashSet := map[string]struct{}{}
		for _, h := range eudiHashes {
			hashSet[h] = struct{}{}
		}
		var removedCreds []clientmodels.LogCredential
		for _, c := range allEudiCreds {
			if _, ok := hashSet[c.Hash]; ok {
				removedCreds = append(removedCreds, clientmodels.CredentialToLogCredential(c))
			}
		}

		// Create removal log before deleting, so the log service can still
		// look up batch metadata to resolve the credential logo filename. A
		// failure here must not block deletion either.
		if len(removedCreds) > 0 {
			logService := services.NewEudiLogService(client.eudiStorage, client.locale())
			if err := logService.AddRemovalLog(removedCreds); err != nil {
				irma.Logger.Warnf("failed to create eudi removal log; deleting anyway: %v", err)
			}
		}

		for format, hash := range eudiHashes {
			support, ok := client.credentialFormats[models.CredentialFormat(format)]
			if !ok {
				return fmt.Errorf("error while deleting eudi credential: no storage for format %q", format)
			}
			// The batch's keys go first, through the key binder, which removes
			// them where they live — a wallet provider's HSM among them — and
			// then their rows. A key the provider failed to remove is
			// unreachable from this wallet either way, so it does not block the
			// deletion.
			keyIds, err := support.Store.KeyIDsByHash(hash)
			if err != nil {
				irma.Logger.Warnf("could not look up the keys of eudi credential %s: %v", hash, err)
			} else if len(keyIds) > 0 {
				if err := support.Keys.RemoveKeys(keyIds); err != nil {
					irma.Logger.Warnf("could not remove all keys of eudi credential %s: %v", hash, err)
				}
			}
			if err := support.Store.DeleteByHash(hash); err != nil {
				return fmt.Errorf("error while deleting eudi credential: %v", err)
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

	// Loop over the attributes in display order. A credential whose type is not
	// in the configuration (a ProblematicCredential being cleaned up — reachable
	// for an SD-JWT-over-IRMA credential whose type was dropped from its scheme)
	// has no attribute types to order by, so its log entry records no attributes;
	// the removal itself must still be logged.
	if credType := irmaConfiguration.CredentialTypes[credentialType]; credType != nil {
		for _, t := range sortedAttributeTypes(credType.AttributeTypes) {
			id := t.GetAttributeTypeIdentifier()
			attrs = append(attrs, attributes[id])
		}
	}

	return &irmaclient.LogEntry{
		Time: irmaclient.LogTime(time.Now()),
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

// walletUnitRevokeTimeout bounds how long RemoveStorage waits for the wallet
// provider to revoke the wallet unit before wiping the wallet regardless.
const walletUnitRevokeTimeout = 10 * time.Second

func (client *Client) RemoveStorage() error {
	// The wallet unit is revoked first, so its keys do not outlive the wallet
	// in the provider's HSM. Best effort: a reset that refuses to reset because
	// the device is offline is worse than an account the provider cleans up
	// on its own (docs/plans/wallet-provider-integration.md, decision 14).
	if client.walletProvider != nil {
		ctx, cancel := context.WithTimeout(context.Background(), walletUnitRevokeTimeout)
		if err := client.walletProvider.Revoke(ctx); err != nil {
			irma.Logger.Warnf("could not revoke the wallet unit; wiping the wallet anyway: %v", err)
		}
		cancel()
	}

	if err := client.sdjwtvcStorage.RemoveAll(); err != nil {
		return fmt.Errorf("failed to remove sdjwtvc storage: %v", err)
	}
	if err := client.keyBinder.RemoveAllPrivateKeys(); err != nil {
		return fmt.Errorf("failed to remove all holder private keys: %v", err)
	}
	if err := client.eudiStorage.RemoveAll(); err != nil {
		return fmt.Errorf("failed to remove eudi storage: %v", err)
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
	logService := services.NewEudiLogService(client.eudiStorage, client.locale())
	eudiLogs, err := logService.GetNewestLogs(max)
	if err != nil {
		return nil, err
	}

	return mergeLogsByTime(irmaLogs, eudiLogs, max), nil
}

func (client *Client) LoadLogsBefore(before time.Time, max int) ([]clientmodels.LogInfo, error) {
	// Load IRMA logs from bbolt.
	rawLogs, err := client.irmaClient.LoadLogsBeforeTime(before, max)
	if err != nil {
		return nil, err
	}
	irmaLogs, err := client.rawLogEntriesToLogInfo(rawLogs)
	if err != nil {
		return nil, err
	}

	// Load EUDI logs from SQLCipher.
	logService := services.NewEudiLogService(client.eudiStorage, client.locale())
	eudiLogs, err := logService.GetLogsBefore(before, max)
	if err != nil {
		return nil, err
	}

	return mergeLogsByTime(irmaLogs, eudiLogs, max), nil
}

// mergeLogsByTime merges two log slices (each already sorted newest-first) into
// a single newest-first slice of at most max entries using a two-pointer merge.
func mergeLogsByTime(a, b []clientmodels.LogInfo, max int) []clientmodels.LogInfo {
	merged := make([]clientmodels.LogInfo, 0, min(len(a)+len(b), max))
	i, j := 0, 0
	for len(merged) < max && (i < len(a) || j < len(b)) {
		switch {
		case i >= len(a):
			merged = append(merged, b[j])
			j++
		case j >= len(b):
			merged = append(merged, a[i])
			i++
		case !a[i].Time.Before(b[j].Time): // a[i] >= b[j], take a
			merged = append(merged, a[i])
			i++
		default:
			merged = append(merged, b[j])
			j++
		}
	}
	return merged
}

// setDeveloperModeOnConfiguration brings the certificate checks in line with
// the developer mode preference. It is separate from setDeveloperModeOnClients
// because New has to call the two at different points: these settings must be
// in place before Configuration.Reload validates the stored chains, while the
// OpenID4VCI client the other half needs is only constructed after that reload.
//
// The trust anchors themselves only follow on the next Reload.
func setDeveloperModeOnConfiguration(conf *eudi.Configuration, enabled bool) {
	mode := eudi.StrictCertificateVerification
	if enabled {
		mode = eudi.DeveloperModeCertificateVerification
	}
	conf.SetCertificateVerificationMode(mode)
	conf.SetUseStagingTrustAnchors(enabled)
}

// setDeveloperModeOnClients brings the transport checks in line with the
// developer mode preference: plain-HTTP OpenID4VCI issuers and insecure did:web
// verifiers.
func setDeveloperModeOnClients(vciClient *openid4vci.Client, didValidator *openid4vp.DidVerifierValidator, enabled bool) {
	vciClient.SetAllowInsecureHttp(enabled)
	didValidator.SetAllowInsecureDidWeb(enabled)
}

// SetPreferences stores prefs and brings the developer mode relaxations in line
// with it, in both directions. The trust models are rebuilt when the developer
// mode preference changed, not on every preference write.
func (client *Client) SetPreferences(prefs clientsettings.Preferences) {
	developerModeChanged := client.irmaClient.Preferences.DeveloperMode != prefs.DeveloperMode
	client.irmaClient.SetPreferences(prefs)

	// Both directions have to take effect: every relaxation developer mode
	// makes is undone when it is switched off, so the wallet does not keep
	// accepting plain HTTP and staging chains until the process restarts.
	// Kept in step with New, which applies the same for the preference that is
	// already set at startup.
	setDeveloperModeOnConfiguration(client.openid4vpClient.Configuration, prefs.DeveloperMode)
	setDeveloperModeOnClients(client.openid4vciClient, client.didValidator, prefs.DeveloperMode)

	if !developerModeChanged {
		return
	}

	// Reload rebuilds both trust models from the anchors the new setting
	// selects: switching developer mode on adds the staging chains, switching
	// it off drops them again.
	if err := client.openid4vpClient.Configuration.Reload(); err != nil {
		common.Logger.Warnf("error while reloading eudi config: %v", err)
	}
	// Only the staging anchors bring distribution points whose CRLs the wallet
	// has not downloaded yet, so this is needed on the way in, not on the way
	// out: the production CRLs were already on disk for the Reload above.
	if prefs.DeveloperMode {
		if err := client.openid4vpClient.Configuration.UpdateCertificateRevocationLists(); err != nil {
			common.Logger.Warnf("error while updating CRLs: %v", err)
		}
	}
}

func (client *Client) GetPreferences() clientsettings.Preferences {
	return client.irmaClient.Preferences
}

func (client *Client) InitJobs(eudiCrlUpdateInterval, statusTokenListRefreshInterval time.Duration) {
	// Future TODO: add Context so we can check for cancellation of the job ?
	_, err := client.scheduler.NewJob(
		gocron.DurationJob(eudiCrlUpdateInterval),
		gocron.NewTask(client.openid4vpClient.Configuration.UpdateCertificateRevocationLists),
		gocron.WithStartAt(gocron.WithStartImmediately()),
	)

	if err != nil {
		common.Logger.Warnf("failed to create new cron job for updating CRLs: %v", err)
	}

	// Periodically re-fetch referenced Token Status Lists and update one
	// representative instance's LastKnownStatus per credential batch (a batch is
	// revoked all at once, so one entry stands in for the whole batch). Skipped
	// when the interval is non-positive. The sweep is fail-soft: per-URI errors
	// are logged inside RefreshStatuses and the previous status is kept. A sweep
	// that finds a status change signals the app through RefreshStatuses.
	if statusTokenListRefreshInterval > 0 {
		_, err = client.scheduler.NewJob(
			gocron.DurationJob(statusTokenListRefreshInterval),
			gocron.NewTask(func() {
				if err := client.RefreshStatuses(context.Background()); err != nil {
					common.Logger.Warnf("scheduled status refresh failed: %v", err)
				}
			}),
			gocron.WithStartAt(gocron.WithStartImmediately()),
		)
		if err != nil {
			common.Logger.Warnf("failed to create new cron job for refreshing credential statuses: %v", err)
		}
	}
}
