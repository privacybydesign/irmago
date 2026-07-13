package wallet

import (
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/eudi_sdjwt_dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/internal/common"
)

// Config configures a Wallet.
type Config struct {
	// DataDir holds the SQLCipher database (yivi-eudi.db) and the encrypted
	// filesystem containers (logos, certificates, CRLs). Created if missing.
	DataDir string

	// AesKey encrypts both the SQLCipher database and the filesystem containers.
	// In a real wallet this is derived from a user secret and kept in a secure
	// enclave; the POC accepts it directly (see cmd for passphrase derivation).
	AesKey [32]byte

	// DeveloperMode loads staging trust anchors in addition to production ones,
	// permits insecure http (non-TLS) issuers and did:web, and relaxes
	// certificate verification. Use only against test/staging infrastructure.
	DeveloperMode bool

	// Policy decides, headlessly, whether to accept issuance offers and which
	// claims to disclose. Defaults to AutoApprovePolicy when nil.
	Policy Policy

	// HolderSigner backs the SD-JWT VC holder binding keys. When set, the KB-JWT
	// signed at OpenID4VP presentation time is produced through this signer
	// instead of software keys pulled from storage — e.g. a WSCA/HSM. When nil,
	// the wallet uses the default storage-backed software binder.
	//
	// This rewires the PRESENTATION (KB-JWT) path. For issuance, also set
	// IssuanceKeyBinder so credentials are issued with a WSCA-bound cnf.
	HolderSigner HolderSigner

	// IssuanceKeyBinderFactory backs the OpenID4VCI proof-of-possession path: it
	// generates holder keys and signs the proof JWTs. It is a factory because the
	// binder must persist holder-key rows into the SAME storage the wallet opens
	// (so credential storage can link each issued credential's cnf to a key). The
	// factory is called once with that storage. When set (e.g. WSCA), the holder
	// private key never enters this process. When nil, software keys are used.
	IssuanceKeyBinderFactory func(storage.Storage) openid4vci.HolderKeyBinder
}

// Wallet is a standalone SD-JWT VC wallet. It is safe for sequential use; the
// underlying protocol clients hold a single current session, so callers must
// not run Receive/Present concurrently. Wallet serializes them with a mutex.
type Wallet struct {
	conf    *eudi.Configuration
	storage storage.Storage
	vci     *openid4vci.Client
	vp      *openid4vp.Client
	policy  Policy

	mu        sync.Mutex
	sessionID int
}

// New builds a Wallet, opening (or creating) encrypted storage under
// cfg.DataDir and wiring the OpenID4VCI and OpenID4VP clients over the EUDI
// SD-JWT VC stack. It mirrors the EUDI half of client.New, without any IRMA
// dependency.
func New(cfg Config) (*Wallet, error) {
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("wallet: DataDir is required")
	}
	if err := common.EnsureDirectoryExists(cfg.DataDir); err != nil {
		return nil, fmt.Errorf("wallet: failed to ensure data dir: %w", err)
	}
	policy := cfg.Policy
	if policy == nil {
		policy = AutoApprovePolicy{}
	}

	// Encrypted storage: SQLCipher DB + AES-GCM filesystem.
	dbPath := filepath.Join(cfg.DataDir, storage.DbFilename)
	eudiStorage, err := storage.NewStorage(cfg.AesKey, dbPath, cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("wallet: failed to open storage: %w", err)
	}

	conf, err := eudi.NewConfiguration(eudiStorage)
	if err != nil {
		eudiStorage.Close()
		return nil, fmt.Errorf("wallet: failed to build eudi configuration: %w", err)
	}

	// Verifier trust: X.509 requestor certificates + DID (did:jwk, did:web),
	// dispatched by client_id prefix.
	x509Validator := openid4vp.NewRequestorCertificateStoreVerifierValidator(&conf.Verifiers, &openid4vp.DefaultQueryValidatorFactory{})
	didValidator := openid4vp.NewDidVerifierValidator(false)
	verifierValidator := openid4vp.NewCompositeVerifierValidator(x509Validator, didValidator)

	// OpenID4VP disclosure over the EUDI (non-IRMA) SD-JWT VC store. When a
	// HolderSigner is configured (e.g. WSCA-backed), the KB-JWT is signed
	// through it instead of software keys from storage.
	var binders []sdjwtvc.KeyBinder
	if cfg.HolderSigner != nil {
		binders = append(binders, newSignerKeyBinder(cfg.HolderSigner))
	}
	dcqlHandler := eudi_sdjwt_dcql.NewSdJwtVcDcqlHandler(
		eudiStorage,
		typemetadata.NewDefaultVctFetcher(nil),
		typemetadata.NewDefaultIssuerFetcher(nil),
		binders...,
	)
	vpClient, err := openid4vp.NewClient(conf, []dcql.DcqlCredentialQueryHandler{dcqlHandler}, verifierValidator)
	if err != nil {
		eudiStorage.Close()
		return nil, fmt.Errorf("wallet: failed to build openid4vp client: %w", err)
	}

	// OpenID4VCI issuance: holder-side SD-JWT VC verification (no requestor-info
	// VCT check, matching the OID4VCI context in client.New).
	verifyCtx := sdjwtvc.SdJwtVcVerificationContext{
		X509VerificationContext: &conf.Issuers,
		Clock:                   eudi_jwt.NewSystemClock(),
		JwtVerifier:             sdjwtvc.NewJwxJwtVerifier(),
		VerifyVerifiableCredentialTypeInRequestorInfo: false,
	}
	var vciOpts []openid4vci.ClientOption
	if cfg.IssuanceKeyBinderFactory != nil {
		vciOpts = append(vciOpts, openid4vci.WithHolderKeyBinder(cfg.IssuanceKeyBinderFactory(eudiStorage)))
	}
	vciClient, err := openid4vci.NewClient(&http.Client{}, conf, sdjwtvc.NewHolderVerificationProcessor(verifyCtx), vciOpts...)
	if err != nil {
		eudiStorage.Close()
		return nil, fmt.Errorf("wallet: failed to build openid4vci client: %w", err)
	}

	if cfg.DeveloperMode {
		conf.EnableStagingTrustAnchors()
		conf.SetCertificateVerificationMode(eudi.DeveloperModeCertificateVerification)
		vciClient.AllowInsecureHttpForTesting()
		didValidator.SetAllowInsecureDidWeb(true)
	}

	if err := conf.Reload(); err != nil {
		eudiStorage.Close()
		return nil, fmt.Errorf("wallet: failed to load trust configuration: %w", err)
	}
	if cfg.DeveloperMode {
		if err := conf.UpdateCertificateRevocationLists(); err != nil {
			eudi.Logger.Warnf("wallet: failed to update CRLs: %v", err)
		}
	}

	return &Wallet{
		conf:    conf,
		storage: eudiStorage,
		vci:     vciClient,
		vp:      vpClient,
		policy:  policy,
	}, nil
}

// Close releases storage handles.
func (w *Wallet) Close() error {
	return w.storage.Close()
}

// Credentials returns all SD-JWT VC credentials currently stored in the wallet.
func (w *Wallet) Credentials() ([]*clientmodels.Credential, error) {
	creds, err := services.NewCredentialService(w.storage).GetCredentialMetadataList()
	if err != nil {
		return nil, fmt.Errorf("wallet: failed to read credentials: %w", err)
	}
	return creds, nil
}

// Logs returns the newest session logs (issuance, disclosure, removal), newest
// first, up to max entries.
func (w *Wallet) Logs(max int) ([]clientmodels.LogInfo, error) {
	logs, err := services.NewEudiLogService(w.storage).GetNewestLogs(max)
	if err != nil {
		return nil, fmt.Errorf("wallet: failed to read logs: %w", err)
	}
	return logs, nil
}

// LogsBefore returns logs older than the given time, newest first, up to max.
func (w *Wallet) LogsBefore(before time.Time, max int) ([]clientmodels.LogInfo, error) {
	logs, err := services.NewEudiLogService(w.storage).GetLogsBefore(before, max)
	if err != nil {
		return nil, fmt.Errorf("wallet: failed to read logs: %w", err)
	}
	return logs, nil
}

// Reset wipes all stored credentials, holder keys and logs.
func (w *Wallet) Reset() error {
	if err := w.storage.RemoveAll(); err != nil {
		return fmt.Errorf("wallet: failed to reset storage: %w", err)
	}
	return nil
}

// nextSessionID returns a fresh non-zero session id (the protocol clients
// reject id 0 and use it to route state).
func (w *Wallet) nextSessionID() int {
	w.sessionID++
	if w.sessionID == 0 {
		w.sessionID = 1
	}
	return w.sessionID
}
