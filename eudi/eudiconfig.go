package eudi

import (
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sirupsen/logrus"
)

type SdJwtVerificationMode int

const (
	StrictSdJwtVerificationMode SdJwtVerificationMode = iota
	LaxSdJwtVerificationMode
)

// Logger is used for logging. For now, it will be set via the Client component
var Logger *logrus.Logger

func init() {
	Logger = common.Logger
}

// SnapshotSource is where Reload reads the trust anchors from: the wallet
// config manager, pinned to one snapshot per reload.
type SnapshotSource interface {
	Snapshot() walletconfig.Snapshot
}

// Configuration keeps track of the issuer and verifier trust models: the CAs
// each role's certificates may chain to, and their certificate revocation
// lists. The anchors come from the wallet configuration — the x509_ca handles
// of the active environment's trusted entities — plus any chains installed in
// the eudi storage folder (issuers and verifiers subfolders, .pem files in
// leaf-to-root order), the seam tests and the debug screen use. CRLs are
// downloaded on demand and cached in the crls subfolder.
type Configuration struct {
	Storage   storage.Storage
	Issuers   TrustModel
	Verifiers TrustModel

	// WalletConfig is the source of the trust anchors. Nil anchors nothing
	// beyond what is installed in storage.
	WalletConfig SnapshotSource

	// reloadMu serializes Reload: the CRL refresh job, the config refresh and
	// the developer-mode toggle can all ask for one, and each trust model
	// assembles its next state in a single pending slot.
	reloadMu sync.Mutex
}

// NewConfiguration returns a new configuration. Set WalletConfig and call
// Reload before use.
func NewConfiguration(s storage.Storage) (conf *Configuration, err error) {
	httpClient := common.HTTPClient

	conf = &Configuration{
		Storage: s,
		Issuers: TrustModel{
			storageContainer: s.FileSystem().Issuers(),
			logger:           Logger,
			httpClient:       httpClient,
		},
		Verifiers: TrustModel{
			storageContainer: s.FileSystem().Verifiers(),
			logger:           Logger,
			httpClient:       httpClient,
		},
	}

	return
}

func (c *Configuration) SetCertificateVerificationMode(mode CertificateVerificationMode) {
	c.Issuers.SetCertificateVerificationMode(mode)
	c.Verifiers.SetCertificateVerificationMode(mode)
}

// Reload rebuilds both trust models and publishes them together: the anchors
// the wallet config's active snapshot delivers (built-in entities and, when a
// config is held, its entities — CA anchors keep working whatever the config's
// freshness), then the chains installed in storage, then the cached CRLs.
// Intermediate certificates are checked against the revocation list of their
// parent before being added. On error nothing is published: readers keep the
// last complete state.
func (c *Configuration) Reload() error {
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()

	c.Issuers.clear()
	c.Verifiers.clear()

	if c.WalletConfig != nil {
		snapshot := c.WalletConfig.Snapshot()
		c.installEntities(snapshot.Environment.BuiltinEntities)
		if snapshot.Config != nil {
			c.installEntities(snapshot.Config.TrustedEntities)
		}
	}

	// Read the trust anchors from storage
	if err := c.Issuers.load(); err != nil {
		c.Issuers.discard()
		c.Verifiers.discard()
		return fmt.Errorf("failed to load issuer trust model: %v", err)
	}
	if err := c.Verifiers.load(); err != nil {
		c.Issuers.discard()
		c.Verifiers.discard()
		return fmt.Errorf("failed to load verifier trust model: %v", err)
	}

	c.Issuers.commit()
	c.Verifiers.commit()
	return nil
}

// installEntities puts every x509_ca handle of the entities into the trust
// model of each role the entity holds. Other handle types anchor nothing: an
// x509_cert or did handle is matched by the trust ladder, not by chain building.
func (c *Configuration) installEntities(entities []walletconfig.TrustedEntity) {
	for i := range entities {
		entity := &entities[i]
		for j := range entity.Handles {
			handle := &entity.Handles[j]
			if handle.Type != walletconfig.HandleTypeX509CA || handle.RootCertificate == nil || handle.RootCertificate.Certificate == nil {
				continue
			}
			intermediates := make([]*x509.Certificate, 0, len(handle.Intermediates))
			for _, intermediate := range handle.Intermediates {
				if intermediate.Certificate != nil {
					intermediates = append(intermediates, intermediate.Certificate)
				}
			}
			for _, role := range entity.Roles {
				var tm *TrustModel
				switch role {
				case walletconfig.RoleIssuer:
					tm = &c.Issuers
				case walletconfig.RoleVerifier:
					tm = &c.Verifiers
				default:
					continue
				}
				tm.addRevocationListDistributionPoints(handle.CRLDistributionPoints...)
				tm.addAnchor(handle.RootCertificate.Certificate, intermediates)
			}
		}
	}
}

// ResolveVerifierLogo returns the cached logo for the given verifier key
// (typically the verifier's certificate serial number) as a base64-encoded
// clientmodels.Image, or nil if no logo is cached.
func (c *Configuration) ResolveVerifierLogo(key string) *clientmodels.Image {
	return LoadLogoImage(c.Verifiers.storageContainer.LogoManager(), key)
}

func (c *Configuration) UpdateCertificateRevocationLists() error {
	var wg sync.WaitGroup
	wg.Add(2)

	go updateWorker(c.Issuers.syncCertificateRevocationLists, &wg)
	go updateWorker(c.Verifiers.syncCertificateRevocationLists, &wg)

	wg.Wait()

	// A reload publishes a whole new state, so a session in progress keeps the
	// state it started with rather than seeing a half-built one.
	return c.Reload()
}

func updateWorker(worker func(), wg *sync.WaitGroup) {
	defer wg.Done()
	worker()
}
