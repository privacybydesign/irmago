package services

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/internal/helpers"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
)

// TrustService is the single home for trust in the wallet: it pins snapshots of
// the wallet config for sessions to rank parties against, ranks the issuers of
// stored credentials, and keeps the trust models in step with the config —
// after a refresh that changed it and after an environment switch.
//
// Ranking never fails a session on its own: nothing on the evaluation path
// returns an error. Fetching happens only in Refresh, never on a session's path.
type TrustService struct {
	manager   *walletconfig.Manager
	conf      *eudi.Configuration
	credStore db.CredentialStore
	appBuild  int64

	// issuerCerts caches the issuer certificate extracted from each stored
	// batch's raw credential, by batch hash. A batch's credential never changes,
	// so the cache is never invalidated; a nil entry records a batch without an
	// x5c issuer.
	issuerCertsMu sync.Mutex
	issuerCerts   map[string]*x509.Certificate
}

// NewTrustService builds the wallet's trust service. appBuild is the build this
// wallet runs, for the minimum app build gate; zero disables the gate.
func NewTrustService(manager *walletconfig.Manager, conf *eudi.Configuration, credStore db.CredentialStore, appBuild int64) *TrustService {
	return &TrustService{
		manager:     manager,
		conf:        conf,
		credStore:   credStore,
		appBuild:    appBuild,
		issuerCerts: map[string]*x509.Certificate{},
	}
}

// Snapshot pins the state a single session evaluates against, so a refresh
// landing mid-session cannot change its verdicts. It never fetches.
func (s *TrustService) Snapshot() trust.View {
	return trust.NewView(s.manager.Snapshot(), &s.conf.Issuers, &s.conf.Verifiers, s.appBuild)
}

// Environment is the active environment.
func (s *TrustService) Environment() walletconfig.Environment {
	return s.manager.Snapshot().Environment
}

// Refresh fetches the active environment's config when it is due — the wallet
// holds none, the held one is past its next_update, or the throttle has
// elapsed — and reloads the trust models when what it holds changed. changed
// reports whether the app may be showing trust information that is now out of
// date. A failing fetch leaves the held config in force; the error is for the
// caller's log.
func (s *TrustService) Refresh(ctx context.Context) (changed bool, err error) {
	changed, err = s.manager.RefreshIfDue(ctx)
	if changed {
		if reloadErr := s.conf.Reload(); reloadErr != nil {
			err = errors.Join(err, reloadErr)
		}
	}
	return changed, err
}

// SwitchEnvironment makes name the active environment and rebuilds the trust
// models from it. What the wallet has for the new environment may be old; the
// caller triggers a Refresh.
func (s *TrustService) SwitchEnvironment(name string) error {
	if err := s.manager.SwitchEnvironment(name); err != nil {
		return err
	}
	return s.conf.Reload()
}

// IssuerStanding ranks the issuer of a stored credential against a fresh view
// and reports whether it meets the issuance minimum of the policy in force. A
// credential whose issuer does not is excluded from disclosure and badged.
func (s *TrustService) IssuerStanding(batch *models.CredentialBatch) (clientmodels.TrustLevel, bool) {
	return s.IssuerStandingIn(s.Snapshot(), batch)
}

// IssuerStandingIn is IssuerStanding against a pinned view, for callers ranking
// a whole list under one snapshot.
func (s *TrustService) IssuerStandingIn(view trust.View, batch *models.CredentialBatch) (clientmodels.TrustLevel, bool) {
	verdict := view.Issuer(s.BatchIssuerEvidence(batch))
	meets := trust.CheckMinimum(view.Policy(), trust.SessionIssuance, verdict.Level) == nil
	return verdict.Level, meets
}

// BatchIssuerEvidence is what the wallet knows about the issuer of a stored
// batch, in the terms the trust ladder ranks by: the DID it signed under, when
// it is one, and the x5c certificate off the stored credential. Read on every
// listing rather than stored as a level, so a credential's rung follows the
// config as it changes.
func (s *TrustService) BatchIssuerEvidence(batch *models.CredentialBatch) trust.Evidence {
	evidence := trust.Evidence{}
	if strings.HasPrefix(batch.IssuerIdentifier, "did:") {
		evidence.DID = batch.IssuerIdentifier
	}
	evidence.Certificate = s.issuerCertificateOf(batch)
	return evidence
}

func (s *TrustService) issuerCertificateOf(batch *models.CredentialBatch) *x509.Certificate {
	s.issuerCertsMu.Lock()
	defer s.issuerCertsMu.Unlock()
	if certificate, ok := s.issuerCerts[batch.Hash]; ok {
		return certificate
	}

	var certificate *x509.Certificate
	if s.credStore != nil {
		// Any instance carries the same issuer signature; an exhausted batch has no
		// unused one left, and then ranks through its DID alone.
		if instance, err := s.credStore.GetUnusedInstance(batch.ID); err == nil {
			certificate = IssuerCertificateFromRawSdJwt(instance.RawCredential)
		}
	}
	s.issuerCerts[batch.Hash] = certificate
	return certificate
}

// IssuerCertificateFromRawSdJwt reads the x5c end-entity certificate off a stored
// SD-JWT's issuer-signed JWT header, or nil when there is none. Nothing is
// verified: the credential verified at issuance, and what the chain says today
// is the trust ladder's question.
func IssuerCertificateFromRawSdJwt(raw []byte) *x509.Certificate {
	issuerSignedJwt, _, _ := strings.Cut(string(raw), "~")
	header, _, err := sdjwt.DecodeJwtWithoutCheckingSignature(issuerSignedJwt)
	if err != nil {
		return nil
	}
	x5c, ok := header["x5c"].([]any)
	if !ok || len(x5c) == 0 {
		return nil
	}
	encoded, ok := x5c[0].(string)
	if !ok {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return certificate
}

// LoadCuratedLogo returns the logo a trusted entity's listing names, from the
// cache or by downloading it, verified against the listing's digest. A logo
// whose bytes do not match the digest is not shown: the digest is what makes a
// logo fetched from anywhere the curator's word. Nil when the entity lists no
// logo, the download fails, or the digest does not match.
func LoadCuratedLogo(ctx context.Context, manager filesystem.LogoManager, httpClient *http.Client, logo *walletconfig.Logo) *clientmodels.Image {
	if logo == nil || manager == nil {
		return nil
	}
	key := curatedLogoKey(logo)
	if image := eudi.LoadLogoImage(manager, key); image != nil {
		return image
	}

	data, mimeType, err := helpers.DownloadRemoteImage(ctx, httpClient, logo.URL)
	if err != nil {
		eudi.Logger.Warnf("trust: downloading curated logo %q: %v", logo.URL, err)
		return nil
	}
	if !digestMatches(logo.Digest, data) {
		eudi.Logger.Warnf("trust: curated logo %q does not match its digest, not showing it", logo.URL)
		return nil
	}
	if err := manager.Save(key, data, mimeType); err != nil {
		eudi.Logger.Warnf("trust: caching curated logo %q: %v", logo.URL, err)
	}
	return clientmodels.NewImage(data, mimeType)
}

// curatedLogoKey files a curated logo by its digest, so a listing that changes
// its logo changes the key and a stale cache entry is never shown.
func curatedLogoKey(logo *walletconfig.Logo) string {
	sum := sha256.Sum256([]byte(logo.Digest))
	return "curated-" + hex.EncodeToString(sum[:])
}

// digestMatches checks data against a `sha256-<base64>` digest.
func digestMatches(digest string, data []byte) bool {
	encoded, ok := strings.CutPrefix(digest, "sha256-")
	if !ok {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	actual := sha256.Sum256(data)
	return len(expected) == len(actual) && subtleEqual(expected, actual[:])
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
