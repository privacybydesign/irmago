package services

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
)

// CatalogService answers what the wallet config's credential catalogue says
// about a credential type, with the display information resolved from the
// type's own metadata and the issuer's metadata: the config lists where a
// credential can be obtained and nothing about how it looks.
//
// Metadata is fetched on demand and cached for as long as the same config is
// held; a fetch that fails is not cached, so a transient outage is retried. The
// catalogue itself vouches for nobody: the trust level a descriptor carries comes
// from a soft match of the offering's host against the trusted entities, and is
// absent when nothing matches.
type CatalogService struct {
	source        eudi.SnapshotSource
	vctFetcher    typemetadata.VctFetcher
	issuerFetcher typemetadata.IssuerFetcher

	mu sync.Mutex
	// cachedFor identifies the config issue the caches were filled for; a new
	// issue empties them, since it may point the same vct elsewhere.
	cachedFor string
	vct       map[string]*typemetadata.VctTypeMetadata
	issuers   map[string]*typemetadata.IssuerMetadata
}

// CatalogHit is what the catalogue says about one credential type, resolved for
// a locale.
type CatalogHit struct {
	Entry walletconfig.CatalogEntry
	// Metadata is the type metadata the entry resolves to, or nil when it could
	// not be fetched or the entry names none; callers render the raw vct then.
	Metadata *typemetadata.VctTypeMetadata
	// Offerings has one element per listed offering, in the listed order.
	Offerings []CatalogOffering
}

// CatalogOffering is one place the credential can be obtained, for a locale.
type CatalogOffering struct {
	// IssueURL is the web page where issuance starts, for the locale.
	IssueURL string
	// Issuer is the party the offering resolves to: named from its metadata,
	// and — when its host matches a trusted entity — from the entity, with the
	// entity's trust level. Unevaluated otherwise: presence in the catalogue is
	// never itself a trust level.
	Issuer clientmodels.TrustedParty
}

// NewCatalogService builds the catalogue service over the wallet config. Nil
// fetchers leave the corresponding metadata unresolved.
func NewCatalogService(source eudi.SnapshotSource, vctFetcher typemetadata.VctFetcher, issuerFetcher typemetadata.IssuerFetcher) *CatalogService {
	return &CatalogService{
		source:        source,
		vctFetcher:    vctFetcher,
		issuerFetcher: issuerFetcher,
		vct:           map[string]*typemetadata.VctTypeMetadata{},
		issuers:       map[string]*typemetadata.IssuerMetadata{},
	}
}

// Lookup is the catalogue's answer for a credential type, or nil when the held
// config lists none for it.
func (s *CatalogService) Lookup(ctx context.Context, vct, locale string) *CatalogHit {
	snapshot := s.source.Snapshot()
	if snapshot.Config == nil {
		return nil
	}
	entry := snapshot.Config.CatalogEntry(vct)
	if entry == nil {
		return nil
	}
	return s.resolve(ctx, snapshot, entry, locale)
}

// StoreItems is the browsable store's OpenID4VC section: one descriptor per
// offering of every entry opted in with in_store, with the issuance URL for the
// locale and the attributes the type metadata describes.
func (s *CatalogService) StoreItems(ctx context.Context, locale string) []*clientmodels.CredentialDescriptor {
	snapshot := s.source.Snapshot()
	if snapshot.Config == nil {
		return nil
	}
	items := []*clientmodels.CredentialDescriptor{}
	for i := range snapshot.Config.CredentialCatalog {
		entry := &snapshot.Config.CredentialCatalog[i]
		if !entry.InStore {
			continue
		}
		hit := s.resolve(ctx, snapshot, entry, locale)
		for _, offering := range hit.Offerings {
			issueURL := offering.IssueURL
			items = append(items, &clientmodels.CredentialDescriptor{
				CredentialId: entry.VCT,
				Name:         CatalogCredentialName(hit.Metadata, entry.VCT, locale),
				Issuer:       offering.Issuer,
				Attributes:   catalogAttributes(hit.Metadata, locale),
				IssueURL:     &issueURL,
			})
		}
	}
	return items
}

func (s *CatalogService) resolve(ctx context.Context, snapshot walletconfig.Snapshot, entry *walletconfig.CatalogEntry, locale string) *CatalogHit {
	s.resetCacheFor(snapshot.Config)
	hit := &CatalogHit{
		Entry:    *entry,
		Metadata: s.vctMetadata(ctx, entry.MetadataURL()),
	}
	for i := range entry.Offerings {
		offering := &entry.Offerings[i]
		hit.Offerings = append(hit.Offerings, CatalogOffering{
			IssueURL: offering.IssuanceURL(locale),
			Issuer:   s.offeringIssuer(ctx, snapshot, offering, locale),
		})
	}
	return hit
}

// resetCacheFor empties the caches when the held config is another issue than
// the one they were filled for.
func (s *CatalogService) resetCacheFor(config *walletconfig.Config) {
	key := fmt.Sprintf("%s/%d/%d", config.ID, config.Version, config.IssuedAt.Unix())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cachedFor == key {
		return
	}
	s.cachedFor = key
	s.vct = map[string]*typemetadata.VctTypeMetadata{}
	s.issuers = map[string]*typemetadata.IssuerMetadata{}
}

func (s *CatalogService) vctMetadata(ctx context.Context, metadataURL string) *typemetadata.VctTypeMetadata {
	if metadataURL == "" || s.vctFetcher == nil {
		return nil
	}
	s.mu.Lock()
	cached, ok := s.vct[metadataURL]
	s.mu.Unlock()
	if ok {
		return cached
	}
	metadata, err := s.vctFetcher.Fetch(ctx, metadataURL)
	if err != nil {
		eudi.Logger.Warnf("catalog: fetching type metadata from %q: %v", metadataURL, err)
		return nil
	}
	s.mu.Lock()
	s.vct[metadataURL] = metadata
	s.mu.Unlock()
	return metadata
}

func (s *CatalogService) issuerMetadata(ctx context.Context, issuerURL string) *typemetadata.IssuerMetadata {
	if issuerURL == "" || s.issuerFetcher == nil {
		return nil
	}
	s.mu.Lock()
	cached, ok := s.issuers[issuerURL]
	s.mu.Unlock()
	if ok {
		return cached
	}
	metadata, err := s.issuerFetcher.Fetch(ctx, issuerURL)
	if err != nil {
		eudi.Logger.Warnf("catalog: fetching issuer metadata from %q: %v", issuerURL, err)
		return nil
	}
	s.mu.Lock()
	s.issuers[issuerURL] = metadata
	s.mu.Unlock()
	return metadata
}

// offeringIssuer names the party behind an offering: from its issuer metadata
// when the offering points at one, and from the trusted entity whose handle
// carries the offering's host when there is one — that entity's name outranks
// the metadata's, and its trust level is the only trust claim made.
func (s *CatalogService) offeringIssuer(ctx context.Context, snapshot walletconfig.Snapshot, offering *walletconfig.Offering, locale string) clientmodels.TrustedParty {
	issuer := clientmodels.TrustedParty{}
	if offering.IssuerMetadataURL != "" {
		issuer.Id = offering.IssuerMetadataURL
		if metadata := s.issuerMetadata(ctx, offering.IssuerMetadataURL); metadata != nil {
			if metadata.Id != "" {
				issuer.Id = metadata.Id
			}
			issuer.Name = clientmodels.Resolve(metadata.Name, locale)
		}
	}
	if entity := entityForHost(snapshot, offeringHost(offering)); entity != nil {
		if name := clientmodels.Resolve(entity.Name, locale); name != "" {
			issuer.Name = name
		}
		issuer.TrustLevel = entity.TrustLevel
		if issuer.Id == "" {
			issuer.Id = entity.ID
		}
	}
	return issuer
}

// offeringHost is the host an offering is recognized by: the credential
// issuer's, or failing that the default issuance page's.
func offeringHost(offering *walletconfig.Offering) string {
	for _, candidate := range []string{offering.IssuerMetadataURL, offering.IssuanceURLs[walletconfig.DefaultIssuanceURLKey]} {
		if parsed, err := url.Parse(candidate); err == nil && parsed.Hostname() != "" {
			return strings.ToLower(parsed.Hostname())
		}
	}
	return ""
}

// entityForHost is the issuer entity one of whose handles carries host: a
// certificate with host among its subject alternative names, or a did:web at
// that domain. CA handles are not consulted: a CA's certificate says nothing
// about the hosts of the parties under it.
func entityForHost(snapshot walletconfig.Snapshot, host string) *walletconfig.TrustedEntity {
	if host == "" {
		return nil
	}
	consider := func(entities []walletconfig.TrustedEntity) *walletconfig.TrustedEntity {
		for i := range entities {
			entity := &entities[i]
			if !entity.HasRole(walletconfig.RoleIssuer) {
				continue
			}
			for j := range entity.Handles {
				if handleCarriesHost(&entity.Handles[j], host) {
					return entity
				}
			}
		}
		return nil
	}
	if entity := consider(snapshot.Environment.BuiltinEntities); entity != nil {
		return entity
	}
	if snapshot.Config != nil {
		return consider(snapshot.Config.TrustedEntities)
	}
	return nil
}

func handleCarriesHost(handle *walletconfig.Handle, host string) bool {
	switch handle.Type {
	case walletconfig.HandleTypeX509Cert:
		if handle.Certificate == nil || handle.Certificate.Certificate == nil {
			return false
		}
		certificate := handle.Certificate.Certificate
		if slices.ContainsFunc(certificate.DNSNames, func(name string) bool { return strings.EqualFold(name, host) }) {
			return true
		}
		return slices.ContainsFunc(certificate.URIs, func(uri *url.URL) bool {
			return uri != nil && strings.EqualFold(uri.Hostname(), host)
		})
	case walletconfig.HandleTypeDID:
		domain, ok := didWebDomain(handle.DID)
		return ok && strings.EqualFold(domain, host)
	}
	return false
}

// didWebDomain is the domain a did:web names, with a percent-encoded port
// stripped, or false for any other DID.
func didWebDomain(did string) (string, bool) {
	rest, ok := strings.CutPrefix(did, "did:web:")
	if !ok {
		return "", false
	}
	domain, _, _ := strings.Cut(rest, ":")
	if decoded, err := url.PathUnescape(domain); err == nil {
		domain = decoded
	}
	if hostOnly, _, found := strings.Cut(domain, ":"); found {
		domain = hostOnly
	}
	return domain, domain != ""
}

// CatalogCredentialName is the display name for a catalogued credential type:
// from its type metadata for the locale, or the raw vct as the last resort.
func CatalogCredentialName(metadata *typemetadata.VctTypeMetadata, vct, locale string) string {
	if name := clientmodels.Resolve(metadata.Names(), locale); name != "" {
		return name
	}
	return vct
}

// catalogAttributes lists the claims the type metadata describes, named for the
// locale and without values: what a credential of this type would carry.
func catalogAttributes(metadata *typemetadata.VctTypeMetadata, locale string) []clientmodels.Attribute {
	if metadata == nil {
		return nil
	}
	attributes := make([]clientmodels.Attribute, 0, len(metadata.Claims))
	for _, claim := range metadata.Claims {
		if len(claim.Path) == 0 {
			continue
		}
		attributes = append(attributes, clientmodels.Attribute{
			ClaimPath:   slices.Clone(claim.Path),
			DisplayName: clientmodels.ResolvePtr(metadata.ClaimNames(claim.Path), locale),
		})
	}
	return attributes
}
