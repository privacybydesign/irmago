package services

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/stretchr/testify/require"
)

// snapshotSource hands out a fixed snapshot.
type snapshotSource struct{ snapshot walletconfig.Snapshot }

func (s snapshotSource) Snapshot() walletconfig.Snapshot { return s.snapshot }

// countingVctFetcher serves canned type metadata and counts fetches.
type countingVctFetcher struct {
	docs  map[string]*typemetadata.VctTypeMetadata
	calls int
}

func (f *countingVctFetcher) Fetch(_ context.Context, vctURL string) (*typemetadata.VctTypeMetadata, error) {
	f.calls++
	if doc, ok := f.docs[vctURL]; ok {
		return doc, nil
	}
	return nil, errors.New("not found")
}

type countingIssuerFetcher struct {
	docs  map[string]*typemetadata.IssuerMetadata
	calls int
}

func (f *countingIssuerFetcher) Fetch(_ context.Context, issuerURL string) (*typemetadata.IssuerMetadata, error) {
	f.calls++
	if doc, ok := f.docs[issuerURL]; ok {
		return doc, nil
	}
	return nil, errors.New("not found")
}

const emailVct = "https://example.com/vct/email"

func emailMetadata() *typemetadata.VctTypeMetadata {
	return &typemetadata.VctTypeMetadata{
		Name:    "Email Credential",
		Display: []typemetadata.DisplayEntry{{Locale: "en", Name: "Email"}, {Locale: "nl", Name: "E-mail"}},
		Claims: []typemetadata.ClaimMetadata{
			{Path: []any{"email"}, Display: []typemetadata.ClaimDisplayEntry{{Locale: "en", Name: "Email address"}, {Locale: "nl", Name: "E-mailadres"}}},
			{Path: []any{"domain"}},
		},
	}
}

func catalogSnapshot(entries ...walletconfig.CatalogEntry) walletconfig.Snapshot {
	config := walletconfig.NewTestConfig("test", 1, time.Now())
	config.CredentialCatalog = entries
	return walletconfig.Snapshot{Environment: walletconfig.Environment{Name: "test"}, Config: config, Freshness: walletconfig.Fresh}
}

func emailCatalogEntry() walletconfig.CatalogEntry {
	return walletconfig.CatalogEntry{
		VCT:     emailVct,
		InStore: true,
		Offerings: []walletconfig.Offering{
			{
				IssuanceURLs:      map[string]string{"default": "https://issue.example.com/email", "nl": "https://issue.example.com/nl/email"},
				IssuerMetadataURL: "https://issuer.example.com",
			},
			{IssuanceURLs: map[string]string{"default": "https://other.example.org/email"}},
		},
	}
}

func TestCatalogService_MissWhenNothingIsListed(t *testing.T) {
	service := NewCatalogService(snapshotSource{catalogSnapshot(emailCatalogEntry())}, nil, nil)
	require.Nil(t, service.Lookup(context.Background(), "https://example.com/vct/other", "en"))

	noConfig := NewCatalogService(snapshotSource{walletconfig.Snapshot{}}, nil, nil)
	require.Nil(t, noConfig.Lookup(context.Background(), emailVct, "en"))
	require.Nil(t, noConfig.StoreItems(context.Background(), "en"))
}

func TestCatalogService_HitResolvesEveryOfferingForTheLocale(t *testing.T) {
	vct := &countingVctFetcher{docs: map[string]*typemetadata.VctTypeMetadata{emailVct: emailMetadata()}}
	issuers := &countingIssuerFetcher{docs: map[string]*typemetadata.IssuerMetadata{
		"https://issuer.example.com": {Id: "https://issuer.example.com", Name: clientmodels.TranslatedString{"en": "Example Issuer", "nl": "Voorbeelduitgever"}},
	}}
	service := NewCatalogService(snapshotSource{catalogSnapshot(emailCatalogEntry())}, vct, issuers)

	hit := service.Lookup(context.Background(), emailVct, "nl")
	require.NotNil(t, hit)
	require.Equal(t, emailVct, hit.Entry.VCT)
	require.NotNil(t, hit.Metadata, "an HTTP vct is fetched as its own metadata URL")
	require.Equal(t, "E-mail", CatalogCredentialName(hit.Metadata, emailVct, "nl"))

	require.Len(t, hit.Offerings, 2, "one per offering")
	require.Equal(t, "https://issue.example.com/nl/email", hit.Offerings[0].IssueURL, "the locale's URL")
	require.Equal(t, "Voorbeelduitgever", hit.Offerings[0].Issuer.Name)
	require.Equal(t, "https://issuer.example.com", hit.Offerings[0].Issuer.Id)
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, hit.Offerings[0].Issuer.TrustLevel, "the catalogue is not a trust level")

	require.Equal(t, "https://other.example.org/email", hit.Offerings[1].IssueURL, "no Dutch URL, so the default")
	require.Empty(t, hit.Offerings[1].Issuer.Name, "no issuer metadata listed, nothing to name it by")
}

func TestCatalogService_URNResolvesThroughTheListedMetadataURL(t *testing.T) {
	entry := walletconfig.CatalogEntry{
		VCT:            "urn:eudi:pid:1",
		VCTMetadataURL: "https://metadata.example.com/pid.json",
		Offerings:      []walletconfig.Offering{{IssuanceURLs: map[string]string{"default": "https://pid.example.com/start"}}},
	}
	vct := &countingVctFetcher{docs: map[string]*typemetadata.VctTypeMetadata{
		"https://metadata.example.com/pid.json": {Display: []typemetadata.DisplayEntry{{Locale: "en", Name: "Person Identification Data"}}},
	}}
	service := NewCatalogService(snapshotSource{catalogSnapshot(entry)}, vct, nil)

	hit := service.Lookup(context.Background(), "urn:eudi:pid:1", "en")
	require.NotNil(t, hit)
	require.Equal(t, "Person Identification Data", CatalogCredentialName(hit.Metadata, "urn:eudi:pid:1", "en"))

	bare := walletconfig.CatalogEntry{VCT: "urn:eudi:pid:2", Offerings: entry.Offerings}
	service = NewCatalogService(snapshotSource{catalogSnapshot(bare)}, vct, nil)
	hit = service.Lookup(context.Background(), "urn:eudi:pid:2", "en")
	require.NotNil(t, hit)
	require.Nil(t, hit.Metadata, "a URN without a metadata URL cannot be fetched")
	require.Equal(t, "urn:eudi:pid:2", CatalogCredentialName(hit.Metadata, "urn:eudi:pid:2", "en"), "the raw vct is the last resort")
	require.Equal(t, 1, vct.calls, "nothing was fetched for it")
}

// The offering's party may be a trusted entity, recognized by the host it
// issues from; then the entity's name and level are shown.
func TestCatalogService_SoftMatchesTheOfferingToATrustedEntity(t *testing.T) {
	caKey, ca := walletconfig.NewTestCA(t, "Issuer CA", nil, nil)
	_, certificate := walletconfig.NewTestEndEntity(t, "issuer.example.com", ca, caKey, func(template *x509.Certificate) {
		template.DNSNames = []string{"issuer.example.com"}
		template.URIs = []*url.URL{{Scheme: "https", Host: "issuer.example.com"}}
	})
	snapshot := catalogSnapshot(emailCatalogEntry())
	snapshot.Config.TrustedEntities = []walletconfig.TrustedEntity{
		{
			ID: "by-cert", Name: clientmodels.TranslatedString{"en": "Certified Issuer"},
			Roles: []walletconfig.Role{walletconfig.RoleIssuer}, TrustLevel: clientmodels.TrustLevel_High,
			Handles: []walletconfig.Handle{{Type: walletconfig.HandleTypeX509Cert, Certificate: &walletconfig.Certificate{Certificate: certificate}}},
		},
		{
			ID: "by-did", Name: clientmodels.TranslatedString{"en": "DID Issuer"},
			Roles: []walletconfig.Role{walletconfig.RoleIssuer}, TrustLevel: clientmodels.TrustLevel_Medium,
			Handles: []walletconfig.Handle{{Type: walletconfig.HandleTypeDID, DID: "did:web:other.example.org"}},
		},
		{
			ID: "verifier-only", Name: clientmodels.TranslatedString{"en": "Verifier"},
			Roles: []walletconfig.Role{walletconfig.RoleVerifier}, TrustLevel: clientmodels.TrustLevel_High,
			Handles: []walletconfig.Handle{{Type: walletconfig.HandleTypeDID, DID: "did:web:issuer.example.com"}},
		},
	}
	service := NewCatalogService(snapshotSource{snapshot}, nil, nil)

	hit := service.Lookup(context.Background(), emailVct, "en")
	require.NotNil(t, hit)
	require.Equal(t, "Certified Issuer", hit.Offerings[0].Issuer.Name, "matched by the issuer metadata URL's host against the certificate's SAN")
	require.Equal(t, clientmodels.TrustLevel_High, hit.Offerings[0].Issuer.TrustLevel)
	require.Equal(t, "DID Issuer", hit.Offerings[1].Issuer.Name, "matched by the default issuance URL's host against the did:web domain")
	require.Equal(t, clientmodels.TrustLevel_Medium, hit.Offerings[1].Issuer.TrustLevel)
	require.Equal(t, "by-did", hit.Offerings[1].Issuer.Id, "an entity id stands in when the offering names no issuer")
}

func TestCatalogService_CachesMetadataForOneConfigIssue(t *testing.T) {
	vct := &countingVctFetcher{docs: map[string]*typemetadata.VctTypeMetadata{emailVct: emailMetadata()}}
	issuers := &countingIssuerFetcher{docs: map[string]*typemetadata.IssuerMetadata{"https://issuer.example.com": {Id: "https://issuer.example.com"}}}
	source := &snapshotSource{catalogSnapshot(emailCatalogEntry())}
	service := NewCatalogService(source, vct, issuers)

	for range 3 {
		require.NotNil(t, service.Lookup(context.Background(), emailVct, "en"))
	}
	require.Equal(t, 1, vct.calls)
	require.Equal(t, 1, issuers.calls)

	// A new issue of the config empties the cache: it may point the vct elsewhere.
	source.snapshot.Config.Version = 2
	require.NotNil(t, service.Lookup(context.Background(), emailVct, "en"))
	require.Equal(t, 2, vct.calls)
	require.Equal(t, 2, issuers.calls)
}

func TestCatalogService_DoesNotCacheAFailedFetch(t *testing.T) {
	vct := &countingVctFetcher{}
	service := NewCatalogService(snapshotSource{catalogSnapshot(emailCatalogEntry())}, vct, nil)

	require.Nil(t, service.Lookup(context.Background(), emailVct, "en").Metadata)
	require.Nil(t, service.Lookup(context.Background(), emailVct, "en").Metadata)
	require.Equal(t, 2, vct.calls, "a transient failure is retried")
}

func TestCatalogService_StoreItemsListOptedInEntriesOnly(t *testing.T) {
	inStore := emailCatalogEntry()
	notInStore := walletconfig.CatalogEntry{
		VCT:       "https://example.com/vct/hidden",
		Offerings: []walletconfig.Offering{{IssuanceURLs: map[string]string{"default": "https://issue.example.com/hidden"}}},
	}
	vct := &countingVctFetcher{docs: map[string]*typemetadata.VctTypeMetadata{emailVct: emailMetadata()}}
	service := NewCatalogService(snapshotSource{catalogSnapshot(inStore, notInStore)}, vct, nil)

	items := service.StoreItems(context.Background(), "nl")
	require.Len(t, items, 2, "one item per offering of the opted-in entry")
	require.Equal(t, emailVct, items[0].CredentialId)
	require.Equal(t, "E-mail", items[0].Name)
	require.Equal(t, "https://issue.example.com/nl/email", *items[0].IssueURL)
	require.Equal(t, "https://other.example.org/email", *items[1].IssueURL)
	require.Len(t, items[0].Attributes, 2, "the claims the type metadata describes")
	require.Equal(t, []any{"email"}, items[0].Attributes[0].ClaimPath)
	require.Equal(t, "E-mailadres", *items[0].Attributes[0].DisplayName)
	require.Nil(t, items[0].Attributes[1].DisplayName, "a claim the metadata does not name has no display name")
	require.Nil(t, items[0].Attributes[1].Value)
}

func TestDidWebDomain(t *testing.T) {
	domain, ok := didWebDomain("did:web:issuer.example.com")
	require.True(t, ok)
	require.Equal(t, "issuer.example.com", domain)
	domain, ok = didWebDomain("did:web:localhost%3A8443:issuer")
	require.True(t, ok)
	require.Equal(t, "localhost", domain, "a percent-encoded port is stripped")
	_, ok = didWebDomain("did:jwk:eyJ")
	require.False(t, ok)
}
