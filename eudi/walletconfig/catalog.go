package walletconfig

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// CurrentSchemaVersion is the schema this code base writes: major
// SupportedSchemaMajor, minor 1, which added the credential catalogue. A config
// declaring minor 0 is read all the same; it just carries no catalogue.
const CurrentSchemaVersion = "1.1"

// DefaultIssuanceURLKey is the issuance_urls key every offering must carry: the
// web URL to hand the browser when no URL is listed for the wallet's locale.
const DefaultIssuanceURLKey = "default"

// CatalogEntry is one credential type in the catalogue: the OpenID4VC analogue
// of the IRMA scheme's credential store, a lookup from credential type (vct) to
// where it can be issued. Entries are self-contained and reference no trusted
// entity: the catalogue lists credentials, it vouches for nobody. Display
// information — names, attributes, logos — comes from the credential type's
// metadata and the issuer's metadata, not from the config.
type CatalogEntry struct {
	// VCT is the credential type, URL or URN, unique within the catalogue.
	VCT string `json:"vct"`

	// VCTMetadataURL is where the SD-JWT VC type metadata for this type is
	// published, for display and claim resolution. Optional: when absent and the
	// vct is an HTTP URL, the vct itself is fetched. It is what makes a URN vct
	// resolvable at all.
	VCTMetadataURL string `json:"vct_metadata_url,omitempty"`

	// InStore opts the entry into the browsable store's OpenID4VC section. Off
	// by default: an entry is there to make a disclosure completable, not
	// necessarily to advertise the credential.
	InStore bool `json:"in_store,omitempty"`

	// Offerings are the places the credential can be obtained, one per issuing
	// party. Several parties issuing the same type are several offerings.
	Offerings []Offering `json:"offerings"`
}

// Offering is one place a credential type can be obtained.
type Offering struct {
	// IssuanceURLs maps a language tag to the web page where issuance starts
	// (browser handoff, the IRMA scheme's IssueURL model). The "default" key is
	// required; other tags are optional. In-wallet OpenID4VCI issuance from the
	// catalogue is a later addition, as a typed URL.
	IssuanceURLs map[string]string `json:"issuance_urls"`

	// IssuerMetadataURL is the OpenID4VCI credential issuer whose metadata
	// supplies issuer-specific display information, merged with the type
	// metadata. Optional.
	IssuerMetadataURL string `json:"issuer_metadata_url,omitempty"`
}

// IssuanceURL is the web URL to open for a locale: the exact tag, then its base
// language (nl-BE → nl), then the default.
func (o *Offering) IssuanceURL(locale string) string {
	if locale != "" {
		if url, ok := o.IssuanceURLs[locale]; ok {
			return url
		}
		if base, _, found := strings.Cut(locale, "-"); found {
			if url, ok := o.IssuanceURLs[base]; ok {
				return url
			}
		}
	}
	return o.IssuanceURLs[DefaultIssuanceURLKey]
}

// MetadataURL is where the type metadata for this entry is fetched from: the
// listed URL, or the vct itself when it is an HTTP URL. Empty when neither
// applies, which is a URN vct without a listed metadata URL.
func (e *CatalogEntry) MetadataURL() string {
	if e.VCTMetadataURL != "" {
		return e.VCTMetadataURL
	}
	if strings.HasPrefix(e.VCT, "https://") || strings.HasPrefix(e.VCT, "http://") {
		return e.VCT
	}
	return ""
}

// CatalogEntry is the catalogue entry for a credential type, or nil when the
// catalogue does not list it.
func (c *Config) CatalogEntry(vct string) *CatalogEntry {
	for i := range c.CredentialCatalog {
		if c.CredentialCatalog[i].VCT == vct {
			return &c.CredentialCatalog[i]
		}
	}
	return nil
}

// languageTag is the shape an issuance_urls key may take besides "default": a
// BCP 47 language tag, loosely — a 2 or 3 letter language, optional subtags.
var languageTag = regexp.MustCompile(`^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{1,8})*$`)

func validateCatalog(entries []CatalogEntry) []error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}
	seen := map[string]bool{}
	for i := range entries {
		entry := &entries[i]
		at := fmt.Sprintf("credential_catalog[%d]", i)
		if entry.VCT != "" {
			at = fmt.Sprintf("%s (%q)", at, entry.VCT)
		}
		switch {
		case entry.VCT == "":
			fail("%s: vct is required", at)
		case seen[entry.VCT]:
			fail("%s: vct is listed by another entry", at)
		}
		seen[entry.VCT] = true

		if entry.VCTMetadataURL != "" {
			if err := requireHTTPSURL(entry.VCTMetadataURL); err != nil {
				fail("%s: vct_metadata_url: %v", at, err)
			}
		}
		if len(entry.Offerings) == 0 {
			fail("%s: offerings is required", at)
		}
		for j := range entry.Offerings {
			for _, err := range entry.Offerings[j].validate() {
				fail("%s: offerings[%d]: %v", at, j, err)
			}
		}
	}
	return errs
}

func (o *Offering) validate() []error {
	var errs []error
	if _, ok := o.IssuanceURLs[DefaultIssuanceURLKey]; !ok {
		errs = append(errs, errors.New(`issuance_urls needs a "default" entry`))
	}
	for tag, url := range o.IssuanceURLs {
		if tag != DefaultIssuanceURLKey && !languageTag.MatchString(tag) {
			errs = append(errs, fmt.Errorf("issuance_urls: %q is not a language tag", tag))
		}
		if err := requireHTTPSURL(url); err != nil {
			errs = append(errs, fmt.Errorf("issuance_urls[%q]: %v", tag, err))
		}
	}
	if o.IssuerMetadataURL != "" {
		if err := requireHTTPSURL(o.IssuerMetadataURL); err != nil {
			errs = append(errs, fmt.Errorf("issuer_metadata_url: %v", err))
		}
	}
	return errs
}
