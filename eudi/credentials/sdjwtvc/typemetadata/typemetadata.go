// Package typemetadata fetches SD-JWT VC Type Metadata documents and OpenID4VCI
// issuer metadata documents needed to describe a credential type whose issuer
// the wallet has never seen. Used by the OpenID4VP disclosure flow when a
// verifier requests a credential the wallet cannot produce.
package typemetadata

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// VctTypeMetadata is the parsed shape of a SD-JWT VC Type Metadata document
// (draft-ietf-oauth-sd-jwt-vc Section 6). The IssuerURL field is non-standard
// and is filled from a top-level "issuer" key when the document defines one
// (a yivi-stack convention).
type VctTypeMetadata struct {
	// Name is the document-level human-readable credential name.
	Name string
	// Display contains localized credential names and (optionally) logos.
	Display []DisplayEntry
	// Claims contains the credential's claim metadata: path + localized display.
	Claims []ClaimMetadata
	// IssuerURL is the optional "issuer" hint — the URL where the issuer's
	// well-known document can be fetched.
	IssuerURL string
}

// DisplayEntry is one localized display entry from the type-metadata document.
// The SD-JWT VC spec uses "lang", not "locale".
type DisplayEntry struct {
	Lang string
	Name string
	Logo *RemoteImage
}

// ClaimMetadata is one claim metadata entry from the type-metadata document.
type ClaimMetadata struct {
	Path    []any
	Display []ClaimDisplayEntry
}

// ClaimDisplayEntry is one localized display entry for a single claim.
type ClaimDisplayEntry struct {
	Lang string
	Name string
}

// RemoteImage is a logo reference in a display entry.
type RemoteImage struct {
	URI     string
	AltText string
}

// IssuerMetadata is a slim view of the OpenID4VCI issuer metadata: only the
// fields we need to describe an unobtainable credential to the user. Logo URL
// is parsed but not downloaded — the unobtainable-descriptor path stays inside
// the user's permission-prompt blocking budget. Frontend can fetch the URL
// itself if it wants to render the logo.
type IssuerMetadata struct {
	Id      string
	Name    clientmodels.TranslatedString
	LogoURI string
}

// VctFetcher fetches and parses the type-metadata document for a VCT URL.
type VctFetcher interface {
	Fetch(ctx context.Context, vctURL string) (*VctTypeMetadata, error)
}

// IssuerFetcher fetches and parses the OpenID4VCI well-known document for an
// issuer URL.
type IssuerFetcher interface {
	Fetch(ctx context.Context, issuerURL string) (*IssuerMetadata, error)
}

const defaultRequestTimeout = 3 * time.Second

// NewDefaultVctFetcher returns a VctFetcher that GETs the VCT URL with a 3s
// per-request timeout and no caching. Failures return an error; the caller is
// expected to log + degrade.
func NewDefaultVctFetcher(client *http.Client) VctFetcher {
	if client == nil {
		client = &http.Client{Timeout: defaultRequestTimeout}
	}
	return &httpVctFetcher{client: client}
}

// NewDefaultIssuerFetcher returns an IssuerFetcher that GETs the issuer's
// well-known/openid-credential-issuer document with a 3s per-request timeout
// and no caching.
func NewDefaultIssuerFetcher(client *http.Client) IssuerFetcher {
	if client == nil {
		client = &http.Client{Timeout: defaultRequestTimeout}
	}
	return &httpIssuerFetcher{client: client}
}

type httpVctFetcher struct {
	client *http.Client
}

func (f *httpVctFetcher) Fetch(ctx context.Context, vctURL string) (*VctTypeMetadata, error) {
	body, err := getJSON(ctx, f.client, vctURL)
	if err != nil {
		return nil, err
	}
	return ParseVctTypeMetadata(body)
}

type httpIssuerFetcher struct {
	client *http.Client
}

func (f *httpIssuerFetcher) Fetch(ctx context.Context, issuerURL string) (*IssuerMetadata, error) {
	wkURL, err := wellKnownIssuerURL(issuerURL)
	if err != nil {
		return nil, err
	}
	body, err := getJSON(ctx, f.client, wkURL)
	if err != nil {
		return nil, err
	}
	return ParseIssuerMetadata(body, issuerURL)
}

// wellKnownIssuerURL inserts /.well-known/openid-credential-issuer between the
// host and the issuer's path component, matching the OpenID4VCI spec for
// multi-tenant issuers.
func wellKnownIssuerURL(issuerURL string) (string, error) {
	if issuerURL == "" {
		return "", fmt.Errorf("issuer URL is empty")
	}
	scheme, hostAndPath, ok := strings.Cut(issuerURL, "://")
	if !ok {
		return "", fmt.Errorf("issuer URL %q has no scheme", issuerURL)
	}
	host, p, _ := strings.Cut(hostAndPath, "/")
	if p == "" {
		return scheme + "://" + host + "/.well-known/openid-credential-issuer", nil
	}
	return scheme + "://" + host + path.Join("/.well-known/openid-credential-issuer", "/"+p), nil
}

func getJSON(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, defaultRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request to %s returned status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ParseVctTypeMetadata decodes a SD-JWT VC Type Metadata document. Tolerant to
// missing/extra fields. Returns a non-nil result when the JSON parses.
func ParseVctTypeMetadata(data []byte) (*VctTypeMetadata, error) {
	var raw rawVctDocument
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse VCT type metadata: %w", err)
	}

	out := &VctTypeMetadata{
		Name:      raw.Name,
		IssuerURL: raw.Issuer,
	}
	for _, d := range raw.Display {
		entry := DisplayEntry{Lang: d.Lang, Name: d.Name}
		if d.Logo != nil {
			entry.Logo = &RemoteImage{URI: d.Logo.URI, AltText: d.Logo.AltText}
		}
		out.Display = append(out.Display, entry)
	}
	for _, c := range raw.Claims {
		cm := ClaimMetadata{Path: c.Path}
		for _, d := range c.Display {
			cm.Display = append(cm.Display, ClaimDisplayEntry(d))
		}
		out.Claims = append(out.Claims, cm)
	}
	return out, nil
}

// ParseIssuerMetadata decodes the OpenID4VCI issuer metadata document and
// extracts only the slim fields we need (name + logo). issuerURL is the URL we
// used to discover this document; it becomes IssuerMetadata.Id.
func ParseIssuerMetadata(data []byte, issuerURL string) (*IssuerMetadata, error) {
	var raw rawIssuerDocument
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse issuer metadata: %w", err)
	}

	id := raw.CredentialIssuer
	if id == "" {
		id = issuerURL
	}

	name := clientmodels.TranslatedString{}
	var logoURI string
	for _, d := range raw.Display {
		locale := d.Locale
		if locale == "" {
			locale = clientmodels.DefaultFallbackLanguage
		}
		if d.Name != "" {
			name[locale] = d.Name
		}
		if logoURI == "" && d.Logo != nil && d.Logo.URI != "" {
			logoURI = d.Logo.URI
		}
	}

	return &IssuerMetadata{
		Id:      id,
		Name:    name,
		LogoURI: logoURI,
	}, nil
}

// --- raw JSON shapes ---

type rawVctDocument struct {
	Name    string          `json:"name"`
	Display []rawVctDisplay `json:"display"`
	Claims  []rawVctClaim   `json:"claims"`
	Issuer  string          `json:"issuer"`
}

type rawVctDisplay struct {
	Lang string        `json:"lang"`
	Name string        `json:"name"`
	Logo *rawRemoteImg `json:"logo,omitempty"`
}

type rawVctClaim struct {
	Path    []any             `json:"path"`
	Display []rawClaimDisplay `json:"display"`
}

type rawClaimDisplay struct {
	Lang string `json:"lang"`
	Name string `json:"name"`
}

type rawRemoteImg struct {
	URI     string `json:"uri"`
	AltText string `json:"alt_text,omitempty"`
}

type rawIssuerDocument struct {
	CredentialIssuer string             `json:"credential_issuer"`
	Display          []rawIssuerDisplay `json:"display"`
}

type rawIssuerDisplay struct {
	Name   string        `json:"name"`
	Locale string        `json:"locale"`
	Logo   *rawRemoteImg `json:"logo,omitempty"`
}
