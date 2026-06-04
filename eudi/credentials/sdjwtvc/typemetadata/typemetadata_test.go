package typemetadata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

func TestParseVctTypeMetadata_FullDocument(t *testing.T) {
	doc := []byte(`{
		"name": "Email Credential",
		"issuer": "https://issuer.example.com",
		"display": [
			{ "lang": "en", "name": "Email Credential", "logo": { "uri": "https://example.com/logo.png" } },
			{ "lang": "nl", "name": "E-mail credential" }
		],
		"claims": [
			{
				"path": ["email"],
				"display": [
					{ "lang": "en", "label": "Email" },
					{ "lang": "nl", "label": "E-mailadres" }
				]
			}
		]
	}`)

	parsed, err := ParseVctTypeMetadata(doc)
	require.NoError(t, err)

	require.Equal(t, "Email Credential", parsed.Name)
	require.Equal(t, "https://issuer.example.com", parsed.IssuerURL)
	require.Len(t, parsed.Display, 2)
	require.Equal(t, "en", parsed.Display[0].Locale)
	require.Equal(t, "Email Credential", parsed.Display[0].Name)
	require.NotNil(t, parsed.Display[0].Logo)
	require.Equal(t, "https://example.com/logo.png", parsed.Display[0].Logo.URI)
	require.Nil(t, parsed.Display[1].Logo)
	require.Len(t, parsed.Claims, 1)
	require.Equal(t, []any{"email"}, parsed.Claims[0].Path)
	require.Len(t, parsed.Claims[0].Display, 2)
	require.Equal(t, "en", parsed.Claims[0].Display[0].Locale)
	require.Equal(t, "Email", parsed.Claims[0].Display[0].Name)
}

// TestParseVctTypeMetadata_LocaleAndLabelAliases pins parsing of the current
// SD-JWT VC draft (≥ draft-16) shape: "locale" rather than "lang", and "label"
// rather than "name" for claim display. Without this, the wallet ends up
// showing the last-locale credential name (e.g. ja-JP wins everywhere) and
// empty claim display names.
func TestParseVctTypeMetadata_LocaleAndLabelAliases(t *testing.T) {
	doc := []byte(`{
		"display": [
			{ "locale": "en-US", "name": "Test Credential" },
			{ "locale": "ja-JP", "name": "テストクレデンシャル" }
		],
		"claims": [
			{
				"path": ["given_name"],
				"display": [
					{ "locale": "en-US", "label": "Given Name" },
					{ "locale": "ja-JP", "label": "名" }
				]
			}
		]
	}`)

	parsed, err := ParseVctTypeMetadata(doc)
	require.NoError(t, err)
	require.Len(t, parsed.Display, 2)
	require.Equal(t, "en-US", parsed.Display[0].Locale)
	require.Equal(t, "Test Credential", parsed.Display[0].Name)
	require.Equal(t, "ja-JP", parsed.Display[1].Locale)
	require.Equal(t, "テストクレデンシャル", parsed.Display[1].Name)

	require.Len(t, parsed.Claims, 1)
	require.Len(t, parsed.Claims[0].Display, 2)
	require.Equal(t, "en-US", parsed.Claims[0].Display[0].Locale)
	require.Equal(t, "Given Name", parsed.Claims[0].Display[0].Name)
	require.Equal(t, "ja-JP", parsed.Claims[0].Display[1].Locale)
	require.Equal(t, "名", parsed.Claims[0].Display[1].Name)
}

// TestParseVctTypeMetadata_CurrentSpecFieldsPreferredOverLegacy asserts that
// when a document carries both the current-spec field ("locale", "label") and
// the legacy alias ("lang", "name") — e.g. for transitional compatibility —
// the current-spec field wins.
func TestParseVctTypeMetadata_CurrentSpecFieldsPreferredOverLegacy(t *testing.T) {
	doc := []byte(`{
		"display": [
			{ "lang": "en", "locale": "de", "name": "Cred" }
		],
		"claims": [
			{
				"path": ["x"],
				"display": [
					{ "lang": "en", "locale": "de", "label": "Spec label", "name": "Legacy name" }
				]
			}
		]
	}`)

	parsed, err := ParseVctTypeMetadata(doc)
	require.NoError(t, err)
	require.Equal(t, "de", parsed.Display[0].Locale)
	require.Equal(t, "de", parsed.Claims[0].Display[0].Locale)
	require.Equal(t, "Spec label", parsed.Claims[0].Display[0].Name)
}

// TestParseVctTypeMetadata_RenderingSimpleLogo ensures the wallet picks up the
// logo when it lives under rendering.simple.logo (the only place Sphereon puts
// it). Top-level "logo" still takes precedence when both are present.
func TestParseVctTypeMetadata_RenderingSimpleLogo(t *testing.T) {
	doc := []byte(`{
		"display": [
			{
				"locale": "en-US",
				"name": "Test Credential",
				"rendering": {
					"simple": {
						"logo": { "uri": "https://example.com/nested.png", "alt_text": "Nested" },
						"background_color": "#1a56db",
						"text_color": "#ffffff"
					}
				}
			},
			{
				"locale": "nl-NL",
				"name": "Test",
				"logo": { "uri": "https://example.com/top.png" },
				"rendering": {
					"simple": {
						"logo": { "uri": "https://example.com/nested-too.png" }
					}
				}
			}
		]
	}`)

	parsed, err := ParseVctTypeMetadata(doc)
	require.NoError(t, err)
	require.Len(t, parsed.Display, 2)
	require.NotNil(t, parsed.Display[0].Logo)
	require.Equal(t, "https://example.com/nested.png", parsed.Display[0].Logo.URI)
	require.Equal(t, "Nested", parsed.Display[0].Logo.AltText)
	require.Equal(t, "#1a56db", parsed.Display[0].BackgroundColor)
	require.NotNil(t, parsed.Display[1].Logo)
	require.Equal(t, "https://example.com/top.png", parsed.Display[1].Logo.URI, "top-level logo wins over rendering.simple.logo")
}

// TestParseVctTypeMetadata_SphereonStyleDocument is a regression test for the
// bridge-event output where the wallet rendered "テストクレデンシャル" (the
// last locale's credential name) under every language and empty strings for
// every claim display label. Documents in this exact shape are produced by
// https://sphereon-oid4vc.ngrok.dev/oid4vci/vct/TestCredential.
func TestParseVctTypeMetadata_SphereonStyleDocument(t *testing.T) {
	doc := []byte(`{
		"vct": "https://example.com/vct/Test",
		"name": "Test Credential",
		"description": "A test SD-JWT verifiable credential",
		"display": [
			{
				"locale": "en-US",
				"name": "Test Credential",
				"description": "A simple test credential",
				"rendering": {
					"simple": {
						"logo": { "uri": "https://example.com/logo.png", "alt_text": "Logo" },
						"background_color": "#1a56db",
						"text_color": "#ffffff"
					}
				}
			},
			{
				"locale": "nl-NL",
				"name": "Testcredential",
				"description": "Een testcredential",
				"rendering": {
					"simple": {
						"background_color": "#1a56db",
						"text_color": "#ffffff"
					}
				}
			},
			{
				"locale": "ja-JP",
				"name": "テストクレデンシャル",
				"description": "テスト",
				"rendering": {
					"simple": {
						"background_color": "#1a56db",
						"text_color": "#ffffff"
					}
				}
			}
		],
		"claims": [
			{
				"path": ["given_name"],
				"sd": "always",
				"display": [
					{ "locale": "en-US", "label": "Given Name", "description": "First name of the holder" },
					{ "locale": "nl-NL", "label": "Voornaam", "description": "Voornaam van de houder" }
				]
			},
			{
				"path": ["family_name"],
				"sd": "always",
				"display": [
					{ "locale": "en-US", "label": "Family Name" }
				]
			}
		]
	}`)

	parsed, err := ParseVctTypeMetadata(doc)
	require.NoError(t, err)

	require.Equal(t, "Test Credential", parsed.Name)
	require.Len(t, parsed.Display, 3)
	require.Equal(t, "en-US", parsed.Display[0].Locale)
	require.Equal(t, "Test Credential", parsed.Display[0].Name)
	require.NotNil(t, parsed.Display[0].Logo)
	require.Equal(t, "https://example.com/logo.png", parsed.Display[0].Logo.URI)
	require.Equal(t, "ja-JP", parsed.Display[2].Locale)
	require.Equal(t, "テストクレデンシャル", parsed.Display[2].Name)

	require.Len(t, parsed.Claims, 2)
	require.Equal(t, []any{"given_name"}, parsed.Claims[0].Path)
	require.Len(t, parsed.Claims[0].Display, 2)
	require.Equal(t, "en-US", parsed.Claims[0].Display[0].Locale)
	require.Equal(t, "Given Name", parsed.Claims[0].Display[0].Name)
	require.Equal(t, "Voornaam", parsed.Claims[0].Display[1].Name)
	require.Equal(t, "Family Name", parsed.Claims[1].Display[0].Name)
}

func TestParseVctTypeMetadata_NoIssuerField(t *testing.T) {
	doc := []byte(`{ "name": "Cred", "display": [{ "lang": "en", "name": "Cred" }] }`)
	parsed, err := ParseVctTypeMetadata(doc)
	require.NoError(t, err)
	require.Equal(t, "", parsed.IssuerURL)
	require.Len(t, parsed.Display, 1)
}

func TestParseVctTypeMetadata_NoDisplayEntries(t *testing.T) {
	doc := []byte(`{ "name": "RawName" }`)
	parsed, err := ParseVctTypeMetadata(doc)
	require.NoError(t, err)
	require.Equal(t, "RawName", parsed.Name)
	require.Empty(t, parsed.Display)
}

func TestParseVctTypeMetadata_InvalidJSON(t *testing.T) {
	_, err := ParseVctTypeMetadata([]byte(`{ not json`))
	require.Error(t, err)
}

func TestParseVctTypeMetadata_RichDisplayFields(t *testing.T) {
	doc := []byte(`{
		"name": "PID",
		"display": [
			{
				"lang": "en-US",
				"name": "Person ID",
				"description": "Government-issued personal identifier",
				"rendering": {
					"simple": {
						"background_color": "#0033A0",
						"text_color": "#FFFFFF"
					}
				}
			}
		]
	}`)
	parsed, err := ParseVctTypeMetadata(doc)
	require.NoError(t, err)
	require.Len(t, parsed.Display, 1)
	require.Equal(t, "Government-issued personal identifier", parsed.Display[0].Description)
	require.Equal(t, "#0033A0", parsed.Display[0].BackgroundColor)
	require.Equal(t, "#FFFFFF", parsed.Display[0].TextColor)
}

func TestParseVctTypeMetadata_ExtendsFields(t *testing.T) {
	doc := []byte(`{
		"name": "Refined PID",
		"extends": "https://issuer.example.com/types/parent",
		"extends#integrity": "sha256-abc123"
	}`)
	parsed, err := ParseVctTypeMetadata(doc)
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example.com/types/parent", parsed.Extends)
	require.Equal(t, "sha256-abc123", parsed.ExtendsIntegrity)
}

func TestParseIssuerMetadata_FullDocument(t *testing.T) {
	doc := []byte(`{
		"credential_issuer": "https://issuer.example.com",
		"display": [
			{ "name": "Example Issuer", "locale": "en", "logo": { "uri": "https://example.com/issuer-logo.png" } },
			{ "name": "Voorbeeldverstrekker", "locale": "nl" }
		]
	}`)

	parsed, err := ParseIssuerMetadata(doc, "https://discover.example.com")
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example.com", parsed.Id)
	require.Equal(t, "Example Issuer", parsed.Name["en"])
	require.Equal(t, "Voorbeeldverstrekker", parsed.Name["nl"])
	require.Equal(t, "https://example.com/issuer-logo.png", parsed.LogoURI)
}

func TestParseIssuerMetadata_FallbackId(t *testing.T) {
	doc := []byte(`{ "display": [{ "name": "X" }] }`)
	parsed, err := ParseIssuerMetadata(doc, "https://discover.example.com")
	require.NoError(t, err)
	require.Equal(t, "https://discover.example.com", parsed.Id, "Id falls back to the URL we discovered the document from")
	require.Equal(t, "X", parsed.Name[clientmodels.DefaultFallbackLanguage])
}

func TestParseIssuerMetadata_InvalidJSON(t *testing.T) {
	_, err := ParseIssuerMetadata([]byte(`not json`), "https://x.example.com")
	require.Error(t, err)
}

func TestVctFetcher_HappyPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/vct/email", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{ "name": "Email", "issuer": "https://issuer.example.com" }`))
	}))
	defer server.Close()

	fetcher := NewDefaultVctFetcher(server.Client())
	parsed, err := fetcher.Fetch(context.Background(), server.URL+"/vct/email")
	require.NoError(t, err)
	require.Equal(t, "Email", parsed.Name)
	require.Equal(t, "https://issuer.example.com", parsed.IssuerURL)
}

func TestVctFetcher_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	fetcher := NewDefaultVctFetcher(server.Client())
	_, err := fetcher.Fetch(context.Background(), server.URL+"/vct/nope")
	require.Error(t, err)
}

func TestVctFetcher_500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	fetcher := NewDefaultVctFetcher(server.Client())
	_, err := fetcher.Fetch(context.Background(), server.URL+"/vct/x")
	require.Error(t, err)
}

func TestIssuerFetcher_HappyPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/.well-known/openid-credential-issuer/issuer1", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"credential_issuer": "https://example.com/issuer1",
			"display": [{ "name": "Issuer One", "locale": "en" }]
		}`))
	}))
	defer server.Close()

	fetcher := NewDefaultIssuerFetcher(server.Client())
	parsed, err := fetcher.Fetch(context.Background(), server.URL+"/issuer1")
	require.NoError(t, err)
	require.Equal(t, "https://example.com/issuer1", parsed.Id)
	require.Equal(t, "Issuer One", parsed.Name["en"])
}

func TestIssuerFetcher_500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	fetcher := NewDefaultIssuerFetcher(server.Client())
	_, err := fetcher.Fetch(context.Background(), server.URL+"/issuer1")
	require.Error(t, err)
}

func TestWellKnownIssuerURL_NoPath(t *testing.T) {
	url, err := wellKnownIssuerURL("https://example.com")
	require.NoError(t, err)
	require.Equal(t, "https://example.com/.well-known/openid-credential-issuer", url)
}

func TestWellKnownIssuerURL_WithPath(t *testing.T) {
	url, err := wellKnownIssuerURL("https://example.com/issuer1")
	require.NoError(t, err)
	require.Equal(t, "https://example.com/.well-known/openid-credential-issuer/issuer1", url)
}

func TestWellKnownIssuerURL_NoScheme(t *testing.T) {
	_, err := wellKnownIssuerURL("example.com/issuer1")
	require.Error(t, err)
}
