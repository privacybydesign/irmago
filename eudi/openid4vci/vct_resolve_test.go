package openid4vci

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/stretchr/testify/require"
)

// --- resolveCredentialMetadataFromVct ---

func TestResolveCredentialMetadataFromVct_ReplacesOnSuccess(t *testing.T) {
	srv := newVctTestServer(t, map[string]string{
		"/vct/Email": `{
			"name": "Email Credential",
			"display": [
				{ "lang": "en", "name": "Email", "description": "Email address" }
			],
			"claims": [{ "path": ["email"] }]
		}`,
	})
	defer srv.Close()

	client := &Client{httpClient: srv.Client(), allowInsecureHttp: true}
	resolver := typemetadata.NewResolver(srv.Client())
	issuerMeta := singleConfigMetadata("Email", metadata.CredentialConfiguration{
		Format:                   metadata.CredentialFormatIdentifier_SdJwtVc,
		VerifiableCredentialType: srv.URL + "/vct/Email",
		CredentialMetadata: &metadata.CredentialMetadata{
			// Pre-existing OID4VCI credential_metadata that VCT should override.
			Display: metadata.CredentialDisplays{
				{Display: metadata.Display{Name: "FROM_CREDMETA"}},
			},
		},
	})
	offer := &CredentialOffer{CredentialConfigurationIds: []string{"Email"}}

	client.resolveCredentialMetadataFromVct(context.Background(), offer, issuerMeta, resolver)

	got := issuerMeta.CredentialConfigurationsSupported["Email"].CredentialMetadata
	require.NotNil(t, got)
	require.Len(t, got.Display, 1)
	require.Equal(t, "Email", got.Display[0].Name, "VCT type metadata should override credential_metadata wholesale")
	require.Equal(t, "Email address", got.Display[0].Description)
	require.Len(t, got.Claims, 1)
}

// TestResolveCredentialMetadataFromVct_VctWinsOverCredentialMetadata_SphereonShape
// asserts that when the issuer ships both an OID4VCI credential_metadata block
// and a fetchable SD-JWT VC type-metadata document, the wallet displays the VCT
// values — including current-spec "locale"+"label" claim displays and a logo
// nested under rendering.simple.logo. Each VCT value is deliberately distinct
// from its credential_metadata counterpart so the test fails if the wrong path
// wins.
func TestResolveCredentialMetadataFromVct_VctWinsOverCredentialMetadata_SphereonShape(t *testing.T) {
	srv := newVctTestServer(t, map[string]string{
		"/vct/Test": `{
			"name": "Test Credential",
			"display": [
				{
					"locale": "en-US",
					"name": "Test Credential (from VCT)",
					"rendering": {
						"simple": {
							"logo": { "uri": "https://example.com/vct-logo.png", "alt_text": "VCT Logo" },
							"background_color": "#1a56db",
							"text_color": "#ffffff"
						}
					}
				}
			],
			"claims": [
				{
					"path": ["given_name"],
					"display": [
						{ "locale": "en-US", "label": "Given Name (from VCT)" },
						{ "locale": "nl-NL", "label": "Voornaam (from VCT)" }
					]
				},
				{
					"path": ["email"],
					"display": [
						{ "locale": "en-US", "label": "Email (from VCT)" }
					]
				}
			]
		}`,
	})
	defer srv.Close()

	enLocale := "en"
	client := &Client{httpClient: srv.Client(), allowInsecureHttp: true}
	resolver := typemetadata.NewResolver(srv.Client())
	issuerMeta := singleConfigMetadata("Test", metadata.CredentialConfiguration{
		Format:                   metadata.CredentialFormatIdentifier_SdJwtVc,
		VerifiableCredentialType: srv.URL + "/vct/Test",
		CredentialMetadata: &metadata.CredentialMetadata{
			// credential_metadata uses sentinel names so we can detect if the
			// wallet wrongly preferred it over the VCT.
			Display: metadata.CredentialDisplays{
				{Display: metadata.Display{Name: "Test Credential (from credential_metadata)", Locale: &enLocale}},
			},
			Claims: []metadata.ClaimsDescription{
				{
					Path: metadata.ClaimsPathPointer{"given_name"},
					Display: []metadata.Display{
						{Name: "Given Name (from credential_metadata)", Locale: &enLocale},
					},
				},
				{
					Path: metadata.ClaimsPathPointer{"email"},
					Display: []metadata.Display{
						{Name: "Email (from credential_metadata)", Locale: &enLocale},
					},
				},
			},
		},
	})
	offer := &CredentialOffer{CredentialConfigurationIds: []string{"Test"}}

	client.resolveCredentialMetadataFromVct(context.Background(), offer, issuerMeta, resolver)

	got := issuerMeta.CredentialConfigurationsSupported["Test"].CredentialMetadata
	require.NotNil(t, got)

	// Credential-level display: VCT name + VCT logo (nested in rendering.simple).
	require.Len(t, got.Display, 1)
	require.Equal(t, "Test Credential (from VCT)", got.Display[0].Name,
		"VCT credential-display name must win over credential_metadata's name")
	require.NotNil(t, got.Display[0].Display.Locale)
	require.Equal(t, "en-US", *got.Display[0].Display.Locale)
	require.Equal(t, "#1a56db", got.Display[0].BackgroundColor)
	require.Equal(t, "#ffffff", got.Display[0].TextColor)
	require.NotNil(t, got.Display[0].Logo, "rendering.simple.logo must surface as CredentialDisplay.Logo")
	require.Equal(t, "https://example.com/vct-logo.png", got.Display[0].Logo.Uri)
	require.Equal(t, "VCT Logo", got.Display[0].Logo.AltText)

	// Claim displays: VCT labels (current-spec field) win over credential_metadata's names.
	require.Len(t, got.Claims, 2)

	require.Equal(t, metadata.ClaimsPathPointer{"given_name"}, got.Claims[0].Path)
	require.Len(t, got.Claims[0].Display, 2, "both VCT locales must come through")
	require.Equal(t, "Given Name (from VCT)", got.Claims[0].Display[0].Name)
	require.NotNil(t, got.Claims[0].Display[0].Locale)
	require.Equal(t, "en-US", *got.Claims[0].Display[0].Locale)
	require.Equal(t, "Voornaam (from VCT)", got.Claims[0].Display[1].Name)
	require.NotNil(t, got.Claims[0].Display[1].Locale)
	require.Equal(t, "nl-NL", *got.Claims[0].Display[1].Locale)

	require.Equal(t, metadata.ClaimsPathPointer{"email"}, got.Claims[1].Path)
	require.Len(t, got.Claims[1].Display, 1)
	require.Equal(t, "Email (from VCT)", got.Claims[1].Display[0].Name)
}

func TestResolveCredentialMetadataFromVct_FetchFailureLeavesCredentialMetadata(t *testing.T) {
	srv := newVctTestServer(t, map[string]string{}) // empty: every URL 404s
	defer srv.Close()

	client := &Client{httpClient: srv.Client(), allowInsecureHttp: true}
	resolver := typemetadata.NewResolver(srv.Client())
	original := &metadata.CredentialMetadata{
		Display: metadata.CredentialDisplays{
			{Display: metadata.Display{Name: "FROM_CREDMETA"}},
		},
	}
	issuerMeta := singleConfigMetadata("Email", metadata.CredentialConfiguration{
		Format:                   metadata.CredentialFormatIdentifier_SdJwtVc,
		VerifiableCredentialType: srv.URL + "/vct/missing",
		CredentialMetadata:       original,
	})
	offer := &CredentialOffer{CredentialConfigurationIds: []string{"Email"}}

	client.resolveCredentialMetadataFromVct(context.Background(), offer, issuerMeta, resolver)

	got := issuerMeta.CredentialConfigurationsSupported["Email"].CredentialMetadata
	require.Same(t, original, got, "fetch failure must leave the original credential_metadata pointer untouched")
}

func TestResolveCredentialMetadataFromVct_NonURLVctSkipsResolution(t *testing.T) {
	client := &Client{httpClient: &http.Client{}, allowInsecureHttp: false}
	resolver := typemetadata.NewResolver(nil)
	original := &metadata.CredentialMetadata{}
	issuerMeta := singleConfigMetadata("Foo", metadata.CredentialConfiguration{
		Format:                   metadata.CredentialFormatIdentifier_SdJwtVc,
		VerifiableCredentialType: "urn:eu:eudi:pid", // not a URL
		CredentialMetadata:       original,
	})
	offer := &CredentialOffer{CredentialConfigurationIds: []string{"Foo"}}

	client.resolveCredentialMetadataFromVct(context.Background(), offer, issuerMeta, resolver)

	require.Same(t, original, issuerMeta.CredentialConfigurationsSupported["Foo"].CredentialMetadata)
}

func TestResolveCredentialMetadataFromVct_NonSdJwtFormatSkipsResolution(t *testing.T) {
	srv := newVctTestServer(t, map[string]string{
		"/vct/X": `{"name":"X"}`,
	})
	defer srv.Close()

	client := &Client{httpClient: srv.Client(), allowInsecureHttp: true}
	resolver := typemetadata.NewResolver(srv.Client())
	original := &metadata.CredentialMetadata{}
	issuerMeta := singleConfigMetadata("X", metadata.CredentialConfiguration{
		Format:                   metadata.CredentialFormatIdentifier_W3CVC, // not SD-JWT VC
		VerifiableCredentialType: srv.URL + "/vct/X",
		CredentialMetadata:       original,
	})
	offer := &CredentialOffer{CredentialConfigurationIds: []string{"X"}}

	client.resolveCredentialMetadataFromVct(context.Background(), offer, issuerMeta, resolver)

	require.Same(t, original, issuerMeta.CredentialConfigurationsSupported["X"].CredentialMetadata)
}

// --- mapVctToCredentialMetadata ---

func TestMapVctToCredentialMetadata_ProjectsAllSupportedFields(t *testing.T) {
	vct := &typemetadata.VctTypeMetadata{
		Display: []typemetadata.DisplayEntry{
			{
				Locale:          "en-US",
				Name:            "Email",
				Description:     "An email credential",
				Logo:            &typemetadata.RemoteImage{URI: "https://x/logo.png", AltText: "logo"},
				BackgroundColor: "#FF0000",
				TextColor:       "#FFFFFF",
			},
		},
		Claims: []typemetadata.ClaimMetadata{
			{
				Path: []any{"email"},
				Display: []typemetadata.ClaimDisplayEntry{
					{Locale: "en", Name: "Email"},
				},
			},
		},
	}
	out := mapVctToCredentialMetadata(vct)
	require.Len(t, out.Display, 1)
	require.Equal(t, "Email", out.Display[0].Name)
	require.NotNil(t, out.Display[0].Display.Locale)
	require.Equal(t, "en-US", *out.Display[0].Display.Locale)
	require.Equal(t, "An email credential", out.Display[0].Description)
	require.Equal(t, "#FF0000", out.Display[0].BackgroundColor)
	require.Equal(t, "#FFFFFF", out.Display[0].TextColor)
	require.NotNil(t, out.Display[0].Logo)
	require.Equal(t, "https://x/logo.png", out.Display[0].Logo.Uri)
	require.Len(t, out.Claims, 1)
	require.Len(t, out.Claims[0].Display, 1)
	require.Equal(t, "Email", out.Claims[0].Display[0].Name)
}

// --- verifyVctIntegrity ---

func TestVerifyVctIntegrity_AbsentClaimSkips(t *testing.T) {
	s := &session{vctResolver: typemetadata.NewResolver(nil)}
	fc := makeFetchedCredential("Email", "https://issuer/vct/Email", map[string]any{
		"vct": "https://issuer/vct/Email",
		// vct#integrity intentionally absent
	})
	require.NoError(t, s.verifyVctIntegrity([]*fetchedCredential{fc}))
}

func TestVerifyVctIntegrity_AcceptsOnMatch(t *testing.T) {
	body := `{"name":"Email"}`
	hash := sha256.Sum256([]byte(body))
	intg := "sha256-" + base64.StdEncoding.EncodeToString(hash[:])

	resolver := newResolverPrimedWith(t, "https://issuer/vct/Email", body)
	s := &session{vctResolver: resolver}

	fc := makeFetchedCredential("Email", "https://issuer/vct/Email", map[string]any{
		"vct":           "https://issuer/vct/Email",
		"vct#integrity": intg,
	})
	require.NoError(t, s.verifyVctIntegrity([]*fetchedCredential{fc}))
}

func TestVerifyVctIntegrity_RejectsOnMismatch(t *testing.T) {
	resolver := newResolverPrimedWith(t, "https://issuer/vct/Email", `{"name":"Different"}`)
	s := &session{vctResolver: resolver}

	hash := sha256.Sum256([]byte(`{"name":"Email"}`))
	intg := "sha256-" + base64.StdEncoding.EncodeToString(hash[:])

	fc := makeFetchedCredential("Email", "https://issuer/vct/Email", map[string]any{
		"vct":           "https://issuer/vct/Email",
		"vct#integrity": intg,
	})
	err := s.verifyVctIntegrity([]*fetchedCredential{fc})
	require.Error(t, err)
	require.Contains(t, err.Error(), "integrity")
}

func TestVerifyVctIntegrity_RejectsOnUnsupportedAlgorithm(t *testing.T) {
	resolver := newResolverPrimedWith(t, "https://issuer/vct/Email", `{}`)
	s := &session{vctResolver: resolver}

	fc := makeFetchedCredential("Email", "https://issuer/vct/Email", map[string]any{
		"vct":           "https://issuer/vct/Email",
		"vct#integrity": "sha512-aGVsbG8=",
	})
	err := s.verifyVctIntegrity([]*fetchedCredential{fc})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported")
}

func TestVerifyVctIntegrity_RejectsWhenClaimPresentButNoCachedDoc(t *testing.T) {
	s := &session{vctResolver: typemetadata.NewResolver(nil)} // empty cache

	fc := makeFetchedCredential("Email", "https://issuer/vct/Email", map[string]any{
		"vct":           "https://issuer/vct/Email",
		"vct#integrity": "sha256-aGVsbG8=",
	})
	err := s.verifyVctIntegrity([]*fetchedCredential{fc})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no type metadata was fetched")
}

func TestVerifyVctIntegrity_NilResolverNoOp(t *testing.T) {
	s := &session{vctResolver: nil}
	fc := makeFetchedCredential("Email", "https://issuer/vct/Email", map[string]any{
		"vct#integrity": "sha256-anything",
	})
	require.NoError(t, s.verifyVctIntegrity([]*fetchedCredential{fc}))
}

// --- helpers ---

func newVctTestServer(t *testing.T, docs map[string]string) *vctTestServer {
	t.Helper()
	ts := &vctTestServer{docs: docs}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, ok := ts.docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	ts.Server = httptest.NewServer(mux)
	return ts
}

type vctTestServer struct {
	*httptest.Server
	docs map[string]string
}

func singleConfigMetadata(id string, config metadata.CredentialConfiguration) *metadata.CredentialIssuerMetadata {
	return &metadata.CredentialIssuerMetadata{
		CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{id: config},
	}
}

// newResolverPrimedWith returns a Resolver whose cache contains a single
// entry at the given URL with the given body. Used to unit-test
// verifyVctIntegrity without standing up an HTTP server for each test.
func newResolverPrimedWith(t *testing.T, url, body string) *typemetadata.Resolver {
	t.Helper()
	r := typemetadata.NewResolver(nil)
	typemetadata.PrimeCacheForTesting(r, url, []byte(body))
	return r
}

func makeFetchedCredential(configID, vct string, payload map[string]any) *fetchedCredential {
	return &fetchedCredential{
		credentialConfigurationId: configID,
		verifiedSdJwtVcs: []*sdjwtvc.VerifiedSdJwtVc{
			{
				IssuerSignedJwtPayload: sdjwtvc.IssuerSignedJwtPayload{
					VerifiableCredentialType: vct,
				},
				ProcessedSdJwtPayload: sdjwtvc.ProcessedSdJwtPayload(payload),
			},
		},
	}
}
