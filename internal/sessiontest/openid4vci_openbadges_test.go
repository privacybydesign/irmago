package sessiontest

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
)

// ============================================================================
// Open Badges claim images
//
// Veramo issues an Open Badges 3.0 credential as vc+sd-jwt from a preset
// credential in the offer, with this test's own JSON-LD context: one that gives
// OpenBadgeCredential the real Open Badges IRI, which is what the wallet tells
// an Open Badges credential by. The context and the images are served by this
// test on the host; the tls_proxy forwards https://localhost:8443/claim-images/
// to it, so the wallet fetches them over https as it would from an issuer. The
// real Open Badges context is not used: these tests do not reach the internet.
// ============================================================================

const (
	// claimImagesListenAddr must match the proxy_pass port of /claim-images/ in
	// testdata/configurations/certs/nginx-tls-proxy.conf. It sits in the
	// 48680-48699 range CI keeps out of the ephemeral port range, and listens on
	// every interface, because the proxy reaches it through the host gateway.
	claimImagesListenAddr = ":48689"

	claimImagesPublicURL = "https://localhost:8443/claim-images"

	openBadgeCredentialConfigId = "TestOpenBadgeCredential"
	openBadgeCredentialName     = "Test Badge"

	// A 1x1 PNG.
	claimImagePNGBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
	claimImageSVG       = `<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><rect width="8" height="8" fill="red"/></svg>`
)

var (
	openBadgeContextURL = claimImagesPublicURL + "/context.json"
	badgeImageURL       = claimImagesPublicURL + "/badge.png"
	logoImageURL        = claimImagesPublicURL + "/logo.svg"
	missingImageURL     = claimImagesPublicURL + "/missing.png"
	photoDataURI        = "data:image/png;base64," + claimImagePNGBase64
)

// startClaimImagesServer serves the test's Open Badges context, a PNG and an
// SVG, and a 404 for anything else, until the test ends.
func startClaimImagesServer(t *testing.T) {
	t.Helper()
	png, err := base64.StdEncoding.DecodeString(claimImagePNGBase64)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/context.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		_, _ = fmt.Fprintf(w, `{"@context": {"OpenBadgeCredential": {"@id": %q}}}`, vcdm.OpenBadgeCredentialType)
	})
	mux.HandleFunc("/badge.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	})
	mux.HandleFunc("/logo.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write([]byte(claimImageSVG))
	})

	listener, err := net.Listen("tcp", claimImagesListenAddr)
	require.NoError(t, err)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("claim images server: %v", err)
		}
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
}

func testSessionHandlerForOpenID4VCOpenBadges(t *testing.T) {
	t.Run("claim images show on every screen and stay in the log", testOpenBadgesClaimImages)
}

func testOpenBadgesClaimImages(t *testing.T) {
	startClaimImagesServer(t)
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := postOffer(t, preAuthIssuerURL, preAuthAdminToken, fmt.Sprintf(`{
		"credentials": [%q],
		"grants": {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "generate"
			}
		},
		"credentialDataSupplierInput": {},
		"credential": {
			"@context": [%q, %q],
			"credentialSubject": {
				"photo": %q,
				"achievement": {
					"name": "Schildertechnieken",
					"image": {"id": %q, "type": "Image"}
				},
				"logo": {"id": %q, "type": "Image"},
				"broken": {"id": %q, "type": "Image"}
			}
		}
	}`, openBadgeCredentialConfigId, vcdm.ContextV2, openBadgeContextURL,
		photoDataURI, badgeImageURL, logoImageURL, missingImageURL))
	startOpenID4VCISession(t, c, 1, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	// The permission screen: the data URI and the two Images that download are
	// pictures, the one that does not is its URL, each Image one attribute.
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)
	require.Equal(t, openBadgeCredentialName, session.OfferedCredentials[0].Name)
	requireOpenBadgeImages(t, session.OfferedCredentials[0].Attributes)

	grantPermission(t, c, session.Id)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// The credential list.
	cred := requireSingleVcdmCredential(t, c)
	require.Equal(t, openBadgeCredentialName, cred.Name)
	requireOpenBadgeImages(t, cred.Attributes)
	holderDid := vcdmHolderDid(t, cred.Attributes)

	// The disclosure screen, and what the verifier receives: the claims as
	// issued, the image URLs and the data URI, not the pictures.
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, vcdmDcqlQuery("",
		[]any{"credentialSubject", "photo"},
		[]any{"credentialSubject", "achievement"},
		[]any{"credentialSubject", "logo"},
		[]any{"credentialSubject", "broken"},
	))
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	option := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	requireOpenBadgeImages(t, option.Credentials[0].Attributes)

	grantPermission(t, c, session.Id, makeDisclosureChoice(option))
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Equal(t, "RESPONSE_RECEIVED", result.Status)
	requireNoVeramoVcdmErrors(t, result)
	requireVerifierReceivedClaims(t, result, vcdmQueryId,
		claim([]any{"photo"}, photoDataURI),
		claim([]any{"achievement", "name"}, "Schildertechnieken"),
		claim([]any{"achievement", "image", "id"}, badgeImageURL),
		claim([]any{"achievement", "image", "type"}, "Image"),
		claim([]any{"logo", "id"}, logoImageURL),
		claim([]any{"logo", "type"}, "Image"),
		claim([]any{"broken", "id"}, missingImageURL),
		claim([]any{"broken", "type"}, "Image"),
		claim([]any{"id"}, holderDid),
	)

	// The log shows the pictures, also once the credential is deleted.
	requireOpenBadgeImages(t, newestDisclosureLogAttrs(t, c, cred.CredentialId))
	require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))
	require.Empty(t, vcdmCredentials(t, c))
	requireOpenBadgeImages(t, newestDisclosureLogAttrs(t, c, cred.CredentialId))
}

// requireOpenBadgeImages checks the claim images of the test badge among
// attrs: the photo is a picture under its own path, each Image object is one
// attribute at its own path, its picture, and the Image whose URL does not
// resolve is its URL. No Image shows its id or type apart.
func requireOpenBadgeImages(t *testing.T, attrs []clientmodels.Attribute) {
	t.Helper()
	requireImageAttr(t, attrs, []any{"credentialSubject", "photo"}, clientmodels.MimeTypePNG)
	requireImageAttr(t, attrs, []any{"credentialSubject", "achievement", "image"}, clientmodels.MimeTypePNG)
	requireImageAttr(t, attrs, []any{"credentialSubject", "logo"}, clientmodels.MimeTypeSVG)

	broken := requireAttrAt(t, attrs, []any{"credentialSubject", "broken"})
	require.Equal(t, clientmodels.AttributeType_String, broken.Value.Type)
	require.Equal(t, missingImageURL, *broken.Value.String)

	for _, a := range attrs {
		if last, ok := a.ClaimPath[len(a.ClaimPath)-1].(string); ok && (last == "id" || last == "type") && len(a.ClaimPath) > 2 {
			t.Fatalf("an Image shows %v apart", a.ClaimPath)
		}
	}
}

func requireImageAttr(t *testing.T, attrs []clientmodels.Attribute, path []any, mimeType string) {
	t.Helper()
	attr := requireAttrAt(t, attrs, path)
	require.Equal(t, clientmodels.AttributeType_Base64Image, attr.Value.Type, "%v is a picture", path)
	require.NotNil(t, attr.Value.MimeType, "%v has a MIME type", path)
	require.Equal(t, mimeType, *attr.Value.MimeType, "%v MIME type", path)
}

func requireAttrAt(t *testing.T, attrs []clientmodels.Attribute, path []any) clientmodels.Attribute {
	t.Helper()
	for _, a := range attrs {
		if clientmodels.ClaimPathKey(a.ClaimPath) == clientmodels.ClaimPathKey(path) {
			require.NotNil(t, a.Value, "%v has a value", path)
			return a
		}
	}
	t.Fatalf("no attribute at %v", path)
	return clientmodels.Attribute{}
}

// newestDisclosureLogAttrs returns the attributes of credentialId in the newest
// disclosure log entry.
func newestDisclosureLogAttrs(t *testing.T, c *client.Client, credentialId string) []clientmodels.Attribute {
	t.Helper()
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	for _, entry := range logs {
		if entry.Type != clientmodels.LogType_Disclosure || entry.DisclosureLog == nil {
			continue
		}
		for _, cred := range entry.DisclosureLog.Credentials {
			if cred.CredentialId == credentialId {
				return cred.Attributes
			}
		}
	}
	t.Fatalf("no disclosure log entry for %q", credentialId)
	return nil
}
