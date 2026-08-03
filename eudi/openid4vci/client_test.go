package openid4vci

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt/sdjwttest"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipherstorage"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/common"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func createOpenID4VCiClientForTesting(t *testing.T) (storage.Storage, *Client) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	keyBinder := sdjwt.NewDefaultKeyBinderWithInMemoryStorage()
	sdJwtStorage, err := irmaclient.NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

	addTestCredentialsToStorage(t, sdJwtStorage, keyBinder)

	storageFolder := test.CreateTestStorage(t)
	testStoragePath := test.FindTestdataFolder(t)
	eudiAppDataPath := filepath.Join(storageFolder, "eudi")
	err = common.CopyDirectory(filepath.Join(testStoragePath, "eudi"), eudiAppDataPath)
	require.NoError(t, err)

	s, err := sqlcipherstorage.New(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	conf, err := eudi.NewConfiguration(s)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	sdJwtVcVerificationContext := sdjwtvc.SdJwtVcVerificationContext{
		X509VerificationContext: &conf.Issuers,
		Clock:                   eudi_jwt.NewSystemClock(),
		JwtVerifier:             sdjwt.NewJwxJwtVerifier(),
	}

	holderVerifier := sdjwtvc.NewHolderVerificationProcessor(sdJwtVcVerificationContext)

	credStore := db.NewCredentialStore(s.Db())
	credentialService := services.NewCredentialService(
		credStore,
		db.NewHolderBindingKeyStore(s.Db()),
		s.FileSystem(),
		services.NewRevocationService(nil, credStore),
		nil,
	)
	client, err := NewClient(&http.Client{}, conf, holderVerifier, credentialService, services.NewHolderBindingKeyService(conf.Storage.Db()), nil, services.NewTrustService(nil))
	require.NoError(t, err)
	client.AllowInsecureHttpForTesting()

	return s, client
}

func TestOpenID4VciClient(t *testing.T) {
	// TODO: The test server mock needs to handle additional endpoints (OAuth authorization server
	// metadata, token exchange, credential request) before this test can work end-to-end.
	t.Skip("test server mock is incomplete: only handles well-known endpoint")

	var issuerBaseUrl string
	issuerTestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/openid-credential-issuer") {
			w.Header().Add("Content-Type", "application/json")
			_, _ = w.Write([]byte(testdata.GetWellKnownConfigurationUrl(issuerBaseUrl)))
			return
		}
	}))
	defer issuerTestServer.Close()

	issuerBaseUrl = issuerTestServer.URL

	t.Run("issuing a credential successfully", func(t *testing.T) {
		testIssuingCredential_Success(t, testdata.GetCredentialOfferEndpointUrl(issuerBaseUrl))
	})
}

func testIssuingCredential_Success(t *testing.T, credentialOfferEndpointUrl string) {
	storage, client := createOpenID4VCiClientForTesting(t)

	handler := newMockSessionHandler(t)
	client.NewSession(1, credentialOfferEndpointUrl, "https://open.yivi.app/-/auth-callback", handler)

	authCodeRequest := handler.AwaitAuthCodeRequest()

	permissionGranted := true
	// Build the callback URL a compliant authorization server would redirect to,
	// echoing back the state the grant handler generated.
	callbackURL := "https://open.yivi.app/-/auth-callback?code=test-code&state=" + authCodeRequest.state
	authCodeRequest.callback(permissionGranted, &callbackURL)
	success := handler.AwaitSessionEnd()

	require.True(t, success)

	storage.Close()
}

// failureRecordingHandler makes the SessionError itself available to the test,
// which MockSessionHandler.Failure does not do (it only signals "not successful").
// It overrides Failure, so a failing session does not reach AwaitSessionEnd:
// wait for the failure with awaitFailure instead.
type failureRecordingHandler struct {
	*MockSessionHandler
	failures chan *clientmodels.SessionError
}

func newFailureRecordingHandler(t *testing.T) *failureRecordingHandler {
	return &failureRecordingHandler{
		MockSessionHandler: newMockSessionHandler(t),
		failures:           make(chan *clientmodels.SessionError, 1),
	}
}

func (h *failureRecordingHandler) Failure(err *clientmodels.SessionError) {
	h.failures <- err
}

func (h *failureRecordingHandler) awaitFailure(t *testing.T) *clientmodels.SessionError {
	t.Helper()
	select {
	case err := <-h.failures:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("session did not report a failure")
		return nil
	}
}

// panickingRoundTripper panics instead of performing a request, to inject a
// panic into the goroutine the openid4vci client runs its session on.
type panickingRoundTripper struct {
	message string
}

func (rt *panickingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	panic(rt.message)
}

// countingRoundTripper fails every request and records how many were attempted,
// so a test can assert a session was aborted before it went to the network.
type countingRoundTripper struct {
	requests atomic.Int32
}

func (rt *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	rt.requests.Add(1)
	return nil, fmt.Errorf("no request expected in this test")
}

func TestParseAndValidateCredentialOfferGrants(t *testing.T) {
	const issuerAndConfigIds = `"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["ExampleCredentialSdJwt"]`

	tests := []struct {
		name      string
		offer     string
		expectErr string
		// check inspects the parsed grants member, which is nil when the offer
		// omits it.
		check func(t *testing.T, grants *Grants)
	}{
		{
			name:  "pre-authorized code grant is accepted",
			offer: `{` + issuerAndConfigIds + `,"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"code"}}}`,
			check: func(t *testing.T, grants *Grants) {
				require.NotNil(t, grants.PreAuthorizedCodeGrant)
				require.Equal(t, "code", grants.PreAuthorizedCodeGrant.PreAuthorizedCode)
				require.False(t, grants.IsEmpty())
			},
		},
		{
			name:  "authorization code grant is accepted",
			offer: `{` + issuerAndConfigIds + `,"grants":{"authorization_code":{"issuer_state":"state-1"}}}`,
			check: func(t *testing.T, grants *Grants) {
				require.NotNil(t, grants.AuthorizationCodeGrant)
				require.NotNil(t, grants.AuthorizationCodeGrant.IssuerState)
				require.Equal(t, "state-1", *grants.AuthorizationCodeGrant.IssuerState)
			},
		},
		{
			// grants is OPTIONAL per OID4VCI v1.0 § 4.1.1; the grant type is
			// derived from the authorization server metadata later on.
			name:  "absent grants member is accepted",
			offer: `{` + issuerAndConfigIds + `}`,
			check: func(t *testing.T, grants *Grants) {
				require.Nil(t, grants)
			},
		},
		{
			name:  "null grants member is accepted",
			offer: `{` + issuerAndConfigIds + `,"grants":null}`,
			check: func(t *testing.T, grants *Grants) {
				require.Nil(t, grants)
			},
		},
		{
			name:  "empty grants object is accepted and reported as empty",
			offer: `{` + issuerAndConfigIds + `,"grants":{}}`,
			check: func(t *testing.T, grants *Grants) {
				require.NotNil(t, grants)
				require.True(t, grants.IsEmpty())
			},
		},
		{
			// A grant whose value is null names no grant, so the offer is treated
			// like one with an empty grants object rather than yielding a grant
			// with every parameter empty (an empty pre-authorized_code, in
			// particular).
			name:  "null grant value names no grant",
			offer: `{` + issuerAndConfigIds + `,"grants":{"authorization_code":null,"urn:ietf:params:oauth:grant-type:pre-authorized_code":null}}`,
			check: func(t *testing.T, grants *Grants) {
				require.Nil(t, grants.AuthorizationCodeGrant)
				require.Nil(t, grants.PreAuthorizedCodeGrant)
				require.True(t, grants.IsEmpty())
			},
		},
		{
			// Grant types we do not implement are kept, so an offer that names
			// only those is not mistaken for an empty grants object.
			name:  "unsupported grant types are kept",
			offer: `{` + issuerAndConfigIds + `,"grants":{"urn:example:zz-future-grant":{},"urn:example:aa-future-grant":{}}}`,
			check: func(t *testing.T, grants *Grants) {
				require.Equal(t, []string{"urn:example:aa-future-grant", "urn:example:zz-future-grant"}, grants.UnsupportedGrantTypes)
				require.False(t, grants.IsEmpty())
			},
		},
		{
			// The null value is skipped for the grant types we implement, not for
			// the identifiers we do not: the issuer named one, so the offer is not
			// the empty one a grant type is derived for.
			name:  "unsupported grant type with a null value is kept",
			offer: `{` + issuerAndConfigIds + `,"grants":{"urn:example:future-grant":null}}`,
			check: func(t *testing.T, grants *Grants) {
				require.Equal(t, []string{"urn:example:future-grant"}, grants.UnsupportedGrantTypes)
				require.False(t, grants.IsEmpty())
			},
		},
		{
			// pre-authorized_code is REQUIRED per OID4VCI v1.0 § 4.1.1, and an
			// empty one is what the null grant value above would have produced.
			name:      "pre-authorized code grant without a code is rejected",
			offer:     `{` + issuerAndConfigIds + `,"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{}}}`,
			expectErr: "missing the required pre-authorized_code parameter",
		},
		{
			name:      "pre-authorized code grant with an empty code is rejected",
			offer:     `{` + issuerAndConfigIds + `,"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":""}}}`,
			expectErr: "missing the required pre-authorized_code parameter",
		},
		{
			name:      "grants member of the wrong type is rejected",
			offer:     `{` + issuerAndConfigIds + `,"grants":"authorization_code"}`,
			expectErr: "failed to unmarshal grants",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{}

			offer, err := client.ParseAndValidateCredentialOffer(tt.offer)

			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)
				require.Nil(t, offer)
				return
			}

			require.NoError(t, err)
			tt.check(t, offer.Grants)
		})
	}
}

// A credential offer without a grants member is valid (OID4VCI v1.0 § 4.1.1),
// so the session continues to the issuer metadata instead of being rejected
// during offer validation. It used to nil-dereference on the session goroutine,
// killing the whole host process instead of the session.
func TestNewSessionCredentialOfferWithoutGrantsContinuesSession(t *testing.T) {
	offers := map[string]string{
		"absent grants member": `{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["ExampleCredentialSdJwt"]}`,
		"null grants member":   `{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["ExampleCredentialSdJwt"],"grants":null}`,
		"empty grants member":  `{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["ExampleCredentialSdJwt"],"grants":{}}`,
	}

	for name, offer := range offers {
		t.Run(name, func(t *testing.T) {
			handler := newFailureRecordingHandler(t)
			// Every request fails, so the session ends at the issuer metadata
			// fetch: the point of this test is that it gets there at all.
			transport := &countingRoundTripper{}
			client := &Client{httpClient: &http.Client{Transport: transport}}

			client.NewSession(1, "openid-credential-offer://?credential_offer="+url.QueryEscape(offer), "https://open.yivi.app/-/auth-callback", handler)

			require.Contains(t, handler.awaitFailure(t).WrappedError, "failed to get and verify credential issuer metadata")
			require.NotZero(t, transport.requests.Load())
		})
	}
}

// End-to-end check that an offer without a grants member starts the
// authorization code flow with the grant type taken from the authorization
// server metadata.
func TestNewSessionWithoutGrantsDerivesAuthorizationCodeFlow(t *testing.T) {
	storage, client := createOpenID4VCiClientForTesting(t)
	defer storage.Close()

	var issuerBaseUrl string
	issuerTestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(testdata.GetWellKnownConfigurationUrl(issuerBaseUrl)))
		case r.URL.Path == "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fmt.Appendf(nil, `{
				"issuer": %q,
				"authorization_endpoint": "%s/authorize",
				"token_endpoint": "%s/token",
				"response_types_supported": ["code"],
				"grant_types_supported": ["authorization_code"],
				"code_challenge_methods_supported": ["S256"]
			}`, issuerBaseUrl, issuerBaseUrl, issuerBaseUrl))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuerTestServer.Close()
	issuerBaseUrl = issuerTestServer.URL

	offer := fmt.Sprintf(
		`{"credential_issuer":"%s/b0ce4f83-1946-4037-b13c-641191fd3214","credential_configuration_ids":["employee-badge"]}`,
		issuerBaseUrl,
	)

	handler := newFailureRecordingHandler(t)
	client.NewSession(1, "openid-credential-offer://?credential_offer="+url.QueryEscape(offer), "https://open.yivi.app/-/auth-callback", handler)

	select {
	case received := <-handler.authCodeRequestChannel:
		parameters := url.Values(received.request.AuthorizationParameters)
		require.Equal(t, issuerBaseUrl+"/authorize", received.request.AuthorizationEndpoint)
		require.Equal(t, "code", parameters.Get("response_type"))
		require.NotEmpty(t, parameters.Get("state"))
		// issuer_state is a member of the offered authorization code grant, so a
		// derived grant has none to send.
		require.Empty(t, parameters.Get("issuer_state"))

		// Let the user decline, so the session ends instead of going on to the
		// token endpoint this test does not serve.
		received.callback(false, nil)
		require.Contains(t, handler.awaitFailure(t).WrappedError, "cancelled or denied by user")
	case failure := <-handler.failures:
		t.Fatalf("session failed instead of starting the authorization code flow: %v", failure.WrappedError)
	case <-time.After(30 * time.Second):
		t.Fatal("session did not start the authorization code flow")
	}
}

func TestNewSessionReportsPanicAsSessionFailure(t *testing.T) {
	handler := newFailureRecordingHandler(t)
	client := &Client{
		httpClient: &http.Client{Transport: &panickingRoundTripper{message: "injected panic"}},
	}

	client.NewSession(1, "openid-credential-offer://?credential_offer_uri=http://issuer.example.com/offer", "https://open.yivi.app/-/auth-callback", handler)

	sessionError := handler.awaitFailure(t)
	require.Equal(t, "panic", sessionError.ErrorType)
	require.Contains(t, sessionError.WrappedError, "injected panic")
	require.NotEmpty(t, sessionError.Stack)
	// Info carries the message and the stack, the way the legacy irmaclient
	// session reports a recovered panic.
	require.Contains(t, sessionError.Info, "injected panic")
	require.Contains(t, sessionError.Info, sessionError.Stack)
}

func addTestCredentialsToStorage(t *testing.T, storage irmaclient.SdJwtVcStorage, keyBinder sdjwt.KeyBinder) {
	// ignoring all errors here, since it's not production code anyway
	mobilephoneInfo, mobilephoneEntry := createMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, "test.test.mobilephone", "https://openid4vc.staging.yivi.app",
		map[string]string{
			"mobilephone": "+31612345678",
		}, 1,
	)
	require.NoError(t, storage.StoreCredential(mobilephoneInfo, mobilephoneEntry))

	emailInfo, emailSdjwts := createMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]string{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	}, 1)
	require.NoError(t, storage.StoreCredential(emailInfo, emailSdjwts))

	emailInfo2, emailSdjwt2 := createMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]string{
		"email":  "yivi@gmail.com",
		"domain": "gmail.com",
	}, 2)
	require.NoError(t, storage.StoreCredential(emailInfo2, emailSdjwt2))
}

func createMultipleSdJwtVcsWithCustomKeyBinder[T sdjwt.LeafClaimDataType](
	t *testing.T, keyBinder sdjwt.KeyBinder, vct string, issuer string, claims map[string]T, num uint,
) (irmaclient.SdJwtVcBatchMetadata, []sdjwtvc.SdJwtVc) {
	result := make([]sdjwtvc.SdJwtVc, num)

	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	certChain, err := utils.ParsePemCertificateChainToX5cFormat(chain)
	if err != nil {
		panic(err)
	}

	for i := range num {
		vc, err := createTestSdJwtVc(keyBinder, vct, issuer, claims, certChain)
		require.NoError(t, err)
		result[i] = vc
	}

	// Convert to SdJwtVcKb since the holder doesn't know if a Key Binding JWT is present or not
	holderVerifier := sdjwtvc.NewHolderVerificationProcessor(sdjwtvc.CreateDefaultVerificationContext(chain))
	info, _, err := createCredentialInfoAndVerifiedSdJwtVc(sdjwtvc.SdJwtVcKb(result[0]), holderVerifier, eudi.StrictSdJwtVerificationMode)
	require.NoError(t, err)
	return irmaclient.SdJwtVcBatchMetadata{
		BatchSize:              num,
		RemainingInstanceCount: num,
		SignedOn:               info.SignedOn,
		Expires:                info.Expires,
		Attributes:             info.Attributes,
		Hash:                   info.Hash,
		CredentialType:         info.CredentialType,
	}, result
}

func createTestSdJwtVc[T sdjwt.LeafClaimDataType](keyBinder sdjwt.KeyBinder, vct, issuerUrl string, claims map[string]T, x5c []string) (sdjwtvc.SdJwtVc, error) {
	holderKey, err := keyBinder.CreateKeyPairs(1)
	if err != nil {
		return "", fmt.Errorf("failed to create holder keys: %v", err)
	}

	return createTestSdJwtVcWithHolderKey(vct, issuerUrl, claims, x5c, holderKey[0])
}

func createTestSdJwtVcWithHolderKey[T sdjwt.LeafClaimDataType](vct, issuerUrl string, claims map[string]T, x5c []string, cnfHolderHey jwk.Key) (sdjwtvc.SdJwtVc, error) {
	holderKeyClaim, err := sdjwt.HolderKeyClaim(cnfHolderHey)
	if err != nil {
		return "", err
	}

	sdjwtClaims := []*sdjwt.ClaimElement{
		holderKeyClaim,
		sdjwt.Claim(jwt.IssuerKey, issuerUrl),
		sdjwt.Claim(jwt.IssuedAtKey, eudi_jwt.NewSystemClock().Now().Unix()),
		sdjwt.Claim(jwt.ExpirationKey, eudi_jwt.NewSystemClock().Now().Unix()+10000),
		sdjwt.Claim(sdjwt.SdAlgKey, iana.SHA256),
		sdjwt.Claim(sdjwtvc.VerifiableCredentialTypeKey, vct),
	}

	for key, value := range claims {
		sdjwtClaims = append(sdjwtClaims, sdjwt.SdClaim(key, value))
	}

	return sdjwtvc.NewSdJwtVcBuilder().
		WithPayload(sdjwtClaims...).
		WithIssuerCertificateChain(x5c).
		Build(sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey())
}

// TODO: this func becomes irrelevant once we have our own metadata storage (and no longer depend on metadata in the IrmaClient)
func createCredentialInfoAndVerifiedSdJwtVc(
	sdJwt sdjwtvc.SdJwtVcKb,
	holderVerifier *sdjwtvc.HolderVerificationProcessor,
	mode eudi.SdJwtVerificationMode,
) (*irmaclient.SdJwtVcMetadata, *sdjwtvc.VerifiedSdJwtVc, error) {
	verifiedSdJwtVc, err := holderVerifier.ParseAndVerifySdJwtVc(sdJwt)

	if err != nil {
		return nil, nil, err
	}

	attributes := map[string]any{}
	for _, d := range verifiedSdJwtVc.Disclosures {
		attributes[d.Key] = d.Value
	}

	hash, err := irmaclient.CreateHashForSdJwtVc(verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType, attributes)
	if err != nil {
		return nil, nil, err
	}

	if mode == eudi.StrictSdJwtVerificationMode {
		idComponents := strings.Split(verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType, ".")
		if num := len(idComponents); num != 3 {
			return nil, nil, fmt.Errorf(
				"credential id expected to have exactly 3 components, separated by dots: %s",
				verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType,
			)
		}
	}

	info := irmaclient.SdJwtVcMetadata{
		Hash:           hash,
		CredentialType: verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType,
		Attributes:     attributes,
	}

	if verifiedSdJwtVc.IssuerSignedJwtPayload.IssuedAt != nil {
		signedOn := irma.Timestamp(
			time.Unix(*verifiedSdJwtVc.IssuerSignedJwtPayload.IssuedAt, 0),
		)
		info.SignedOn = &signedOn
	}

	if verifiedSdJwtVc.IssuerSignedJwtPayload.Expiry != nil {
		expires := irma.Timestamp(
			time.Unix(*verifiedSdJwtVc.IssuerSignedJwtPayload.Expiry, 0),
		)
		info.Expires = &expires
	}

	return &info, verifiedSdJwtVc, nil
}
