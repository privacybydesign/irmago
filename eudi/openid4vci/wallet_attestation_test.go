package openid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/oauth2"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

const (
	testClientID = "https://provider.example/wallet-units/1"
	testASIssuer = "https://as.example"
	testWIA      = "header.wia.sig"
)

func es256Signer(key *ecdsa.PrivateKey) proofs.ES256SignFunc {
	return func(input []byte) ([]byte, error) {
		digest := sha256.Sum256(input)
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	}
}

type fakeAttester struct {
	key *ecdsa.PrivateKey

	mu          sync.Mutex
	issuers     []string
	attested    []*ecdsa.PublicKey
	kaNonces    []*string
	noKeyAttest bool
}

func newFakeAttester(t *testing.T) *fakeAttester {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &fakeAttester{key: key}
}

func (a *fakeAttester) ClientAttestation(credentialIssuer string) (*ClientAttestation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.issuers = append(a.issuers, credentialIssuer)
	return &ClientAttestation{JWT: testWIA, ClientID: testClientID, Key: &a.key.PublicKey, Sign: es256Signer(a.key)}, nil
}

func (a *fakeAttester) KeyAttestation(_ string, key *ecdsa.PublicKey, nonce *string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.noKeyAttest {
		return "", nil
	}
	a.attested = append(a.attested, key)
	a.kaNonces = append(a.kaNonces, nonce)
	return "ka.for.key", nil
}

// verifyES256 checks token's signature with key and returns its header and claims.
func verifyES256(t *testing.T, token string, key *ecdsa.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	payload, err := jws.Verify([]byte(token), jws.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	hdrPart, _, _ := strings.Cut(token, ".")
	hdrJSON, err := base64.RawURLEncoding.DecodeString(hdrPart)
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(hdrJSON, &header))
	return header, claims
}

func attestedSession(t *testing.T, attester *fakeAttester, tokenEndpoint string, httpClient *http.Client) *session {
	t.Helper()
	att, err := newSessionAttestation(attester, "https://issuer.example")
	require.NoError(t, err)
	return &session{
		attestation: att,
		httpClient:  httpClient,
		issuerSettings: openid4vciSessionIssuerSettings{
			authorizationServerMetadata: &oauth2.AuthorizationServerMetadata{Issuer: testASIssuer, TokenEndpoint: tokenEndpoint},
		},
	}
}

func TestTokenRequestCarriesClientAttestationAndDPoP(t *testing.T) {
	attester := newFakeAttester(t)
	var requests int
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		require.NoError(t, r.ParseForm())
		require.Equal(t, testClientID, r.PostForm.Get("client_id"))
		require.Equal(t, testWIA, r.Header.Get(clientAttestationHeader))

		popHeader, pop := verifyES256(t, r.Header.Get(clientAttestationPoPHeader), &attester.key.PublicKey)
		require.Equal(t, clientAttestationPoPTyp, popHeader["typ"])
		require.Equal(t, testClientID, pop["iss"])
		require.Equal(t, testASIssuer, pop["aud"])
		require.NotEmpty(t, pop["jti"])

		dpopHdr, dpop := verifyES256(t, r.Header.Get(dpopHeader), &attester.key.PublicKey)
		require.Equal(t, dpopTyp, dpopHdr["typ"])
		require.NotNil(t, dpopHdr["jwk"], "the DPoP key is the attestation key, carried as jwk")
		require.Equal(t, http.MethodPost, dpop["htm"])
		require.Equal(t, server.URL+"/token", dpop["htu"])
		require.NotContains(t, dpop, "ath")

		if dpop["nonce"] == nil {
			w.Header().Set(dpopNonceHeader, "n-1")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		require.Equal(t, "n-1", dpop["nonce"])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP"}`))
	}))
	defer server.Close()

	s := attestedSession(t, attester, server.URL+"/token", server.Client())
	resp, err := (&PreAuthorizedCodeFlowHandler{}).doTokenRequest(s, &PreAuthorizedCodeGrant{PreAuthorizedCode: "code"}, nil)
	require.NoError(t, err)
	require.Equal(t, "at", resp.GetAccessToken())
	require.Equal(t, 2, requests, "retried once with the DPoP nonce")
	require.True(t, s.attestation.dpopBoundToken)
	require.Equal(t, []string{"https://issuer.example"}, attester.issuers)
}

func TestTokenRequestWithoutAttestationIsUnchanged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		require.Empty(t, r.PostForm.Get("client_id"))
		require.Empty(t, r.Header.Get(clientAttestationHeader))
		require.Empty(t, r.Header.Get(clientAttestationPoPHeader))
		require.Empty(t, r.Header.Get(dpopHeader))
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP"}`))
	}))
	defer server.Close()

	s := &session{
		httpClient: server.Client(),
		issuerSettings: openid4vciSessionIssuerSettings{
			authorizationServerMetadata: &oauth2.AuthorizationServerMetadata{Issuer: testASIssuer, TokenEndpoint: server.URL},
		},
	}
	_, err := (&PreAuthorizedCodeFlowHandler{}).doTokenRequest(s, &PreAuthorizedCodeGrant{PreAuthorizedCode: "code"}, nil)
	require.ErrorContains(t, err, "valid token type", "a DPoP token is refused when no DPoP proof was sent")
}

func TestPARCarriesClientAttestation(t *testing.T) {
	attester := newFakeAttester(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, testWIA, r.Header.Get(clientAttestationHeader))
		_, pop := verifyES256(t, r.Header.Get(clientAttestationPoPHeader), &attester.key.PublicKey)
		require.Equal(t, testASIssuer, pop["aud"])
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"request_uri":"urn:x","expires_in":60}`))
	}))
	defer server.Close()

	s := attestedSession(t, attester, "", server.Client())
	h := &AuthorizationCodeFlowHandler{httpClient: server.Client(), attestation: s.attestation, asIssuer: testASIssuer}
	_, err := h.pushAuthorizationRequest(server.URL, url.Values{"client_id": {s.clientID()}})
	require.NoError(t, err)
}

func TestCredentialRequestWithDPoPBoundToken(t *testing.T) {
	attester := newFakeAttester(t)
	var requests int
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		require.Equal(t, "DPoP at", r.Header.Get("Authorization"))
		_, dpop := verifyES256(t, r.Header.Get(dpopHeader), &attester.key.PublicKey)
		sum := sha256.Sum256([]byte("at"))
		require.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), dpop["ath"])
		require.Equal(t, server.URL, dpop["htu"])
		body, _ := io.ReadAll(r.Body)
		require.Equal(t, "{}", string(body), "the retry resends the same body")
		if dpop["nonce"] == nil {
			w.Header().Set(dpopNonceHeader, "rs-1")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		require.Equal(t, "rs-1", dpop["nonce"])
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := attestedSession(t, attester, "", server.Client())
	s.attestation.dpopBoundToken = true
	s.credentialIssuerMetadata = &metadata.CredentialIssuerMetadata{CredentialEndpoint: server.URL}
	resp, err := s.sendCredentialRequest([]byte("{}"), "application/json", "at")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, 2, requests)
}

func keyAttestationConfig() metadata.CredentialConfiguration {
	return metadata.CredentialConfiguration{
		Format:                               metadata.CredentialFormatIdentifier_SdJwtVc,
		VerifiableCredentialType:             "vct",
		CredentialSigningAlgValuesSupported:  []any{"ES256"},
		CryptographicBindingMethodsSupported: []proofs.CryptographicBindingMethod{proofs.CryptographicBindingMethod_JWK},
		ProofTypesSupported: map[metadata.ProofTypeIdentifier]metadata.ProofType{
			metadata.ProofTypeIdentifier_JWT: {
				ProofSigningAlgValuesSupported: []string{"ES256"},
				KeyAttestationsRequired:        &metadata.KeyAttestationRequirement{KeyStorage: []metadata.AttestationAttackResistance{"iso_18045_high"}},
			},
		},
	}
}

func TestKeyAttestationsRequiredNeedsAnAttester(t *testing.T) {
	config := keyAttestationConfig()

	_, err := (&CredentialConfigurationValidator{}).ValidateAndGetSupportedFeatures(&config)
	require.ErrorContains(t, err, "key_attestations_required")

	_, err = (&CredentialConfigurationValidator{keyAttestations: true}).ValidateAndGetSupportedFeatures(&config)
	require.NoError(t, err)
}

// proofKeyBinder mints real keys and proofs, like the software binder.
type proofKeyBinder struct {
	keys []*ecdsa.PrivateKey
}

func (b *proofKeyBinder) CreateKeyPairsWithProofs(num uint, builder proofs.ProofBuilder) ([]models.PublicHolderBindingKey, []string, error) {
	ids := make([]models.PublicHolderBindingKey, num)
	out := make([]string, num)
	for i := range num {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		proof, err := builder.Build(key)
		if err != nil {
			return nil, nil, err
		}
		b.keys = append(b.keys, key)
		ids[i] = models.PublicHolderBindingKey{ID: datatypes.NewUUIDv4()}
		out[i] = proof.(string)
	}
	return ids, out, nil
}

func (b *proofKeyBinder) RemoveKeys([]datatypes.UUID) error { return nil }

func TestCredentialProofCarriesKeyAttestation(t *testing.T) {
	attester := newFakeAttester(t)
	var proofsSent []any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Proofs map[string][]any `json:"proofs"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		proofsSent = req.Proofs["jwt"]
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_proof"}`))
	}))
	defer server.Close()

	s := attestedSession(t, attester, "", server.Client())
	keys := &proofKeyBinder{}
	s.formats = services.CredentialFormats{models.CredentialFormatSdJwtVc: {Keys: keys}}
	s.credentialIssuerMetadata = &metadata.CredentialIssuerMetadata{
		CredentialIssuer:                  "https://issuer.example",
		CredentialEndpoint:                server.URL,
		NonceEndpoint:                     server.URL + "/nonce",
		BatchCredentialIssuance:           &metadata.BatchCredentialIssuance{BatchSize: 10},
		CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"c": keyAttestationConfig()},
	}

	nonce := "c-nonce"
	_, err := s.obtainCredential("c", &nonce, "at")
	require.ErrorContains(t, err, "invalid_proof")

	require.Len(t, proofsSent, 1, "one proof per request when attesting, despite the batch size")
	require.Len(t, keys.keys, 1)
	header, claims := verifyES256(t, proofsSent[0].(string), &keys.keys[0].PublicKey)
	require.Equal(t, "ka.for.key", header["key_attestation"])
	require.Equal(t, testClientID, claims["iss"])
	require.True(t, keys.keys[0].PublicKey.Equal(attester.attested[0]), "the key attestation covers the proof's key")
	require.Equal(t, &nonce, attester.kaNonces[0])
}

type noAttestation struct{ fakeAttester }

func (*noAttestation) ClientAttestation(string) (*ClientAttestation, error) { return nil, nil }

func TestNilClientAttestationRunsWithoutAttestation(t *testing.T) {
	att, err := newSessionAttestation(&noAttestation{}, "https://issuer.example")
	require.NoError(t, err)
	require.Nil(t, att)
}
