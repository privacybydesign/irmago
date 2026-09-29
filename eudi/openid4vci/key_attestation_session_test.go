package openid4vci

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/walletunit"
	"github.com/privacybydesign/irmago/walletprovider"
	"github.com/privacybydesign/irmago/walletprovider/fake"
	"github.com/privacybydesign/irmago/walletprovider/providertest"
)

type fixedPin string

func (p fixedPin) RequestPin(*int) (string, bool) { return string(p), true }
func (fixedPin) PinBlocked(time.Duration)         {}

// keyAttestationSession is a session whose SD-JWT VC keys are minted by an
// activated fake wallet provider, for one credential configuration with the
// given proof types. The fake's KAs chain to ca.
func keyAttestationSession(t *testing.T, types map[metadata.ProofTypeIdentifier]metadata.ProofType, protection *walletprovider.KeyProtection, credentialEndpoint http.HandlerFunc) (*session, *fake.Provider, *fake.AttestationCA) {
	t.Helper()
	ca, err := fake.NewAttestationCA()
	require.NoError(t, err)
	wp, err := fake.New(fake.Options{AttestationCA: ca, KeyProtection: protection})(providertest.NewHost())
	require.NoError(t, err)
	require.NoError(t, wp.Activate(context.Background(), "12345"))

	s, ts := setupTestEnvironment(t, 0, credentialEndpoint)
	t.Cleanup(ts.Close)
	support := s.formats[models.CredentialFormatSdJwtVc]
	support.Keys = services.NewHolderBindingKeyService(s.storage.Db(), wp)
	s.formats[models.CredentialFormatSdJwtVc] = support
	s.ctx = walletunit.WithSession(context.Background(), walletunit.NewSession(wp, fixedPin("12345")))
	s.credentialIssuerMetadata.CredentialIssuer = ts.URL

	config := s.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"]
	config.CryptographicBindingMethodsSupported = []proofs.CryptographicBindingMethod{proofs.CryptographicBindingMethod_JWK}
	config.ProofTypesSupported = types
	config.CredentialSigningAlgValuesSupported = []any{"ES256"}
	s.credentialIssuerMetadata.CredentialConfigurationsSupported["credential-config-1"] = config
	s.credentialIssuerMetadata.BatchCredentialIssuance = &metadata.BatchCredentialIssuance{BatchSize: 3}
	return s, wp.(*fake.Provider), ca
}

// strictKeyAttestationEndpoint is a credential endpoint that checks the key
// attestation of the request the way an issuer requiring one would, reports
// what it found on found, and ends the request there.
func strictKeyAttestationEndpoint(t *testing.T, ca **fake.AttestationCA, found chan<- *providertest.KeyAttestation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req CredentialRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.NotNil(t, req.Proofs)

		var ka *providertest.KeyAttestation
		var kaRaw string
		if list, ok := (*req.Proofs)[metadata.ProofTypeIdentifier_Attestation]; ok {
			require.Len(t, list, 1, "one key attestation as the proof")
			require.NotContains(t, *req.Proofs, metadata.ProofTypeIdentifier_JWT)
			kaRaw = list[0].(string)
		} else {
			jwtProofs := (*req.Proofs)[metadata.ProofTypeIdentifier_JWT]
			require.NotEmpty(t, jwtProofs)
			for _, p := range jwtProofs {
				raw := []byte(p.(string))
				header := proofHeader(t, p.(string))
				ka, _ := header["key_attestation"].(string)
				require.NotEmpty(t, ka, "every jwt proof carries the key attestation")
				if kaRaw == "" {
					kaRaw = ka
				}
				require.Equal(t, kaRaw, ka, "the same key attestation in every proof")
				msg, err := jws.Parse(raw)
				require.NoError(t, err)
				key, ok := msg.Signatures()[0].ProtectedHeaders().JWK()
				require.True(t, ok)
				_, err = jws.Verify(raw, jws.WithKey(jwa.ES256(), key))
				require.NoError(t, err, "the proof is signed by its jwk")
			}
		}

		var err error
		ka, err = providertest.ParseKeyAttestation([]byte(kaRaw))
		require.NoError(t, err)
		pool := x509.NewCertPool()
		pool.AddCert((*ca).Root)
		_, err = ka.Chain[0].Verify(x509.VerifyOptions{Roots: pool})
		require.NoError(t, err, "the key attestation chains to the provider's CA")
		found <- ka

		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"key attestation checked"}`))
	}
}

// proofHeader decodes the protected header of a compact JWS.
func proofHeader(t *testing.T, compact string) map[string]any {
	t.Helper()
	encoded, _, ok := strings.Cut(compact, ".")
	require.True(t, ok)
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(data, &header))
	return header
}

func requiredHigh() *metadata.KeyAttestationRequirement {
	return &metadata.KeyAttestationRequirement{KeyStorage: []metadata.AttestationAttackResistance{metadata.Iso18045_High}}
}

func TestKeyAttestationProofTypes(t *testing.T) {
	es256 := []string{"ES256"}
	for name, types := range map[string]map[metadata.ProofTypeIdentifier]metadata.ProofType{
		"attestation proof type": {
			metadata.ProofTypeIdentifier_Attestation: {ProofSigningAlgValuesSupported: es256, KeyAttestationsRequired: requiredHigh()},
		},
		"jwt proof type with key_attestation": {
			metadata.ProofTypeIdentifier_JWT: {ProofSigningAlgValuesSupported: es256, KeyAttestationsRequired: requiredHigh()},
		},
	} {
		t.Run(name, func(t *testing.T) {
			found := make(chan *providertest.KeyAttestation, 1)
			var ca *fake.AttestationCA
			s, provider, providerCA := keyAttestationSession(t, types, nil, strictKeyAttestationEndpoint(t, &ca, found))
			ca = providerCA
			require.NoError(t, s.checkKeyAttestations(), "a provider claiming high meets the requirement")

			nonce := "c-nonce-1"
			_, err := s.obtainCredential("credential-config-1", &nonce, "token")
			require.ErrorContains(t, err, "key attestation checked")

			ka := <-found
			require.Equal(t, nonce, ka.Nonce, "the key attestation carries the c_nonce")
			require.Len(t, ka.AttestedKeys, 3, "one key attestation over the whole batch")
			require.Equal(t, []string{"iso_18045_high"}, ka.KeyStorage)
			require.Equal(t, 1, provider.KeyAttestations())
		})
	}
}

func TestNoKeyAttestationUnlessRequired(t *testing.T) {
	var sawHeader bool
	endpoint := func(w http.ResponseWriter, r *http.Request) {
		var req CredentialRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		for _, p := range (*req.Proofs)[metadata.ProofTypeIdentifier_JWT] {
			_, has := proofHeader(t, p.(string))["key_attestation"]
			sawHeader = sawHeader || has
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"checked"}`))
	}
	s, provider, _ := keyAttestationSession(t, map[metadata.ProofTypeIdentifier]metadata.ProofType{
		metadata.ProofTypeIdentifier_JWT:         {ProofSigningAlgValuesSupported: []string{"ES256"}},
		metadata.ProofTypeIdentifier_Attestation: {ProofSigningAlgValuesSupported: []string{"ES256"}},
	}, nil, endpoint)

	nonce := "n"
	_, err := s.obtainCredential("credential-config-1", &nonce, "token")
	require.ErrorContains(t, err, "checked")
	require.False(t, sawHeader, "no key attestation for an issuer that accepts jwt proofs without one")
	require.Zero(t, provider.KeyAttestations())
}

func TestUnmetKeyAttestationRequirementsAreRefusedBeforeConsent(t *testing.T) {
	types := map[metadata.ProofTypeIdentifier]metadata.ProofType{
		metadata.ProofTypeIdentifier_JWT: {ProofSigningAlgValuesSupported: []string{"ES256"}, KeyAttestationsRequired: requiredHigh()},
	}
	unused := func(w http.ResponseWriter, r *http.Request) { t.Error("no credential request expected") }

	t.Run("a provider claiming less than required", func(t *testing.T) {
		s, _, _ := keyAttestationSession(t, types, &walletprovider.KeyProtection{KeyStorage: []string{"iso_18045_moderate"}}, unused)
		require.ErrorContains(t, s.checkKeyAttestations(), "requires key storage")
	})
	t.Run("a provider claiming nothing", func(t *testing.T) {
		s, _, _ := keyAttestationSession(t, types, &walletprovider.KeyProtection{}, unused)
		require.ErrorContains(t, s.checkKeyAttestations(), "requires key storage")
	})
	t.Run("software keys", func(t *testing.T) {
		s, _, _ := keyAttestationSession(t, types, nil, unused)
		support := s.formats[models.CredentialFormatSdJwtVc]
		support.Keys = services.NewHolderBindingKeyService(s.storage.Db(), nil)
		s.formats[models.CredentialFormatSdJwtVc] = support
		require.ErrorContains(t, s.checkKeyAttestations(), "only keys held by an active wallet unit")
	})
	t.Run("a wallet unit that is not active", func(t *testing.T) {
		s, provider, _ := keyAttestationSession(t, types, nil, unused)
		require.NoError(t, provider.Revoke(context.Background()))
		require.ErrorContains(t, s.checkKeyAttestations(), "only keys held by an active wallet unit")
	})
}

// A key attestation's keys are what the issuer binds the credentials to, so
// what the store keys the batch by must be those keys.
func TestAttestedKeysAreTheStoredKeys(t *testing.T) {
	found := make(chan *providertest.KeyAttestation, 1)
	var ca *fake.AttestationCA
	s, _, providerCA := keyAttestationSession(t, map[metadata.ProofTypeIdentifier]metadata.ProofType{
		metadata.ProofTypeIdentifier_Attestation: {ProofSigningAlgValuesSupported: []string{"ES256"}},
	}, nil, strictKeyAttestationEndpoint(t, &ca, found))
	ca = providerCA

	keys, proofStrings, err := s.formats[models.CredentialFormatSdJwtVc].Keys.CreateKeyPairsWithProofs(s.ctx, 2,
		proofs.NewJwtProofBuilder(YiviClientId, "https://issuer.example", jwa.ES256(), nil, nil, proofs.CryptographicBindingMethod_JWK),
		&services.KeyAttestationOptions{AsProof: true})
	require.NoError(t, err)
	require.Len(t, proofStrings, 1)
	ka, err := providertest.ParseKeyAttestation([]byte(proofStrings[0]))
	require.NoError(t, err)
	require.Len(t, keys, 2)
	for i, pub := range ka.AttestedKeys {
		key, err := jwk.Import[jwk.Key](pub)
		require.NoError(t, err)
		thumbprint, err := key.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		require.NotNil(t, keys[i].PublicKeyThumbprint)
		require.Equal(t, hex.EncodeToString(thumbprint), *keys[i].PublicKeyThumbprint, "stored key %d is attested key %d", i, i)
	}
}
