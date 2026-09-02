package walletconfig

import (
	"context"
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// Why a config's signature is checked against a root of its own rather than
// against the issuer or verifier anchors.
//
// Verify's contract is narrow: chain to the root, digitalSignature key usage,
// `typ`, and an `environment` field — a public value. So anyone who can obtain a
// certificate under the anchor set would be able to produce a config the wallet
// accepts, and a config can grant any party the top rung. Pointing the check at
// the issuer pool would make "may issue credentials" silently also mean "may
// decide who is trusted".
//
// Verify takes exactly one root and no pool, so the shared-pool arrangement is
// not expressible here at all; this test pins the direction of vouching: the
// config root vouches for issuer CAs, never the reverse.
func TestAnchorIsolation_AConfigSignedByACredentialIssuerIsRefused(t *testing.T) {
	configSigner := NewTestSigner(t)
	env := configSigner.Environment("test", testConfigURL)

	// An issuer CA the config vouches for, and an end-entity certificate under it:
	// what any onboarded credential issuer holds.
	issuerRootKey, issuerRoot := NewTestCA(t, "Onboarded Issuer Root CA", nil, nil)
	issuerKey, issuerCert := NewTestEndEntity(t, "issuer.example", issuerRoot, issuerRootKey, func(template *x509.Certificate) {
		template.URIs = []*url.URL{{Scheme: "https", Host: "issuer.example"}}
	})

	// The config that onboards it verifies: the config root vouches for the
	// issuer root.
	onboarding := NewTestConfig("test", 1, time.Now())
	onboarding.TrustedEntities = []TrustedEntity{{
		ID:         "onboarded-issuer",
		Name:       clientmodels.TranslatedString{"en": "Onboarded Issuer"},
		Roles:      []Role{RoleIssuer},
		TrustLevel: clientmodels.TrustLevel_High,
		Handles:    []Handle{{Type: HandleTypeX509CA, RootCertificate: &Certificate{issuerRoot}}},
	}}
	_, err := Verify(configSigner.Sign(t, onboarding), env, time.Now())
	require.NoError(t, err)

	// The issuer, now onboarded, writes itself a config granting a forger the top
	// rung and signs it with its issuing certificate.
	forgery := NewTestConfig("test", 2, time.Now())
	forgery.TrustedEntities = []TrustedEntity{{
		ID:         "forger",
		Name:       clientmodels.TranslatedString{"en": "Someone Else BV"},
		Roles:      []Role{RoleIssuer, RoleVerifier},
		TrustLevel: clientmodels.TrustLevel_High,
		Handles:    []Handle{{Type: HandleTypeDID, DID: "did:web:forger.example"}},
	}}
	forged := configSigner.SignWith(t, mustJSON(t, forgery), SignOverrides{
		Key: issuerKey, Chain: []*x509.Certificate{issuerCert},
	})

	_, err = Verify(forged, env, time.Now())
	require.ErrorContains(t, err, "unknown authority",
		"a certificate under an issuer root must not chain to the config root")

	// And through the manager: the forgery is refused and the wallet keeps what
	// it held.
	server := NewTestServer(t)
	server.SetBody(forged)
	env.ConfigURL = server.URL
	store := NewMemoryStore()
	require.NoError(t, store.Put("test", configSigner.Sign(t, onboarding)))
	m, err := NewManager(Options{Environments: []Environment{env}, Active: "test", Store: store, HTTPClient: server.Client()})
	require.NoError(t, err)

	_, err = m.Refresh(context.Background())
	require.ErrorContains(t, err, "unknown authority")
	require.Equal(t, uint64(1), m.Snapshot().Config.Version)
	require.Equal(t, "onboarded-issuer", m.Snapshot().Config.TrustedEntities[0].ID)
}
