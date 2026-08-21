package lote

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/jades"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/stretchr/testify/require"
)

// Why a list's signature is checked against a trust-list anchor set of its own
// rather than against the issuer anchors.
//
// The checker's contract is narrow: chain to an anchor, digitalSignature key
// usage, CRL, then SchemeName and LoTEType — both public values. So anyone who can
// produce a certificate under the anchor set can produce a list the wallet
// accepts, and pointing it at the issuer pool confers that on every issuer.
//
// Clause 6.8.0 does not fix it: it binds the signing certificate's subject to the
// document's own SchemeTerritory and SchemeOperatorName, which a forger writes to
// match. These two tests are the same forgery against the two arrangements.

// forgedList grants the forger the top rung, naming the scheme it impersonates
// and claiming its own organization as the scheme operator, so even a clause
// 6.8.0 check would find the document internally consistent.
func forgedList(listId, did, organization string) List {
	list := NewTestList(listId, 999,
		NewTestEntity(organization, "", NewTestDidService(trust.RoleIssuer, did)))
	list.SchemeInformation.SchemeOperatorName = MultiLang{"en": organization}
	return list
}

// signAs signs a list with an arbitrary key and certificate, the way a foreign
// publisher would.
func signAs(t *testing.T, list List, key *ecdsa.PrivateKey, certificate *x509.Certificate) []byte {
	t.Helper()
	payload, err := json.Marshal(Document{LoTE: list})
	require.NoError(t, err)

	chain := &cert.Chain{}
	require.NoError(t, chain.Add([]byte(base64.StdEncoding.EncodeToString(certificate.Raw))))
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, LoteTyp))
	require.NoError(t, headers.Set(jws.X509CertChainKey, chain))
	require.NoError(t, headers.Set(jades.IatHeader, time.Now().Unix()))

	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return signed
}

// newEndEntityUnder issues a certificate under the given root with its own
// organization and digitalSignature key usage: what any party certificate looks
// like, a credential issuer's included.
func newEndEntityUnder(
	t *testing.T,
	rootCert *x509.Certificate,
	rootKey *ecdsa.PrivateKey,
	organization string,
) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject: pkix.Name{
			CommonName:   "party.example.com",
			Country:      []string{"NL"},
			Organization: []string{organization},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, rootCert, key.Public(), rootKey)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, parsed
}

// The failure this design avoids: when the checker's anchor set is the one that
// anchors party certificates, a party can sign the list. Asserted rather than
// described, so collapsing the two pools back into one does not look harmless.
func TestAnchorIsolation_ASharedAnchorSetLetsAPartySignTheList(t *testing.T) {
	signer := NewTestLoteSigner(t)
	forgerKey, forgerCert := newEndEntityUnder(t, signer.RootCert, signer.RootKey, "Someone Else BV")

	server := NewTestLoteServer(t)
	server.SetBody(signAs(t,
		forgedList(testListId, "did:web:forger.example.com", "Someone Else BV"),
		forgerKey, forgerCert))

	// The signer's root stands in for a pool anchoring both list signers and
	// parties: what passing &eudiConf.Issuers to the checker would give.
	checker := NewChecker(Config{
		Sources:     []Source{server.Source(testListId, clientmodels.TrustLevel_High)},
		X509Context: signer.X509VerificationContext(),
		Store:       memoryStore{},
	})
	_, err := checker.Refresh(context.Background())
	require.NoError(t, err, "a shared anchor set accepts the forgery")

	listing := checker.Snapshot().Lookup(trust.RoleIssuer,
		trust.Evidence{Identifiers: []string{"did:web:forger.example.com"}})
	require.NotNil(t, listing,
		"with a shared anchor set, any certificate under it can grant the top rung")
	require.Equal(t, clientmodels.TrustLevel_High, listing.Level)
}

// And the arrangement the wallet actually uses: the checker's anchor set contains
// only the trust-list root, so a certificate under the issuer root does not chain
// and the forgery is refused before anything else is looked at.
func TestAnchorIsolation_ASeparateAnchorSetRefusesAPartySignedList(t *testing.T) {
	issuerRootKey, issuerRoot := newSelfSignedRoot(t, "issuer root")
	trustListSigner := NewTestLoteSigner(t)

	forgerKey, forgerCert := newEndEntityUnder(t, issuerRoot, issuerRootKey, "Someone Else BV")

	server := NewTestLoteServer(t)
	server.SetBody(signAs(t,
		forgedList(testListId, "did:web:forger.example.com", "Someone Else BV"),
		forgerKey, forgerCert))

	// Only the trust-list root is anchored — what &eudiConf.TrustLists gives.
	checker := NewChecker(Config{
		Sources:     []Source{server.Source(testListId, clientmodels.TrustLevel_High)},
		X509Context: trustListSigner.X509VerificationContext(),
		Store:       memoryStore{},
	})
	_, err := checker.Refresh(context.Background())
	require.ErrorContains(t, err, "unknown authority",
		"a certificate under the issuer root must not chain to the trust-list anchor")

	require.Nil(t, checker.Snapshot().Lookup(trust.RoleIssuer,
		trust.Evidence{Identifiers: []string{"did:web:forger.example.com"}}),
		"and the forged list grants nothing")
}

// The genuine signer still works against the separate anchor set, so the test
// above is showing isolation rather than a pool that rejects everything.
func TestAnchorIsolation_TheGenuineSignerStillVerifies(t *testing.T) {
	signer := NewTestLoteSigner(t)
	server := NewTestLoteServer(t)
	server.Serve(t, signer, NewTestList(testListId, 1,
		NewTestEntity("Listed Ltd", "", NewTestDidService(trust.RoleIssuer, "did:web:listed.example.com"))))

	checker := NewChecker(Config{
		Sources:     []Source{server.Source(testListId, clientmodels.TrustLevel_High)},
		X509Context: signer.X509VerificationContext(),
		Store:       memoryStore{},
	})
	_, err := checker.Refresh(context.Background())
	require.NoError(t, err)
	require.NotNil(t, checker.Snapshot().Lookup(trust.RoleIssuer,
		trust.Evidence{Identifiers: []string{"did:web:listed.example.com"}}))
}

func newSelfSignedRoot(t *testing.T, commonName string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, parsed
}
