package eudi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// The certificate channel's classifier: which anchor a leaf's chain validates
// to decides the level it confers, chains to nowhere confer nothing, and only
// acts of distrust (revocation, a dropped anchor) demote — expiry does not.

func TestTrustModel_Classify(t *testing.T) {
	t.Run("a chain to an installed anchor confers high", testClassifyInstalledAnchorConfersHigh)
	t.Run("a pinned anchor confers the level it was pinned at", testClassifyPinnedAnchorConfersItsLevel)
	t.Run("a chain to an unknown root confers nothing", testClassifyUnknownRootConfersNothing)
	t.Run("an expired leaf still classifies", testClassifyToleratesAnExpiredLeaf)
	t.Run("a revoked leaf confers nothing", testClassifyRevokedLeafConfersNothing)
	t.Run("nil confers nothing", testClassifyNilConfersNothing)
}

// classifyFixture is a trust model with one CA chain anchored at the given
// level, plus that CA's certificate and key so tests can mint leaves under it.
func classifyFixture(t *testing.T, confers clientmodels.TrustLevel) (*TrustModel, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Classify Root"), testdata.PkiOption_None)
	caKey, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Classify CA"), rootCert, rootKey, testdata.PkiOption_None, nil)

	tm, _ := setupTrustModelWithStoragePath(t)
	chainPem := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})...)
	require.NoError(t, tm.addTrustAnchors(confers, chainPem))

	return tm, caCert, caKey
}

// mintLeaf issues an end-entity certificate under the given CA, with the
// validity window the test asks for.
func mintLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "party.example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"party.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, key.Public(), caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf
}

func testClassifyInstalledAnchorConfersHigh(t *testing.T) {
	// A chain installed through storage is the dev/test stand-in for the Yivi
	// CA, so it confers high — the level loadTrustChains states.
	rootKey, rootCert := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Installed Root"), testdata.PkiOption_None)
	caKey, caCert, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Installed CA"), rootCert, rootKey, testdata.PkiOption_None, nil)

	tm, _ := setupTrustModelWithStoragePath(t)
	installCertChain(t, tm, caCert, rootCert)
	require.NoError(t, tm.Reload())

	leaf := mintLeaf(t, caCert, caKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.Equal(t, clientmodels.TrustLevel_High, tm.Classify(leaf))
}

func testClassifyPinnedAnchorConfersItsLevel(t *testing.T) {
	// The same machinery, at the level the anchor was pinned at: this is the
	// anchored-third-party-CA case, and promotion under contract is this data
	// changing to high.
	tm, caCert, caKey := classifyFixture(t, clientmodels.TrustLevel_Medium)

	leaf := mintLeaf(t, caCert, caKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.Equal(t, clientmodels.TrustLevel_Medium, tm.Classify(leaf))
}

func testClassifyUnknownRootConfersNothing(t *testing.T) {
	// A chain the wallet cannot trace to any anchor proves nothing: the
	// certificate's contents count as self-asserted, and the ladder sees
	// absent evidence rather than a failure.
	tm, _, _ := classifyFixture(t, clientmodels.TrustLevel_High)

	strangerRootKey, strangerRoot := testdata.CreateRootCertificate(t, testdata.CreateDistinguishedName("Stranger Root"), testdata.PkiOption_None)
	strangerCaKey, strangerCa, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("Stranger CA"), strangerRoot, strangerRootKey, testdata.PkiOption_None, nil)
	leaf := mintLeaf(t, strangerCa, strangerCaKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	require.Equal(t, clientmodels.TrustLevel_Unevaluated, tm.Classify(leaf))
}

func testClassifyToleratesAnExpiredLeaf(t *testing.T) {
	// Classification serves stored evidence: the vouching question about a
	// stored credential concerns the signing act, which happened inside the
	// leaf's validity window, and issuer leaves routinely expire before the
	// credentials they signed. Expiry is routine hygiene, not distrust.
	tm, caCert, caKey := classifyFixture(t, clientmodels.TrustLevel_High)

	// Expired ten minutes ago, still inside the CA's own validity — the shape
	// a real expired issuer leaf has, since a CA cannot sign before it exists.
	leaf := mintLeaf(t, caCert, caKey, time.Now().Add(-50*time.Minute), time.Now().Add(-10*time.Minute))
	require.Equal(t, clientmodels.TrustLevel_High, tm.Classify(leaf))
}

func testClassifyRevokedLeafConfersNothing(t *testing.T) {
	// Revocation is an act of distrust, so it stops the anchor's word — unlike
	// expiry above.
	tm, caCert, caKey := classifyFixture(t, clientmodels.TrustLevel_High)
	leaf := mintLeaf(t, caCert, caKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	crlTemplate := testdata.GetDefaultCrlTemplate(caCert)
	crlTemplate.RevokedCertificateEntries = []x509.RevocationListEntry{{
		SerialNumber:   leaf.SerialNumber,
		RevocationTime: time.Now().Add(-time.Minute),
	}}
	crlDer, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(crlDer)
	require.NoError(t, err)
	tm.revocationLists = append(tm.revocationLists, crl)

	require.Equal(t, clientmodels.TrustLevel_Unevaluated, tm.Classify(leaf))
}

func testClassifyNilConfersNothing(t *testing.T) {
	tm, _, _ := classifyFixture(t, clientmodels.TrustLevel_High)
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, tm.Classify(nil))
}
