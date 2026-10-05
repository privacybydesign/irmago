package eudi_jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testChainHostname = "example.com"

type testCertAndKey struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

type testCertOptions struct {
	isCA     bool
	keyUsage x509.KeyUsage
	extUsage []x509.ExtKeyUsage
	dnsNames []string
}

// newTestChainCert creates a certificate signed by parent, or a self-signed one when parent is nil.
func newTestChainCert(t *testing.T, cn string, parent *testCertAndKey, opts testCertOptions) *testCertAndKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              opts.keyUsage,
		ExtKeyUsage:           opts.extUsage,
		DNSNames:              opts.dnsNames,
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
	}

	issuerCert, issuerKey := template, key
	if parent != nil {
		issuerCert, issuerKey = parent.cert, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &key.PublicKey, issuerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &testCertAndKey{cert: cert, key: key}
}

func newTestCaCert(t *testing.T, cn string, parent *testCertAndKey) *testCertAndKey {
	return newTestChainCert(t, cn, parent, testCertOptions{isCA: true, keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign})
}

func newTestLeafCert(t *testing.T, cn string, parent *testCertAndKey) *testCertAndKey {
	return newTestChainCert(t, cn, parent, testCertOptions{keyUsage: x509.KeyUsageDigitalSignature, dnsNames: []string{testChainHostname}})
}

// newTestChainVerificationContext trusts only the given root, with an empty intermediate pool.
func newTestChainVerificationContext(root *x509.Certificate) *StaticVerificationContext {
	roots := x509.NewCertPool()
	roots.AddCert(root)

	return &StaticVerificationContext{
		VerifyOpts: x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
	}
}

// ─── VerifyCertificateChain ──────────────────────────────────────────────────

func Test_VerifyCertificateChain_LeafAndIntermediateInChain_RootTrusted_Succeeds(t *testing.T) {
	root := newTestCaCert(t, "root", nil)
	sub := newTestCaCert(t, "sub", root)
	leaf := newTestLeafCert(t, "leaf", sub)

	err := VerifyCertificateChain(newTestChainVerificationContext(root.cert), []*x509.Certificate{leaf.cert, sub.cert}, nil)
	require.NoError(t, err)
}

func Test_VerifyCertificateChain_IntermediateWithoutKeyUsageExtension_Succeeds(t *testing.T) {
	// Real-world CA certificates often carry no digitalSignature key usage, or no key usage extension at all.
	// Only the leaf signs the JWT, so only the leaf needs digitalSignature.
	root := newTestCaCert(t, "root", nil)
	sub := newTestChainCert(t, "sub", root, testCertOptions{isCA: true})
	leaf := newTestLeafCert(t, "leaf", sub)

	err := VerifyCertificateChain(newTestChainVerificationContext(root.cert), []*x509.Certificate{leaf.cert, sub.cert}, nil)
	require.NoError(t, err)
}

func Test_VerifyCertificateChain_RootIncludedInChain_Succeeds(t *testing.T) {
	root := newTestCaCert(t, "root", nil)
	sub := newTestCaCert(t, "sub", root)
	leaf := newTestLeafCert(t, "leaf", sub)

	err := VerifyCertificateChain(newTestChainVerificationContext(root.cert), []*x509.Certificate{leaf.cert, sub.cert, root.cert}, nil)
	require.NoError(t, err)
}

func Test_VerifyCertificateChain_TemplateWithoutIntermediatePool_DoesNotPanic(t *testing.T) {
	root := newTestCaCert(t, "root", nil)
	sub := newTestCaCert(t, "sub", root)
	leaf := newTestLeafCert(t, "leaf", sub)

	context := newTestChainVerificationContext(root.cert)
	context.VerifyOpts.Intermediates = nil

	require.NotPanics(t, func() {
		err := VerifyCertificateChain(context, []*x509.Certificate{leaf.cert, sub.cert}, nil)
		require.NoError(t, err)
	})
}

func Test_VerifyCertificateChain_DoesNotAddChainCertsToTemplatePool(t *testing.T) {
	root := newTestCaCert(t, "root", nil)
	sub := newTestCaCert(t, "sub", root)
	leaf := newTestLeafCert(t, "leaf", sub)

	context := newTestChainVerificationContext(root.cert)
	require.NoError(t, VerifyCertificateChain(context, []*x509.Certificate{leaf.cert, sub.cert}, nil))

	// The sub-CA from the first chain must not have been added to the trusted intermediates
	err := VerifyCertificateChain(context, []*x509.Certificate{leaf.cert}, nil)
	require.ErrorContains(t, err, "certificate signed by unknown authority")
}

func Test_VerifyCertificateChain_LeafWithoutDigitalSignatureKeyUsage_ReturnsError(t *testing.T) {
	root := newTestCaCert(t, "root", nil)
	sub := newTestCaCert(t, "sub", root)
	leaf := newTestChainCert(t, "leaf", sub, testCertOptions{keyUsage: x509.KeyUsageKeyEncipherment, dnsNames: []string{testChainHostname}})

	err := VerifyCertificateChain(newTestChainVerificationContext(root.cert), []*x509.Certificate{leaf.cert, sub.cert}, nil)
	require.ErrorContains(t, err, "missing digitalSignature key usage")
}

func Test_VerifyCertificateChain_IntermediateFromUntrustedRoot_ReturnsError(t *testing.T) {
	root := newTestCaCert(t, "root", nil)
	otherRoot := newTestCaCert(t, "other root", nil)
	otherSub := newTestCaCert(t, "other sub", otherRoot)
	leaf := newTestLeafCert(t, "leaf", otherSub)

	err := VerifyCertificateChain(newTestChainVerificationContext(root.cert), []*x509.Certificate{leaf.cert, otherSub.cert}, nil)
	require.ErrorContains(t, err, "certificate signed by unknown authority")
}

func Test_VerifyCertificateChain_IntermediateMissing_ReturnsError(t *testing.T) {
	root := newTestCaCert(t, "root", nil)
	sub := newTestCaCert(t, "sub", root)
	leaf := newTestLeafCert(t, "leaf", sub)

	err := VerifyCertificateChain(newTestChainVerificationContext(root.cert), []*x509.Certificate{leaf.cert}, nil)
	require.ErrorContains(t, err, "certificate signed by unknown authority")
}

func Test_VerifyCertificateChain_HostnameMatchesLeaf_Succeeds(t *testing.T) {
	root := newTestCaCert(t, "root", nil)
	sub := newTestCaCert(t, "sub", root)
	leaf := newTestLeafCert(t, "leaf", sub)

	hostname := testChainHostname
	err := VerifyCertificateChain(newTestChainVerificationContext(root.cert), []*x509.Certificate{leaf.cert, sub.cert}, &hostname)
	require.NoError(t, err)
}

func Test_VerifyCertificateChain_HostnameMismatch_ReturnsError(t *testing.T) {
	root := newTestCaCert(t, "root", nil)
	sub := newTestCaCert(t, "sub", root)
	leaf := newTestLeafCert(t, "leaf", sub)

	hostname := "evil.com"
	err := VerifyCertificateChain(newTestChainVerificationContext(root.cert), []*x509.Certificate{leaf.cert, sub.cert}, &hostname)
	require.ErrorContains(t, err, "not evil.com")
}

func Test_VerifyCertificateChain_HostnameDoesNotRelaxExtKeyUsage(t *testing.T) {
	// The extended key usages required by the verification context must be enforced,
	// regardless of whether a hostname is checked.
	root := newTestCaCert(t, "root", nil)
	sub := newTestCaCert(t, "sub", root)
	leaf := newTestChainCert(t, "leaf", sub, testCertOptions{
		keyUsage: x509.KeyUsageDigitalSignature,
		extUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		dnsNames: []string{testChainHostname},
	})

	context := newTestChainVerificationContext(root.cert)
	context.VerifyOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	chain := []*x509.Certificate{leaf.cert, sub.cert}

	err := VerifyCertificateChain(context, chain, nil)
	require.ErrorContains(t, err, "incompatible key usage")

	hostname := testChainHostname
	err = VerifyCertificateChain(context, chain, &hostname)
	require.ErrorContains(t, err, "incompatible key usage")
}
