package walletconfig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/cert"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// Not a _test.go file: session tests in internal/sessiontest and the CLI's tests
// need configs they control, and Go does not export test-only code across
// packages. Same shape as the statuslist package's test utilities.

// TestSigner is a config CA for tests: a root, an intermediate and a signing
// leaf, so chain building through an intermediate is exercised the way the real
// signer's chain will be. Certificates are valid from an hour ago for two years,
// so a test can move its clock past a config's grace period and still have the
// chain verify; a test about an expired signer builds its own leaf.
type TestSigner struct {
	RootKey *ecdsa.PrivateKey
	Root    *x509.Certificate

	IntermediateKey *ecdsa.PrivateKey
	Intermediate    *x509.Certificate

	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
}

// testCertificateLifetime is how long the certificates NewTestCA and
// NewTestEndEntity issue stay valid.
const testCertificateLifetime = 2 * 365 * 24 * time.Hour

func NewTestSigner(t *testing.T) *TestSigner {
	t.Helper()
	rootKey, root := NewTestCA(t, "Test Wallet Config Root CA", nil, nil)
	intermediateKey, intermediate := NewTestCA(t, "Test Wallet Config CA", root, rootKey)
	key, leaf := NewTestEndEntity(t, "test-config-signer", intermediate, intermediateKey, nil)
	return &TestSigner{
		RootKey: rootKey, Root: root,
		IntermediateKey: intermediateKey, Intermediate: intermediate,
		Key: key, Cert: leaf,
	}
}

// Chain is the `x5c` this signer puts on a config: leaf, then intermediate.
func (s *TestSigner) Chain() []*x509.Certificate {
	return []*x509.Certificate{s.Cert, s.Intermediate}
}

// Environment describes a world anchored on this signer's root, expecting the
// config NewTestConfig builds for name.
func (s *TestSigner) Environment(name, configURL string) Environment {
	return Environment{Name: name, ConfigID: TestConfigID(name), ConfigURL: configURL, SigningRoot: s.Root}
}

// TestConfigID is the id NewTestConfig gives the config for an environment.
func TestConfigID(environment string) string {
	return "test-" + environment
}

// Sign signs through Sign, the path the publisher takes, so a positive fixture
// cannot pass while the real signer is broken.
func (s *TestSigner) Sign(t *testing.T, config *Config) []byte {
	t.Helper()
	signed, err := Sign(config, s.Key, s.Chain())
	require.NoError(t, err, "the test signer must be able to sign the way the publisher does")
	return signed
}

// SignRaw signs bytes Sign would refuse — an invalid config, or no config at
// all — with the headers Sign would have produced.
func (s *TestSigner) SignRaw(t *testing.T, payload []byte) []byte {
	t.Helper()
	signed, err := signPayload(payload, s.Key, s.Chain())
	require.NoError(t, err)
	return signed
}

// SignOverrides are the deviations SignWith applies to what Sign would produce.
type SignOverrides struct {
	// Typ replaces the `typ` header; "" leaves Typ in place. OmitTyp drops it.
	Typ     string
	OmitTyp bool

	// Alg and Key together replace the signing algorithm and key; both or neither.
	Alg *jwa.SignatureAlgorithm
	Key crypto.Signer

	// Chain replaces `x5c`; OmitChain drops the header altogether.
	Chain     []*x509.Certificate
	OmitChain bool

	// Extra adds protected header parameters verbatim.
	Extra map[string]any
}

// SignWith assembles a signature by hand, with deviations from what Sign
// produces. It deliberately bypasses Sign: producing what Verify refuses is how
// the refusals get tested.
func (s *TestSigner) SignWith(t *testing.T, payload []byte, overrides SignOverrides) []byte {
	t.Helper()

	headers := jws.NewHeaders()
	if !overrides.OmitTyp {
		typ := Typ
		if overrides.Typ != "" {
			typ = overrides.Typ
		}
		require.NoError(t, headers.Set(jws.TypeKey, typ))
	}
	if !overrides.OmitChain {
		chain := overrides.Chain
		if chain == nil {
			chain = s.Chain()
		}
		x5c := &cert.Chain{}
		for _, certificate := range chain {
			require.NoError(t, x5c.Add([]byte(base64.StdEncoding.EncodeToString(certificate.Raw))))
		}
		require.NoError(t, headers.Set(jws.X509CertChainKey, x5c))
	}
	for name, value := range overrides.Extra {
		require.NoError(t, headers.Set(name, value))
	}

	alg, key := jwa.ES256(), crypto.Signer(s.Key)
	if overrides.Alg != nil {
		alg = *overrides.Alg
	}
	if overrides.Key != nil {
		key = overrides.Key
	}
	signed, err := jws.Sign(payload, jws.WithKey(alg, key, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return signed
}

// TestChainHeader is an `x5c` header value carrying the certificates, for tests
// in other packages that sign JWTs by hand.
func TestChainHeader(t *testing.T, chain ...*x509.Certificate) *cert.Chain {
	t.Helper()
	x5c := &cert.Chain{}
	for _, certificate := range chain {
		require.NoError(t, x5c.Add([]byte(base64.StdEncoding.EncodeToString(certificate.Raw))))
	}
	return x5c
}

// NewTestCA issues a CA certificate under parent, or a self-signed root when
// parent is nil. Valid from an hour ago for two years.
func NewTestCA(t *testing.T, commonName string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Yivi Test"}, Country: []string{"NL"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(testCertificateLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          randomBytes(t, 20),
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	return key, issue(t, template, parent, key.Public(), parentKey)
}

// NewTestEndEntity issues a signing certificate under parent, with the
// digitalSignature key usage. mutate, when given, edits the template before it
// is signed: how a test gets an expired leaf or one without the key usage.
func NewTestEndEntity(t *testing.T, commonName string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, mutate func(*x509.Certificate)) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Yivi Test"}, Country: []string{"NL"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(testCertificateLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          randomBytes(t, 20),
	}
	if mutate != nil {
		mutate(template)
	}
	return key, issue(t, template, parent, key.Public(), parentKey)
}

func issue(t *testing.T, template, parent *x509.Certificate, publicKey any, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	require.NoError(t, err)
	return serial
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

// NewTestConfig is a minimal valid config for environment: version as given,
// issued at now, current for thirty days with a week of grace, low/low policy,
// and one DID-anchored issuer.
func NewTestConfig(environment string, version uint64, now time.Time) *Config {
	return &Config{
		SchemaVersion:   "1.0",
		ID:              TestConfigID(environment),
		Environment:     environment,
		Version:         version,
		IssuedAt:        NewUnixTime(now),
		NextUpdate:      NewUnixTime(now.Add(30 * 24 * time.Hour)),
		GracePeriodSecs: 7 * 24 * 60 * 60,
		Policy: Policy{MinimumTrustLevel: MinimumTrustLevel{
			Issuance:   clientmodels.TrustLevel_Low,
			Disclosure: clientmodels.TrustLevel_Low,
		}},
		TrustedEntities: []TrustedEntity{{
			ID:         "example",
			Name:       clientmodels.TranslatedString{"en": "Example", "nl": "Voorbeeld"},
			Roles:      []Role{RoleIssuer},
			TrustLevel: clientmodels.TrustLevel_High,
			Handles:    []Handle{{Type: HandleTypeDID, DID: "did:web:example.com"}},
		}},
	}
}

// TestServer publishes one config body for a test wallet to fetch.
type TestServer struct {
	*httptest.Server

	mu     sync.Mutex
	body   []byte
	status int
	hits   atomic.Int32
}

func NewTestServer(t *testing.T) *TestServer {
	t.Helper()
	server := &TestServer{status: http.StatusOK}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.hits.Add(1)
		server.mu.Lock()
		body, status := server.body, server.status
		server.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

// SetBody makes the server serve body with a 200.
func (s *TestServer) SetBody(body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.status = body, http.StatusOK
}

// SetStatus makes the server answer with status and an empty body.
func (s *TestServer) SetStatus(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.status = nil, status
}

// Hits is how many requests the server has answered.
func (s *TestServer) Hits() int {
	return int(s.hits.Load())
}

// TestClock is a clock tests move by hand.
type TestClock struct {
	mu  sync.Mutex
	now time.Time
}

func NewTestClock(now time.Time) *TestClock {
	return &TestClock{now: now}
}

func (c *TestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *TestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *TestClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}
