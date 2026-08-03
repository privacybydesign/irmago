package lote

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/privacybydesign/irmago/common/clientmodels"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/stretchr/testify/require"
)

// The fixtures below live in a non-test file so that the tests of other
// packages — the session tests of the slices that build on this channel — can
// stand up a recognized list of their own.

// TestListSigner signs trust lists with a throwaway two-level chain: a root
// that acts as the anchor, and the list-signing certificate under it. The chain
// is what a real list signer has, so a test exercising the anchors is not
// exercising a special self-signed case.
type TestListSigner struct {
	RootCert   *x509.Certificate
	CaCert     *x509.Certificate
	SignerCert *x509.Certificate

	signerKey *ecdsa.PrivateKey
	signerDer []byte
}

// NewTestListSigner creates a signer with a fresh root, intermediate and
// list-signing certificate.
func NewTestListSigner(t *testing.T) *TestListSigner {
	t.Helper()

	rootKey, rootCert, _ := createTestCertificate(t, "lote-test-root", nil, nil)
	caKey, caCert, _ := createTestCertificate(t, "lote-test-ca", rootCert, rootKey)
	signerKey, signerCert, signerDer := createTestCertificate(t, "lote-test-signer", caCert, caKey)

	return &TestListSigner{
		RootCert:   rootCert,
		CaCert:     caCert,
		SignerCert: signerCert,
		signerKey:  signerKey,
		signerDer:  signerDer,
	}
}

// Anchors returns the verification context that trusts this signer's chain,
// for use as RecognizedList.Anchors.
func (s *TestListSigner) Anchors() eudi_jwt.X509VerificationContext {
	roots := x509.NewCertPool()
	roots.AddCert(s.RootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(s.CaCert)
	return &eudi_jwt.StaticVerificationContext{
		VerifyOpts: x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
	}
}

// Sign returns the list as a signed trust list.
func (s *TestListSigner) Sign(t *testing.T, list List) []byte {
	t.Helper()
	return s.SignWithTyp(t, list, Typ)
}

// SignWithTyp is Sign with the 'typ' header overridden, for negative paths.
func (s *TestListSigner) SignWithTyp(t *testing.T, list List, typ string) []byte {
	t.Helper()

	payload, err := json.Marshal(list)
	require.NoError(t, err)

	chain := &cert.Chain{}
	require.NoError(t, chain.Add([]byte(base64.StdEncoding.EncodeToString(s.signerDer))))

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, typ))
	require.NoError(t, headers.Set(jws.X509CertChainKey, chain))

	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), s.signerKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return signed
}

// createTestCertificate creates a CA-capable certificate, self-signed when
// parent is nil. Everything on the chain can sign, so one helper covers the
// root, the intermediate and the leaf.
func createTestCertificate(
	t *testing.T,
	commonName string,
	parentCert *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(mustRandomSerial(t)),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Yivi Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	signingCert, signingKey := template, key
	if parentCert != nil {
		signingCert, signingKey = parentCert, parentKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signingCert, key.Public(), signingKey)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, parsed, der
}

func mustRandomSerial(t *testing.T) int64 {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	return serial.Int64()
}

// ========================================================================
// Building lists
// ========================================================================

// TestListOpts shapes a list built by NewTestList. Zero-value defaults:
// sequence number 1, and a NextUpdate an hour out.
type TestListOpts struct {
	Id             string
	SequenceNumber int64
	NextUpdate     time.Time
	Providers      []TrustServiceProvider
}

// NewTestList builds a list from opts.
func NewTestList(opts TestListOpts) List {
	if opts.SequenceNumber == 0 {
		opts.SequenceNumber = 1
	}
	if opts.NextUpdate.IsZero() {
		opts.NextUpdate = time.Now().Add(time.Hour)
	}
	return List{
		SchemeInformation: SchemeInformation{
			ListIdentifier: opts.Id,
			SequenceNumber: opts.SequenceNumber,
			IssueDateTime:  time.Now().Add(-time.Minute),
			NextUpdate:     opts.NextUpdate,
		},
		Providers: opts.Providers,
	}
}

// GrantedVerifier builds a provider with one granted verifier service under the
// given name, identified by every one of the identities.
func GrantedVerifier(name string, identities ...DigitalIdentity) TrustServiceProvider {
	return grantedProvider(name, ServiceTypeVerifier, identities)
}

// GrantedIssuer builds a provider with one granted issuer service under the
// given name, identified by every one of the identities.
func GrantedIssuer(name string, identities ...DigitalIdentity) TrustServiceProvider {
	return grantedProvider(name, ServiceTypeIssuer, identities)
}

func grantedProvider(name, serviceType string, identities []DigitalIdentity) TrustServiceProvider {
	return TrustServiceProvider{
		Name: clientmodels.TranslatedString{"en": name},
		Services: []Service{{
			Type:       serviceType,
			Status:     StatusGranted,
			Identities: identities,
		}},
	}
}

// DidIdentity identifies a party by its DID.
func DidIdentity(did string) DigitalIdentity {
	return DigitalIdentity{OtherId: &OtherId{Type: OtherIdTypeDid, Value: did}}
}

// UriIdentity identifies a party by an HTTPS identifier, such as an OpenID4VCI
// credential issuer identifier.
func UriIdentity(uri string) DigitalIdentity {
	return DigitalIdentity{OtherId: &OtherId{Type: OtherIdTypeUri, Value: uri}}
}

// CertificateIdentity identifies a party by exactly this certificate.
func CertificateIdentity(certificate *x509.Certificate) DigitalIdentity {
	return DigitalIdentity{X509Certificate: base64.StdEncoding.EncodeToString(certificate.Raw)}
}

// SkiIdentity identifies a party by the subject key identifier of its
// certificate, so a re-issue of the same key still matches.
func SkiIdentity(certificate *x509.Certificate) DigitalIdentity {
	return DigitalIdentity{X509Ski: base64.StdEncoding.EncodeToString(certificate.SubjectKeyId)}
}

// ========================================================================
// Serving lists
// ========================================================================

// TestListServer serves one signed trust list, and lets the test change what it
// serves while a wallet is pointed at it — which is what the degradation cases
// (a tampered, expired or rolled-back list) and the transition cases need.
type TestListServer struct {
	server *httptest.Server
	body   atomic.Pointer[[]byte]
	status atomic.Int64
	hits   atomic.Int64
	delay  atomic.Int64
}

// NewTestListServer starts a server that serves nothing yet. Use Serve to give
// it a list.
func NewTestListServer(t *testing.T) *TestListServer {
	t.Helper()
	s := &TestListServer{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		if delay := s.delay.Load(); delay > 0 {
			time.Sleep(time.Duration(delay))
		}
		if status := s.status.Load(); status != 0 {
			w.WriteHeader(int(status))
			return
		}
		if body := s.body.Load(); body != nil {
			_, _ = w.Write(*body)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

// URL is where the list is served: what RecognizedList.URL points at.
func (s *TestListServer) URL() string { return s.server.URL }

// Serve signs the list and serves it on every subsequent request.
func (s *TestListServer) Serve(t *testing.T, signer *TestListSigner, list List) {
	t.Helper()
	s.SetBody(signer.Sign(t, list))
}

// SetBody replaces the bytes served on subsequent requests.
func (s *TestListServer) SetBody(body []byte) { s.body.Store(&body) }

// SetStatus makes subsequent requests fail with this HTTP status. 0 restores
// serving the list.
func (s *TestListServer) SetStatus(status int) { s.status.Store(int64(status)) }

// SetDelay holds every subsequent request open for this long before answering,
// so a test can have several sessions meet one fetch in flight.
func (s *TestListServer) SetDelay(delay time.Duration) { s.delay.Store(int64(delay)) }

// Close stops the server, so the endpoint becomes unreachable.
func (s *TestListServer) Close() { s.server.Close() }

// Hits is how many requests have been served, for asserting that a wallet does
// not re-fetch a list it already has.
func (s *TestListServer) Hits() int64 { return s.hits.Load() }

// RecognizedList returns the configuration that recognizes this server's list
// under listId, verified against signer's anchors — ready to hand to
// NewChecker or to the wallet's WithRecognizedLists option.
func (s *TestListServer) RecognizedList(listId string, signer *TestListSigner) RecognizedList {
	return RecognizedList{Id: listId, URL: s.URL(), Anchors: signer.Anchors()}
}
