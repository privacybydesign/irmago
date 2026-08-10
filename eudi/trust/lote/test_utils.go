package lote

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/stretchr/testify/require"
)

// This file is deliberately not a _test.go file: session tests in
// internal/sessiontest and slices beyond this one need a LoTE they control, and
// Go does not export test-only code across packages. It follows the same shape
// as the statuslist package's test utilities.

// TestLoteSigner is a fixture for publishing signed LoTEs in tests. It carries
// a two-level PKI — a root CA and a list-signing certificate under it — because
// the real list signer chains to the Yivi root rather than being self-signed,
// and a self-signed fixture would not exercise chain building at all.
type TestLoteSigner struct {
	RootKey  *ecdsa.PrivateKey
	RootCert *x509.Certificate
	PrivKey  *ecdsa.PrivateKey
	Cert     *x509.Certificate
	DERBytes []byte
}

// NewTestLoteSigner creates a signer backed by a fresh root CA and a
// list-signing certificate issued under it.
func NewTestLoteSigner(t *testing.T) *TestLoteSigner {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "lote-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDer, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDer)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "lote-test-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDer, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, leafKey.Public(), rootKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDer)
	require.NoError(t, err)

	return &TestLoteSigner{
		RootKey:  rootKey,
		RootCert: rootCert,
		PrivKey:  leafKey,
		Cert:     leafCert,
		DERBytes: leafDer,
	}
}

// X509VerificationContext returns a trust store that anchors this signer's
// root, standing in for the pinned Yivi anchors.
func (s *TestLoteSigner) X509VerificationContext() eudi_jwt.X509VerificationContext {
	pool := x509.NewCertPool()
	pool.AddCert(s.RootCert)
	return &eudi_jwt.StaticVerificationContext{
		VerifyOpts: x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
	}
}

// SignList serializes list and signs it as a compact JAdES-B-B document.
func (s *TestLoteSigner) SignList(t *testing.T, list List) []byte {
	t.Helper()
	return s.SignListWithTyp(t, list, LoteTyp)
}

// SignListWithTyp is SignList with the `typ` header overridden, for
// negative-path tests.
func (s *TestLoteSigner) SignListWithTyp(t *testing.T, list List, typ string) []byte {
	t.Helper()

	payload, err := json.Marshal(list)
	require.NoError(t, err)

	chain := &cert.Chain{}
	require.NoError(t, chain.Add([]byte(base64.StdEncoding.EncodeToString(s.DERBytes))))

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, typ))
	require.NoError(t, headers.Set(jws.X509CertChainKey, chain))

	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), s.PrivKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return signed
}

// NewTestPartyCertificate issues a certificate for a party a test wants to put
// on a list: an end-entity certificate under this signer's root, carrying
// organizationIdentifier in its subject when one is given, and a subject key
// identifier so entries can be keyed on the key rather than the certificate.
func (s *TestLoteSigner) NewTestPartyCertificate(t *testing.T, commonName, organizationIdentifier string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	subject := pkix.Name{CommonName: commonName}
	if organizationIdentifier != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{{
			Type:  organizationIdentifierOID,
			Value: organizationIdentifier,
		}}
	}

	// A predictable SKI so a test can key an entry on it: the SHA-1 of the
	// public key is what RFC 5280 §4.2.1.2 method (1) prescribes, but any
	// stable value works here, and SHA-256 avoids a deprecated hash.
	pubDer, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	var pubInfo struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(pubDer, &pubInfo)
	require.NoError(t, err)
	ski := sha256.Sum256(pubInfo.PublicKey.Bytes)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: ski[:20],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.RootCert, key.Public(), s.RootKey)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return parsed
}

// NewTestList builds a list with a NextUpdate a day out, so a test that does
// not care about expiry gets a current one.
func NewTestList(listId string, sequenceNumber uint64, entities ...Entity) List {
	now := time.Now().UTC()
	return List{
		SchemeInformation: SchemeInformation{
			ListIdentifier:    listId,
			SequenceNumber:    sequenceNumber,
			ListIssueDateTime: now,
			NextUpdate:        now.Add(24 * time.Hour),
		},
		Entities: entities,
	}
}

// NewTestEntity builds a granted entity with the given services.
func NewTestEntity(name, organizationIdentifier string, services ...Service) Entity {
	return Entity{
		OrganizationIdentifier: organizationIdentifier,
		Name:                   clientmodels.TranslatedString{"en": name, "nl": name},
		Services:               services,
	}
}

// NewTestCertificateService builds a granted service keyed on a certificate.
func NewTestCertificateService(serviceType trust.Role, partyCert *x509.Certificate, markings ...string) Service {
	return Service{
		Type:            serviceType,
		Status:          ServiceStatusGranted,
		DigitalIdentity: DigitalIdentity{X509Certificate: partyCert.Raw},
		Markings:        markings,
	}
}

// NewTestSkiService builds a granted service keyed on a certificate's subject
// key identifier rather than on the certificate itself.
func NewTestSkiService(serviceType trust.Role, partyCert *x509.Certificate, markings ...string) Service {
	return Service{
		Type:            serviceType,
		Status:          ServiceStatusGranted,
		DigitalIdentity: DigitalIdentity{X509SKI: partyCert.SubjectKeyId},
		Markings:        markings,
	}
}

// NewTestDidService builds a granted service keyed on a DID.
func NewTestDidService(serviceType trust.Role, did string, markings ...string) Service {
	return Service{
		Type:            serviceType,
		Status:          ServiceStatusGranted,
		DigitalIdentity: DigitalIdentity{OtherIds: []OtherId{{Type: OtherIdTypeDid, Value: did}}},
		Markings:        markings,
	}
}

// TestLoteServer is a mutable httptest server publishing one LoTE. What it
// serves can be replaced between requests, so a single test can walk a list
// through a re-issue, a tampered copy, or an outage without standing up a
// second server.
type TestLoteServer struct {
	server     *httptest.Server
	bodyBytes  atomic.Pointer[[]byte]
	statusCode atomic.Int64
	hits       atomic.Int64
}

// NewTestLoteServer starts a server that serves nothing yet; call Serve to give
// it a list.
func NewTestLoteServer(t *testing.T) *TestLoteServer {
	t.Helper()
	s := &TestLoteServer{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r
		s.hits.Add(1)
		if code := s.statusCode.Load(); code != 0 {
			w.WriteHeader(int(code))
			return
		}
		w.Header().Set("Content-Type", "application/jose")
		if bp := s.bodyBytes.Load(); bp != nil {
			_, _ = w.Write(*bp)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

// URL returns the server's base URL, which is what a Source points at.
func (s *TestLoteServer) URL() string { return s.server.URL }

// Source returns a Source pointing at this server for the given list
// identifier, conferring the given level — TrustLevel_High for a fixture
// standing in for Yivi's own list, TrustLevel_Medium for any other
// recognized list.
func (s *TestLoteServer) Source(listId string, confers clientmodels.TrustLevel) Source {
	return Source{ListId: listId, URL: s.URL(), Confers: confers}
}

// Serve signs list with signer and serves it on subsequent requests.
func (s *TestLoteServer) Serve(t *testing.T, signer *TestLoteSigner, list List) {
	t.Helper()
	s.SetBody(signer.SignList(t, list))
}

// SetBody replaces the body served on subsequent requests.
func (s *TestLoteServer) SetBody(body []byte) {
	s.statusCode.Store(0)
	s.bodyBytes.Store(&body)
}

// SetStatus makes subsequent requests fail with the given HTTP status. 0
// restores serving the body.
func (s *TestLoteServer) SetStatus(code int) { s.statusCode.Store(int64(code)) }

// Close shuts the server down, so subsequent fetches fail to connect — the
// unreachable-endpoint case.
func (s *TestLoteServer) Close() { s.server.Close() }

// Hits returns the number of requests served so far.
func (s *TestLoteServer) Hits() int64 { return s.hits.Load() }
