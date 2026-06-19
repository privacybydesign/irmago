package statuslist

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/stretchr/testify/require"
)

// TestStatusListSigner is a fixture for building signed Status List
// Tokens in tests. Each instance carries an ephemeral ECDSA key and
// a self-signed certificate; the public X509VerificationContext()
// trusts that certificate so the verifier can validate signatures.
type TestStatusListSigner struct {
	PrivKey  *ecdsa.PrivateKey
	Cert     *x509.Certificate
	DERBytes []byte
}

// NewTestStatusListSigner creates a signer backed by a self-signed
// ECDSA P-256 certificate.
func NewTestStatusListSigner(t *testing.T) *TestStatusListSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "statuslist-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &TestStatusListSigner{PrivKey: priv, Cert: parsed, DERBytes: der}
}

// X509VerificationContext returns a VerifyCertificate-friendly trust
// store that trusts this signer's certificate as a root.
func (s *TestStatusListSigner) X509VerificationContext() eudi_jwt.X509VerificationContext {
	pool := x509.NewCertPool()
	pool.AddCert(s.Cert)
	return &eudi_jwt.StaticVerificationContext{
		VerifyOpts: x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
	}
}

// TestStatusListOpts shapes a Status List Token built by SignToken.
// Zero-value defaults: bits=1, lst=all-zero (everyone Valid) sized
// to fit the highest Statuses key, iat=now, no exp/ttl.
type TestStatusListOpts struct {
	Issuer   string
	Subject  string // typically the status list URI
	IssuedAt time.Time
	// OmitIssuedAt builds a token without an `iat` claim, for
	// negative-path tests — `iat` is REQUIRED by §5.1.
	OmitIssuedAt bool
	Expiry       time.Time
	TTLSeconds   int64
	Bits         int
	// Statuses maps idx → raw status value. Indices not listed
	// default to 0 (Valid). The lst is sized to fit max(idx)+1
	// entries at the requested bits per entry.
	Statuses map[uint64]uint8
}

// SignToken builds a JWT carrying the Status List Token claims and
// signs it with the signer's key, embedding the certificate in the
// x5c header. typ defaults to "statuslist+jwt".
func (s *TestStatusListSigner) SignToken(t *testing.T, opts TestStatusListOpts) []byte {
	t.Helper()
	return s.SignTokenWithTyp(t, opts, StatusListTokenTyp)
}

// SignTokenWithTyp is like SignToken but lets the caller override
// the 'typ' header for negative-path tests.
func (s *TestStatusListSigner) SignTokenWithTyp(t *testing.T, opts TestStatusListOpts, typ string) []byte {
	t.Helper()
	bits := opts.Bits
	if bits == 0 {
		bits = 1
	}

	lstBytes := encodeStatusBits(t, opts.Statuses, bits)

	builder := jwt.NewBuilder().
		Issuer(opts.Issuer).
		Subject(opts.Subject).
		Claim("status_list", map[string]any{
			"bits": bits,
			"lst":  lstBytes,
		})
	if !opts.OmitIssuedAt {
		if opts.IssuedAt.IsZero() {
			opts.IssuedAt = time.Now()
		}
		builder = builder.IssuedAt(opts.IssuedAt)
	}
	if !opts.Expiry.IsZero() {
		builder = builder.Expiration(opts.Expiry)
	}
	if opts.TTLSeconds > 0 {
		builder = builder.Claim("ttl", opts.TTLSeconds)
	}
	tok, err := builder.Build()
	require.NoError(t, err)

	chain := &cert.Chain{}
	require.NoError(t, chain.Add([]byte(base64.StdEncoding.EncodeToString(s.DERBytes))))

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, typ))
	require.NoError(t, headers.Set(jws.X509CertChainKey, chain))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), s.PrivKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return signed
}

// encodeStatusBits packs the per-index status values into a byte
// array of bits-wide entries (little-endian within each byte, per
// spec §4), then zlib-compresses and base64url-encodes the result.
func encodeStatusBits(t *testing.T, statuses map[uint64]uint8, bits int) string {
	t.Helper()
	maxIdx := uint64(0)
	for idx := range statuses {
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	totalEntries := maxIdx + 1
	// Round up so the byte count fits all entries.
	totalBits := totalEntries * uint64(bits)
	byteLen := (totalBits + 7) / 8
	if byteLen == 0 {
		byteLen = 1
	}
	raw := make([]byte, byteLen)
	for idx, val := range statuses {
		bitStart := idx * uint64(bits)
		byteIdx := bitStart / 8
		bitOffset := uint(bitStart % 8)
		mask := byte((1 << bits) - 1)
		// Clear old bits, then set new value.
		raw[byteIdx] &^= mask << bitOffset
		raw[byteIdx] |= (val & mask) << bitOffset
	}

	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

// TestStatusListServer is an httptest.Server that serves a single
// Status List Token at any URL with the spec-mandated Content-Type.
type TestStatusListServer struct {
	server    *httptest.Server
	bodyBytes atomic.Pointer[[]byte]
	maxAge    atomic.Int64
	hits      atomic.Int64
}

// NewTestStatusListServer starts a server that returns body on every
// GET with Content-Type: application/statuslist+jwt. The returned URL
// is the server's base URL; tests should use it directly as the
// status_list.uri.
func NewTestStatusListServer(t *testing.T, body []byte) *TestStatusListServer {
	t.Helper()
	s := &TestStatusListServer{}
	s.bodyBytes.Store(&body)
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r
		s.hits.Add(1)
		w.Header().Set("Content-Type", StatusListTokenContentType)
		if mx := s.maxAge.Load(); mx > 0 {
			w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", mx))
		}
		bp := s.bodyBytes.Load()
		if bp != nil {
			_, _ = w.Write(*bp)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

// NewTestStatusListServerWithToken starts a server and serves a Status
// List Token signed by signer. opts.Subject defaults to the server's
// own URL when unset, so the §5.1 `sub` == `uri` binding holds for
// callers that reference the token by this server's URL.
func NewTestStatusListServerWithToken(t *testing.T, signer *TestStatusListSigner, opts TestStatusListOpts) *TestStatusListServer {
	t.Helper()
	srv := NewTestStatusListServer(t, nil)
	srv.Serve(t, signer, opts)
	return srv
}

// URL returns the server's base URL — what callers use as the
// status_list.uri.
func (s *TestStatusListServer) URL() string { return s.server.URL }

// Serve signs opts with signer and serves the result on subsequent
// requests. opts.Subject defaults to this server's URL when unset so
// the spec-required `sub` == `uri` binding holds.
func (s *TestStatusListServer) Serve(t *testing.T, signer *TestStatusListSigner, opts TestStatusListOpts) {
	t.Helper()
	if opts.Subject == "" {
		opts.Subject = s.URL()
	}
	s.SetBody(signer.SignToken(t, opts))
}

// SetBody atomically replaces the body served on subsequent requests.
func (s *TestStatusListServer) SetBody(body []byte) { s.bodyBytes.Store(&body) }

// SetMaxAge sets the value of the Cache-Control: max-age=N response
// header on subsequent requests. 0 omits the header.
func (s *TestStatusListServer) SetMaxAge(seconds int64) { s.maxAge.Store(seconds) }

// Hits returns the number of requests served so far.
func (s *TestStatusListServer) Hits() int64 { return s.hits.Load() }
