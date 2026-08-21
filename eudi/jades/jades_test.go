package jades_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/privacybydesign/irmago/eudi/jades"
	"github.com/stretchr/testify/require"
)

const testTyp = "test+jwt"

type testSigner struct {
	key  *ecdsa.PrivateKey
	leaf *x509.Certificate
}

func newSigner(t *testing.T) *testSigner {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jades-test-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testSigner{key: key, leaf: leaf}
}

func (s *testSigner) sign(t *testing.T, payload []byte, at time.Time) []byte {
	t.Helper()
	signed, err := jades.SignBaselineB(payload, jades.SignOptions{
		Typ:      testTyp,
		Chain:    []*x509.Certificate{s.leaf},
		Key:      s.key,
		SignedAt: at,
	})
	require.NoError(t, err)
	return signed
}

// signRaw assembles a signature by hand, so a test can produce what
// SignBaselineB refuses to.
func (s *testSigner) signRaw(t *testing.T, payload []byte, headers map[string]any) []byte {
	t.Helper()

	chain := &cert.Chain{}
	require.NoError(t, chain.Add([]byte(base64.StdEncoding.EncodeToString(s.leaf.Raw))))

	protected := jws.NewHeaders()
	require.NoError(t, protected.Set(jws.TypeKey, testTyp))
	require.NoError(t, protected.Set(jws.X509CertChainKey, chain))
	for name, value := range headers {
		if value == nil {
			continue
		}
		require.NoError(t, protected.Set(name, value))
	}

	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), s.key, jws.WithProtectedHeaders(protected)))
	require.NoError(t, err)
	return signed
}

func verifyOpts() jades.VerifyOptions {
	return jades.VerifyOptions{AllowedTyps: []string{testTyp}}
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

// Read off the wire rather than through jwx: what matters is what another
// implementation's validator sees.
func TestSignBaselineB_ProducesTheHeadersBaselineBRequires(t *testing.T) {
	signer := newSigner(t)
	// A time with a fractional part, to prove it does not survive into the header.
	at := time.Date(2026, 8, 21, 9, 15, 30, 123456789, time.UTC)

	signed := signer.sign(t, []byte(`{"hello":"world"}`), at)

	parts := strings.Split(string(signed), ".")
	require.Len(t, parts, 3, "a compact JWS has exactly three parts")
	protected, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err, "the protected header must be base64url without padding")

	// Raw messages so the wire form is the assertion: through an int64 field,
	// "1787303730", 1787303730.0 and 1787303730.5 all read back the same.
	var header map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(protected, &header))

	require.Equal(t, `"ES256"`, string(header["alg"]))
	require.Equal(t, `"`+testTyp+`"`, string(header["typ"]))
	require.Contains(t, header, "x5c", "clause 5.1.7 requires a reference to the signing certificate")

	require.Equal(t, "1787303730", string(header[jades.IatHeader]),
		"clause 5.1.11: whole seconds since the epoch as a JSON integer")
	require.NotContains(t, header, jades.SigTHeader,
		"sigT is the pre-2025-07-15 spelling; emitting both would claim two signing times")
	require.NotContains(t, header, "crit",
		"clause 5.1.9 requires crit only alongside sigD, and iat is an RFC 7519 parameter")
}

func TestSignBaselineB_RefusesWithoutTheMaterialItNeeds(t *testing.T) {
	signer := newSigner(t)
	payload := []byte(`{"a":1}`)
	now := time.Now()

	for _, tc := range []struct {
		name string
		opts jades.SignOptions
		want string
	}{
		{"no certificate", jades.SignOptions{Key: signer.key, SignedAt: now}, "clause 5.1.7"},
		{"no key", jades.SignOptions{Chain: []*x509.Certificate{signer.leaf}, SignedAt: now}, "signing key"},
		{"no signing time", jades.SignOptions{Chain: []*x509.Certificate{signer.leaf}, Key: signer.key}, "table 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jades.SignBaselineB(payload, tc.opts)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestSignBaselineB_RefusesAnEmptyPayload(t *testing.T) {
	signer := newSigner(t)

	_, err := jades.SignBaselineB(nil, jades.SignOptions{
		Chain: []*x509.Certificate{signer.leaf}, Key: signer.key, SignedAt: time.Now(),
	})

	require.ErrorContains(t, err, "empty payload")
}

// ---------------------------------------------------------------------------
// Verifying
// ---------------------------------------------------------------------------

func TestVerifyBaselineB_AcceptsWhatSignBaselineBProduces(t *testing.T) {
	signer := newSigner(t)
	at := time.Now().Truncate(time.Second)

	verified, err := jades.VerifyBaselineB(signer.sign(t, []byte(`{"a":1}`), at), verifyOpts())

	require.NoError(t, err)
	require.JSONEq(t, `{"a":1}`, string(verified.Payload))
	require.Equal(t, signer.leaf.Raw, verified.Signer.Raw)
	require.Equal(t, at.UTC(), verified.ClaimedSigningTime)
}

// The gap the signer had: a signature with neither parameter was produced, and
// accepted.
func TestVerifyBaselineB_RejectsASignatureWithNoClaimedSigningTime(t *testing.T) {
	signer := newSigner(t)

	_, err := jades.VerifyBaselineB(signer.signRaw(t, []byte(`{"a":1}`), nil), verifyOpts())

	require.ErrorContains(t, err, "no claimed signing time")
	require.ErrorContains(t, err, "table 1")
}

// Clause 5.1.11 binds the generator of new signatures, so `sigT` still satisfies
// the requirement even though it is never emitted.
func TestVerifyBaselineB_AcceptsSigTAsTheClaimedSigningTime(t *testing.T) {
	signer := newSigner(t)
	raw := signer.signRaw(t, []byte(`{"a":1}`), map[string]any{
		jades.SigTHeader: "2026-08-21T09:15:30Z",
	})

	verified, err := jades.VerifyBaselineB(raw, verifyOpts())

	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 8, 21, 9, 15, 30, 0, time.UTC), verified.ClaimedSigningTime)
}

func TestVerifyBaselineB_RejectsAnIatThatIsNotAWholeNumberOfSeconds(t *testing.T) {
	signer := newSigner(t)
	raw := signer.signRaw(t, []byte(`{"a":1}`), map[string]any{jades.IatHeader: 1787303730.5})

	_, err := jades.VerifyBaselineB(raw, verifyOpts())

	require.ErrorContains(t, err, "fractions of a second")
}

func TestVerifyBaselineB_RejectsAQuotedIat(t *testing.T) {
	signer := newSigner(t)
	raw := signer.signRaw(t, []byte(`{"a":1}`), map[string]any{jades.IatHeader: "1787303730"})

	_, err := jades.VerifyBaselineB(raw, verifyOpts())

	require.ErrorContains(t, err, "`iat` is not a number")
}

// The test exists because jwx defaults crit validation off: drop the option and a
// document asserting "you must understand sigT" is accepted by a verifier that does
// not. Every LoTE the Commission's reference implementation publishes has this shape.
func TestVerifyBaselineB_RejectsACriticalExtensionItCannotHonour(t *testing.T) {
	signer := newSigner(t)
	raw := signer.signRaw(t, []byte(`{"a":1}`), map[string]any{
		jades.SigTHeader: "2026-08-21T09:15:30Z",
		"crit":           []string{jades.SigTHeader},
	})

	_, err := jades.VerifyBaselineB(raw, verifyOpts())

	require.ErrorContains(t, err, "crit")
	require.ErrorContains(t, err, jades.SigTHeader)
}

// JAdES leaves `typ` unconstrained, so the guard is the caller's to configure.
func TestVerifyBaselineB_RejectsAForeignTyp(t *testing.T) {
	signer := newSigner(t)
	raw := signer.signRaw(t, []byte(`{"a":1}`), map[string]any{jades.IatHeader: time.Now().Unix()})

	_, err := jades.VerifyBaselineB(raw, jades.VerifyOptions{AllowedTyps: []string{"something+else"}})

	require.ErrorContains(t, err, "typ")
}

func TestVerifyBaselineB_RefusesToRunWithNoAllowedTyps(t *testing.T) {
	signer := newSigner(t)

	_, err := jades.VerifyBaselineB(signer.sign(t, []byte(`{"a":1}`), time.Now()), jades.VerifyOptions{})

	require.ErrorContains(t, err, "state what it expects")
}

func TestVerifyBaselineB_RejectsATamperedPayload(t *testing.T) {
	signer := newSigner(t)
	signed := signer.sign(t, []byte(`{"a":1}`), time.Now())

	parts := strings.Split(string(signed), ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"a":2}`))

	_, err := jades.VerifyBaselineB([]byte(strings.Join(parts, ".")), verifyOpts())

	require.Error(t, err)
}

func TestSignatureAlgorithmFor_FollowsTheCurveAndRefusesTheRest(t *testing.T) {
	for _, tc := range []struct {
		curve elliptic.Curve
		alg   string
	}{
		{elliptic.P256(), "ES256"},
		{elliptic.P384(), "ES384"},
		{elliptic.P521(), "ES512"},
	} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		require.NoError(t, err)
		alg, err := jades.SignatureAlgorithmFor(key)
		require.NoError(t, err)
		require.Equal(t, tc.alg, alg.String())
	}

	_, err := jades.SignatureAlgorithmFor(nil)
	require.ErrorContains(t, err, "unsupported key type")
}
