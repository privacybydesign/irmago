package walletconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

const testConfigURL = "https://config.example/wallet-config/v1/"

func TestVerify_AcceptsAConfigSignedUnderTheEnvironmentRoot(t *testing.T) {
	signer := NewTestSigner(t)
	now := time.Now()
	raw := signer.Sign(t, NewTestConfig("test", 3, now))

	verified, err := Verify(raw, signer.Environment("test", testConfigURL), now)
	require.NoError(t, err)
	require.Equal(t, uint64(3), verified.Config.Version)
	require.Equal(t, "test", verified.Config.Environment)
	require.Equal(t, raw, verified.Raw, "the bytes that verified are what gets stored")
	require.True(t, signer.Cert.Equal(verified.Signer))
	require.Len(t, verified.Config.TrustedEntities, 1)
	require.Equal(t, "did:web:example.com", verified.Config.TrustedEntities[0].Handles[0].DID)
}

func TestVerify_RoundTripsAFullyFeaturedConfig(t *testing.T) {
	signer := NewTestSigner(t)
	config := fullyFeaturedConfig(t)

	verified, err := Verify(signer.Sign(t, config), signer.Environment("test", testConfigURL), time.Now())
	require.NoError(t, err)
	require.JSONEq(t, string(mustJSON(t, config)), string(mustJSON(t, verified.Config)))

	ca := verified.Config.TrustedEntities[0].Handles[0]
	require.True(t, ca.RootCertificate.IsCA)
	require.Len(t, ca.Intermediates, 1)
	require.Equal(t, "party.example", verified.Config.TrustedEntities[1].Handles[0].Certificate.Subject.CommonName)
}

func TestVerify_AcceptsALeafDirectlyUnderTheRoot(t *testing.T) {
	signer := NewTestSigner(t)
	key, leaf := NewTestEndEntity(t, "direct-signer", signer.Root, signer.RootKey, nil)
	payload := mustJSON(t, NewTestConfig("test", 1, time.Now()))

	raw := signer.SignWith(t, payload, SignOverrides{Key: key, Chain: []*x509.Certificate{leaf}})
	_, err := Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.NoError(t, err)
}

func TestVerify_RejectsAnotherTyp(t *testing.T) {
	signer := NewTestSigner(t)
	payload := mustJSON(t, NewTestConfig("test", 1, time.Now()))

	raw := signer.SignWith(t, payload, SignOverrides{Typ: "tl+jwt"})
	_, err := Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, `typ is "tl+jwt"`)

	raw = signer.SignWith(t, payload, SignOverrides{OmitTyp: true})
	_, err = Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, "typ is")
}

// ES256 is the only algorithm. A stronger curve is refused too: the allow-list
// has one entry, and widening it is a decision, not a fallback.
func TestVerify_RejectsAnotherAlgorithm(t *testing.T) {
	signer := NewTestSigner(t)
	key384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	leaf384 := issue(t, &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: "p384-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, signer.Intermediate, key384.Public(), signer.IntermediateKey)

	es384 := jwa.ES384()
	raw := signer.SignWith(t, mustJSON(t, NewTestConfig("test", 1, time.Now())), SignOverrides{
		Alg: &es384, Key: key384, Chain: []*x509.Certificate{leaf384, signer.Intermediate},
	})
	_, err = Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, `alg is "ES384"`)
}

func TestVerify_RejectsCriticalHeaderParameters(t *testing.T) {
	signer := NewTestSigner(t)
	raw := signer.SignWith(t, mustJSON(t, NewTestConfig("test", 1, time.Now())), SignOverrides{
		Extra: map[string]any{"crit": []string{"exp"}, "exp": 1},
	})
	_, err := Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, "critical header parameters [exp]")
}

func TestVerify_RejectsAMissingChain(t *testing.T) {
	signer := NewTestSigner(t)
	raw := signer.SignWith(t, mustJSON(t, NewTestConfig("test", 1, time.Now())), SignOverrides{OmitChain: true})
	_, err := Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, "missing x5c header")
}

// jwx refuses to build such a header itself, so the document is assembled by
// hand: what a broken or hostile publisher could put on the wire.
func TestVerify_RejectsAChainThatIsNotCertificates(t *testing.T) {
	signer := NewTestSigner(t)
	raw := handBuiltJWS(t, map[string]any{
		"alg": "ES256",
		"typ": Typ,
		"x5c": []string{base64.StdEncoding.EncodeToString([]byte("not a certificate"))},
	}, mustJSON(t, NewTestConfig("test", 1, time.Now())), signer.Key)

	_, err := Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.Error(t, err)
	require.NotContains(t, err.Error(), "verify signature", "refused before any signature check")
}

// handBuiltJWS signs a compact JWS with ES256 without going through jwx, so a
// header jwx would refuse to construct can still be tested.
func handBuiltJWS(t *testing.T, header map[string]any, payload []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	signingInput := base64.RawURLEncoding.EncodeToString(mustJSON(t, header)) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return []byte(signingInput + "." + base64.RawURLEncoding.EncodeToString(signature))
}

func TestVerify_RejectsAChainToAnotherRoot(t *testing.T) {
	signer := NewTestSigner(t)
	other := NewTestSigner(t)
	raw := other.Sign(t, NewTestConfig("test", 1, time.Now()))

	_, err := Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, "unknown authority")
}

// The chain is checked against the presented intermediates plus the root, and
// nothing else: an intermediate left out of x5c is not looked up anywhere.
func TestVerify_RejectsAChainMissingItsIntermediate(t *testing.T) {
	signer := NewTestSigner(t)
	raw := signer.SignWith(t, mustJSON(t, NewTestConfig("test", 1, time.Now())), SignOverrides{
		Chain: []*x509.Certificate{signer.Cert},
	})
	_, err := Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, "unknown authority")
}

func TestVerify_RejectsALeafWithoutDigitalSignatureKeyUsage(t *testing.T) {
	signer := NewTestSigner(t)
	key, leaf := NewTestEndEntity(t, "enciphering-signer", signer.Intermediate, signer.IntermediateKey, func(template *x509.Certificate) {
		template.KeyUsage = x509.KeyUsageKeyEncipherment
	})
	raw := signer.SignWith(t, mustJSON(t, NewTestConfig("test", 1, time.Now())), SignOverrides{
		Key: key, Chain: []*x509.Certificate{leaf, signer.Intermediate},
	})
	_, err := Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, "digitalSignature")
}

// The chain is validated at the moment given, not at the wall clock: a
// certificate is checked as of when the wallet reads the document.
func TestVerify_ChecksTheChainAtTheGivenMoment(t *testing.T) {
	signer := NewTestSigner(t)
	expiry := time.Now().Add(-time.Minute)
	key, leaf := NewTestEndEntity(t, "expired-signer", signer.Intermediate, signer.IntermediateKey, func(template *x509.Certificate) {
		template.NotAfter = expiry
	})
	raw := signer.SignWith(t, mustJSON(t, NewTestConfig("test", 1, time.Now())), SignOverrides{
		Key: key, Chain: []*x509.Certificate{leaf, signer.Intermediate},
	})
	env := signer.Environment("test", testConfigURL)

	_, err := Verify(raw, env, time.Now())
	require.ErrorContains(t, err, "expired")

	_, err = Verify(raw, env, expiry.Add(-30*time.Minute))
	require.NoError(t, err, "inside the certificate's validity window the same document verifies")
}

func TestVerify_RejectsAConfigForAnotherEnvironment(t *testing.T) {
	signer := NewTestSigner(t)
	raw := signer.Sign(t, NewTestConfig("production", 1, time.Now()))

	_, err := Verify(raw, signer.Environment("staging", testConfigURL), time.Now())
	require.ErrorContains(t, err, `for environment "production", expected "staging"`)
}

func TestVerify_RejectsAnUnsupportedSchemaMajor(t *testing.T) {
	signer := NewTestSigner(t)
	config := NewTestConfig("test", 1, time.Now())
	config.SchemaVersion = "2.0"

	_, err := Verify(signer.SignRaw(t, mustJSON(t, config)), signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, "major 2 is not supported")
}

func TestVerify_RejectsAPayloadThatIsNotAConfig(t *testing.T) {
	signer := NewTestSigner(t)
	env := signer.Environment("test", testConfigURL)

	_, err := Verify(signer.SignRaw(t, []byte("not json")), env, time.Now())
	require.ErrorContains(t, err, "decode payload")

	config := NewTestConfig("test", 0, time.Now())
	_, err = Verify(signer.SignRaw(t, mustJSON(t, config)), env, time.Now())
	require.ErrorContains(t, err, "invalid config")
	require.ErrorContains(t, err, "version must be at least 1")
}

// Must-ignore: a field this client does not know, at any level, is not a reason
// to refuse the document. This is what lets a minor schema bump ship without an
// app release.
func TestVerify_IgnoresUnknownFields(t *testing.T) {
	signer := NewTestSigner(t)
	var document map[string]any
	require.NoError(t, json.Unmarshal(mustJSON(t, NewTestConfig("test", 1, time.Now())), &document))
	document["services"] = map[string]any{"wallet_provider": "https://wp.example"}
	entity := document["trusted_entities"].([]any)[0].(map[string]any)
	entity["future_field"] = true
	entity["handles"].([]any)[0].(map[string]any)["future_handle_field"] = "x"
	payload, err := json.Marshal(document)
	require.NoError(t, err)

	verified, err := Verify(signer.SignRaw(t, payload), signer.Environment("test", testConfigURL), time.Now())
	require.NoError(t, err)
	require.Equal(t, uint64(1), verified.Config.Version)
	require.Equal(t, "did:web:example.com", verified.Config.TrustedEntities[0].Handles[0].DID)
}

func TestVerify_RejectsATamperedPayload(t *testing.T) {
	signer := NewTestSigner(t)
	raw := signer.Sign(t, NewTestConfig("test", 1, time.Now()))

	parts := strings.Split(string(raw), ".")
	require.Len(t, parts, 3)
	tampered := NewTestConfig("test", 2, time.Now())
	parts[1] = base64.RawURLEncoding.EncodeToString(mustJSON(t, tampered))

	_, err := Verify([]byte(strings.Join(parts, ".")), signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, "verify signature")
}

// A genuine chain on the header proves nothing about who signed: the signature
// must verify under the leaf's key.
func TestVerify_RejectsASignatureByAnotherKeyUnderAGenuineChain(t *testing.T) {
	signer := NewTestSigner(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	raw := signer.SignWith(t, mustJSON(t, NewTestConfig("test", 1, time.Now())), SignOverrides{Key: otherKey})

	_, err = Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, "verify signature")
}

// jws.Verify accepts a JSON-serialized document as soon as any one of its
// signatures holds, so a second signature is refused before that can matter.
func TestVerify_RejectsMultipleSignatures(t *testing.T) {
	signer := NewTestSigner(t)
	other := NewTestSigner(t)
	headersFor := func(s *TestSigner) jws.Headers {
		headers, err := protectedHeaders(Typ, s.Chain())
		require.NoError(t, err)
		return headers
	}
	raw, err := jws.Sign(mustJSON(t, NewTestConfig("test", 1, time.Now())),
		jws.WithJSON(),
		jws.WithKey(jwa.ES256(), signer.Key, jws.WithProtectedHeaders(headersFor(signer))),
		jws.WithKey(jwa.ES256(), other.Key, jws.WithProtectedHeaders(headersFor(other))),
	)
	require.NoError(t, err)

	_, err = Verify(raw, signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, "expected exactly one signature, got 2")
}

func TestVerify_RejectsAnEnvironmentWithoutARoot(t *testing.T) {
	signer := NewTestSigner(t)
	raw := signer.Sign(t, NewTestConfig("test", 1, time.Now()))
	_, err := Verify(raw, Environment{Name: "test"}, time.Now())
	require.ErrorContains(t, err, "no signing root")
}

func TestVerify_RejectsGarbage(t *testing.T) {
	signer := NewTestSigner(t)
	_, err := Verify([]byte("garbage"), signer.Environment("test", testConfigURL), time.Now())
	require.ErrorContains(t, err, "parse JWS")
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
