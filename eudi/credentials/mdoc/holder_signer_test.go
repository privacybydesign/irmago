package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// HOLDER AS AN INTERFACE — the hardware-backed device key path
// ============================================================

// opaqueSigner stands in for an Android StrongBox / Secure Enclave key handle:
// it can sign and it can name its public key, and there is no method that
// returns the private half. A test using it therefore cannot accidentally take
// the software route, which is the whole point of Holder being an interface.
type opaqueSigner struct {
	key *ecdsa.PrivateKey

	// What go-cose actually asked for, recorded so the contract documented on
	// NewHolderFromSigner is pinned by a test rather than by a comment alone.
	calls        int
	lastDigestLn int
	lastOptsNil  bool
}

func newOpaqueSigner(t *testing.T, curve elliptic.Curve) *opaqueSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err, "generate key: %v", err)
	return &opaqueSigner{key: key}
}

func (s *opaqueSigner) Public() crypto.PublicKey { return s.key.Public() }

func (s *opaqueSigner) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	s.lastDigestLn = len(digest)
	s.lastOptsNil = opts == nil
	// ASN.1 DER, which is what Android Keystore's SHA256withECDSA returns and
	// what go-cose expects back from an opaque signer.
	return ecdsa.SignASN1(rnd, s.key, digest)
}

// TestOpaqueSignerProducesVerifiableDeviceAuth is the reason Holder is an
// interface: a device key that cannot be extracted still produces a
// presentation the verifier accepts, with no change anywhere else in the flow.
func TestOpaqueSignerProducesVerifiableDeviceAuth(t *testing.T) {
	signer := newOpaqueSigner(t, elliptic.P256())

	holder, err := NewHolderFromSigner(signer)
	require.NoError(t, err, "NewHolderFromSigner: %v", err)
	// Holder, not *DefaultHolder: everything below goes through the interface.
	var asInterface Holder = holder

	issuer, err := NewTestIssuer()
	require.NoError(t, err, "NewTestIssuer: %v", err)

	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"

	credential, err := issuer.Issue(docType, namespace,
		map[string]any{"age_over_18": true}, asInterface.PublicKey())
	require.NoError(t, err, "Issue: %v", err)

	presented, err := SelectiveDisclose(credential, namespace, []string{"age_over_18"})
	require.NoError(t, err, "SelectiveDisclose: %v", err)

	transcript := SessionTranscript{
		DeviceEngagementBytes: testTag24("test-engagement"),
		EReaderKeyBytes:       testTag24("test-reader-key"),
		Handover:              "test-handover",
	}

	deviceAuthBytes, err := asInterface.SignDeviceAuth(docType, transcript)
	require.NoError(t, err, "SignDeviceAuth: %v", err)

	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})
	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)
	require.True(t, result.Valid && result.DeviceAuthValid, "presentation signed by an opaque device key was rejected: valid=%v deviceAuth=%v err=%q",
		result.Valid, result.DeviceAuthValid, result.Error)

	// The signing really went through the opaque signer, rather than go-cose
	// finding an *ecdsa.PrivateKey to use directly.
	require.Equal(t, 1, signer.calls, "opaque signer was called %d times, want exactly 1", signer.calls)

	// The contract a hardware wrapper has to satisfy, asserted rather than
	// described: it is handed a 32-byte SHA-256 digest and nil opts, so it must
	// assume SHA-256 instead of reading the hash function out of opts.
	require.Equal(t, 32, signer.lastDigestLn, "signer was handed %d bytes, want a 32-byte SHA-256 digest", signer.lastDigestLn)
	require.True(t, signer.lastOptsNil, "signer was handed non-nil SignerOpts; a hardware wrapper cannot rely on opts naming the hash")
}

// TestNewHolderFromSignerCurves keeps the wrong-curve failure at construction.
// Left to signing time it produces a signature the verifier rejects with nothing
// naming the cause — and go-cose does not catch it, since
// cose.NewSigner(AlgorithmES256, aP384Key) succeeds.
//
// The accepted set is the three NIST curves 9.1.3.6 pairs with ES256, ES384 and
// ES512. It was P-256 alone until the reader gained algorithm agility; a device
// key on P-384 is conformant and there is no longer any reason to refuse one.
func TestNewHolderFromSignerCurves(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run("accepts "+curve.Params().Name, func(t *testing.T) {
			holder, err := NewHolderFromSigner(newOpaqueSigner(t, curve))
			require.NoError(t, err, "ISO/IEC 18013-5 9.1.3.6 pairs %s with an ES algorithm; it must be accepted: %v",
				curve.Params().Name, err)
			// The algorithm is not a free choice — the clause fixes one per curve.
			alg, err := deviceAuthAlgorithmFor(holder.PublicKey().Curve)
			require.NoError(t, err, "no algorithm for an accepted curve: %v", err)
			want := map[string]cose.Algorithm{
				"P-256": cose.AlgorithmES256,
				"P-384": cose.AlgorithmES384,
				"P-521": cose.AlgorithmES512,
			}[curve.Params().Name]
			require.Equal(t, want, alg, "%s paired with %v, want %v", curve.Params().Name, alg, want)
		})
	}

	t.Run("refuses a curve outside the table", func(t *testing.T) {
		// P-224 is a real curve that 18013-5 does not list for cipher suite 1.
		_, err := NewHolderFromSigner(newOpaqueSigner(t, elliptic.P224()))
		require.Error(t, err, "a P-224 device key was accepted; it has no ISO/IEC 18013-5 algorithm pairing")
		require.ErrorContains(t, err, "P-224", "error was %q, want it to name the offending curve", err)
	})
}

func TestNewHolderFromSignerRejectsNonECDSA(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "generate ed25519 key: %v", err)
	_, err = NewHolderFromSigner(priv)
	require.Error(t, err, "an Ed25519 device key was accepted for ES256 device authentication")
}

func TestNewHolderRejectsNilKeys(t *testing.T) {
	_, err := NewHolderFromSigner(nil)
	require.Error(t, err, "a nil signer was accepted")
	_, err = NewHolderFromPrivateKey(nil)
	require.Error(t, err, "a nil private key was accepted")
}

// TestDefaultHolderSatisfiesHolder pins the software implementation to the same
// interface the hardware one will implement, so a change to either constructor's
// return type is caught here rather than at the call sites.
func TestDefaultHolderSatisfiesHolder(t *testing.T) {
	software, err := NewHolder()
	require.NoError(t, err, "NewHolder: %v", err)
	fromKey, err := NewHolderFromPrivateKey(software.signer.(*ecdsa.PrivateKey))
	require.NoError(t, err, "NewHolderFromPrivateKey: %v", err)

	// The []Holder element type is the assertion: both values have to satisfy the
	// interface, which is what this test is named for.
	holders := []Holder{software, fromKey}
	for i, h := range holders {
		require.NotNil(t, h.PublicKey(), "holder %d returned a nil public key", i)
		require.Equal(t, elliptic.P256(), h.PublicKey().Curve, "holder %d device key is on %s, want P-256", i, h.PublicKey().Curve.Params().Name)
	}
}
