package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"strings"
	"testing"

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
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
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
	if err != nil {
		t.Fatalf("NewHolderFromSigner: %v", err)
	}
	// Holder, not *DefaultHolder: everything below goes through the interface.
	var asInterface Holder = holder

	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"

	credential, err := issuer.Issue(docType, namespace,
		map[string]any{"age_over_18": true}, asInterface.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	presented, err := SelectiveDisclose(credential, namespace, []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	transcript := SessionTranscript{
		DeviceEngagementBytes: []byte("test-engagement"),
		EReaderKeyBytes:       []byte("test-reader-key"),
		Handover:              "test-handover",
	}

	deviceAuthBytes, err := asInterface.SignDeviceAuth(docType, transcript)
	if err != nil {
		t.Fatalf("SignDeviceAuth: %v", err)
	}

	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})
	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)
	if !result.Valid || !result.DeviceAuthValid {
		t.Fatalf("presentation signed by an opaque device key was rejected: valid=%v deviceAuth=%v err=%q",
			result.Valid, result.DeviceAuthValid, result.Error)
	}

	// The signing really went through the opaque signer, rather than go-cose
	// finding an *ecdsa.PrivateKey to use directly.
	if signer.calls != 1 {
		t.Errorf("opaque signer was called %d times, want exactly 1", signer.calls)
	}

	// The contract a hardware wrapper has to satisfy, asserted rather than
	// described: it is handed a 32-byte SHA-256 digest and nil opts, so it must
	// assume SHA-256 instead of reading the hash function out of opts.
	if signer.lastDigestLn != 32 {
		t.Errorf("signer was handed %d bytes, want a 32-byte SHA-256 digest", signer.lastDigestLn)
	}
	if !signer.lastOptsNil {
		t.Errorf("signer was handed non-nil SignerOpts; a hardware wrapper cannot rely on opts naming the hash")
	}
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
			if err != nil {
				t.Fatalf("ISO/IEC 18013-5 9.1.3.6 pairs %s with an ES algorithm; it must be accepted: %v",
					curve.Params().Name, err)
			}
			// The algorithm is not a free choice — the clause fixes one per curve.
			alg, err := deviceAuthAlgorithmFor(holder.PublicKey().Curve)
			if err != nil {
				t.Fatalf("no algorithm for an accepted curve: %v", err)
			}
			want := map[string]cose.Algorithm{
				"P-256": cose.AlgorithmES256,
				"P-384": cose.AlgorithmES384,
				"P-521": cose.AlgorithmES512,
			}[curve.Params().Name]
			if alg != want {
				t.Errorf("%s paired with %v, want %v", curve.Params().Name, alg, want)
			}
		})
	}

	t.Run("refuses a curve outside the table", func(t *testing.T) {
		// P-224 is a real curve that 18013-5 does not list for cipher suite 1.
		_, err := NewHolderFromSigner(newOpaqueSigner(t, elliptic.P224()))
		if err == nil {
			t.Fatal("a P-224 device key was accepted; it has no ISO/IEC 18013-5 algorithm pairing")
		}
		if !strings.Contains(err.Error(), "P-224") {
			t.Errorf("error was %q, want it to name the offending curve", err)
		}
	})
}

func TestNewHolderFromSignerRejectsNonECDSA(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	if _, err := NewHolderFromSigner(priv); err == nil {
		t.Fatal("an Ed25519 device key was accepted for ES256 device authentication")
	}
}

func TestNewHolderRejectsNilKeys(t *testing.T) {
	if _, err := NewHolderFromSigner(nil); err == nil {
		t.Error("a nil signer was accepted")
	}
	if _, err := NewHolderFromPrivateKey(nil); err == nil {
		t.Error("a nil private key was accepted")
	}
}

// TestDefaultHolderSatisfiesHolder pins the software implementation to the same
// interface the hardware one will implement, so a change to either constructor's
// return type is caught here rather than at the call sites.
func TestDefaultHolderSatisfiesHolder(t *testing.T) {
	software, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	fromKey, err := NewHolderFromPrivateKey(software.signer.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("NewHolderFromPrivateKey: %v", err)
	}

	// The []Holder element type is the assertion: both values have to satisfy the
	// interface, which is what this test is named for.
	holders := []Holder{software, fromKey}
	for i, h := range holders {
		if h.PublicKey() == nil {
			t.Errorf("holder %d returned a nil public key", i)
		}
		if h.PublicKey().Curve != elliptic.P256() {
			t.Errorf("holder %d device key is on %s, want P-256", i, h.PublicKey().Curve.Params().Name)
		}
	}
}
