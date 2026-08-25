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

// TestNewHolderFromSignerRejectsNonP256 keeps the wrong-curve failure at
// construction. Left to signing time it produces a signature of the wrong
// width, which fails at the verifier with nothing naming the cause.
func TestNewHolderFromSignerRejectsNonP256(t *testing.T) {
	_, err := NewHolderFromSigner(newOpaqueSigner(t, elliptic.P384()))
	if err == nil {
		t.Fatal("a P-384 device key was accepted for ES256 device authentication")
	}
	if !strings.Contains(err.Error(), "P-256") {
		t.Errorf("error was %q, want it to name the required curve", err)
	}
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

	var holders []Holder = []Holder{software, fromKey}
	for i, h := range holders {
		if h.PublicKey() == nil {
			t.Errorf("holder %d returned a nil public key", i)
		}
		if h.PublicKey().Curve != elliptic.P256() {
			t.Errorf("holder %d device key is on %s, want P-256", i, h.PublicKey().Curve.Params().Name)
		}
	}
}
