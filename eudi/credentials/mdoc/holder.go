package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	cose "github.com/veraison/go-cose"
)

// ============================================================
// HOLDER
// ============================================================

// Holder is the wallet app on the user's device, reduced to the only two
// operations that need the device key: handing out the public half at issuance,
// and signing a DeviceAuthentication at presentation.
//
// It is an interface so the private half never has to exist in this process.
// DefaultHolder is the software implementation used by tests and by the current
// wallet; an implementation backed by StrongBox, TrustZone or the Secure Enclave
// satisfies the same two methods without the key ever being extractable. See
// NewHolderFromSigner for the cheapest route to one.
type Holder interface {
	// PublicKey returns the device public key — the only part of the device key
	// pair an issuer (or anyone else) ever needs.
	PublicKey() *ecdsa.PublicKey

	// SignDeviceAuth builds and signs a fresh DeviceAuthentication for this
	// session. Called at every presentation — never reused.
	SignDeviceAuth(docType string, transcript SessionTranscript) ([]byte, error)
}

// DefaultHolder is the software implementation of Holder: the device key is an
// ordinary in-process key, reached only through crypto.Signer so the same code
// path serves a hardware-backed key.
type DefaultHolder struct {
	signer crypto.Signer
	pub    *ecdsa.PublicKey
}

var _ Holder = (*DefaultHolder)(nil)

// NewHolder generates a fresh software device key. In production the equivalent
// key is generated inside Secure Enclave / TrustZone / StrongBox, where it is
// not extractable and every signing operation happens inside the hardware — for
// that, wrap the platform's key handle with NewHolderFromSigner instead.
func NewHolder() (*DefaultHolder, error) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}
	return NewHolderFromSigner(deviceKey)
}

// NewHolderFromPrivateKey wraps an already-generated device key pair in a
// Holder. Used by wallet storage layers that persist the device key
// generated at issuance time (e.g. as part of a HolderBindingKey record)
// and need to reconstruct a Holder capable of signing at presentation
// time, in a later process than the one that called NewHolder.
func NewHolderFromPrivateKey(deviceKey *ecdsa.PrivateKey) (*DefaultHolder, error) {
	if deviceKey == nil {
		return nil, fmt.Errorf("device key is nil")
	}
	return NewHolderFromSigner(deviceKey)
}

// NewHolderFromSigner wraps any crypto.Signer as a Holder, which is how a
// non-extractable device key reaches this package: an Android Keystore /
// StrongBox or Secure Enclave key handle only has to implement Public and Sign.
//
// The signer must satisfy the contract go-cose imposes on an opaque signer
// (ecdsa.go, ecdsaCryptoSigner.SignDigest), because that is what will call it:
//
//   - Sign receives the already-computed SHA-256 digest, not the message, and
//     opts is nil — so the implementation must assume SHA-256 rather than read
//     the hash from opts.
//   - Sign must return an ASN.1 DER SEQUENCE of (r, s). go-cose converts that to
//     the raw r||s COSE form itself. Android Keystore's "SHA256withECDSA"
//     already returns DER, so it fits without conversion.
//
// The curve is checked here rather than left to signing time: ES256 is the only
// algorithm ISO 18013-5 device authentication uses in this package, and a signer
// on any other curve would otherwise produce a signature of the wrong width that
// fails at the verifier with nothing naming the cause.
func NewHolderFromSigner(signer crypto.Signer) (*DefaultHolder, error) {
	if signer == nil {
		return nil, fmt.Errorf("device key signer is nil")
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("device key must be ECDSA, got %T", signer.Public())
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("device key must be on P-256 for ES256 device authentication, got %s", pub.Curve.Params().Name)
	}
	return &DefaultHolder{signer: signer, pub: pub}, nil
}

// PublicKey returns the holder's device public key — the only part of the
// device key pair an issuer (or anyone else) ever needs; the private key
// stays behind the signer and is never returned.
func (h *DefaultHolder) PublicKey() *ecdsa.PublicKey {
	return h.pub
}

// SignDeviceAuth builds and signs a fresh DeviceAuthentication for this session
// Called at every presentation — never reused
// SessionTranscript ties this signature to a specific verifier + session — defeats replay
func (h *DefaultHolder) SignDeviceAuth(docType string, transcript SessionTranscript) ([]byte, error) {
	// deviceNameSpaces = Tag24(empty map) for AV Blueprint
	// The AV profile has no holder-asserted claims — only issuer-signed attributes
	emptyNS, err := tag24Wrap(map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("encode empty nameSpaces: %w", err)
	}

	// DeviceAuthentication is a CBOR array (not map):
	// ["DeviceAuthentication", SessionTranscript, docType, deviceNameSpaces]
	// This is what ECDSA actually signs (via Sig_structure inside COSE_Sign1)
	deviceAuth := DeviceAuthentication{
		Context:           "DeviceAuthentication",
		SessionTranscript: transcript,
		DocType:           docType,
		DeviceNameSpaces:  emptyNS,
	}

	// DeviceAuthentication travels as Tag24(CBOR(DeviceAuthentication)) —
	// the same "Bytes" pattern ISO 18013-5 uses for MSO. Confirmed against
	// Multipaz's actual signing code (MdocDocument.kt): the whole array is
	// wrapped in Tagged(ENCODED_CBOR, ...) — CBOR tag 24 — before signing,
	// not just the deviceNameSpaces element inside it.
	payload, err := tag24Wrap(deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("wrap deviceAuthentication: %w", err)
	}

	// Sign with the device key — uses the same ES256 (ECDSA P-256 + SHA-256) as
	// issuerAuth but with a completely separate key pair (holder's device key,
	// not issuer's DS key). go-cose takes a crypto.Signer, so a hardware-backed
	// signer needs nothing extra here.
	signer, err := cose.NewSigner(cose.AlgorithmES256, h.signer)
	if err != nil {
		return nil, fmt.Errorf("create device signer: %w", err)
	}

	// Untagged, for the reason given in issuer.go: ISO 18013-5's
	// DeviceSignature is a bare COSE_Sign1 array, not COSE_Sign1_Tagged.
	msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers,
		Payload: payload}
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	// unprotected headers intentionally empty — no cert in deviceAuth
	// trust comes from deviceKey being embedded in the already-trusted MSO

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("sign deviceAuth: %w", err)
	}

	// Detach the payload before transmitting: the AV Blueprint spec's own
	// worked example (Annex A §A.11) shows deviceSignature's payload as
	// `null`, not the actual DeviceAuthentication bytes — the verifier has
	// every input already (its own session transcript, the docType it
	// requested, and the deviceNameSpaces transmitted alongside this
	// signature) and reconstructs this structure itself rather than
	// receiving it explicitly. The signature above was computed over the
	// real payload bytes and remains valid; clearing msg.Payload now only
	// affects what's serialized for transmission, not what was signed.
	msg.Payload = nil

	return msg.MarshalCBOR()
}
