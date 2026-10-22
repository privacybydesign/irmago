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
// DEVICE SIGNER
// ============================================================

// DeviceSigner performs ISO/IEC 18013-5 mdoc authentication with one device key:
// handing out the public half at issuance, and signing a DeviceAuthentication at
// presentation. It is the device key and nothing else — not the wallet, not the
// person the credential was issued to, neither of which this package models.
//
// It is an interface so the private half never has to exist in this process.
//
// SoftwareDeviceSigner is what the wallet uses in production today: the device
// private key lives in this process, read from storage on demand. It is reached
// through services.NewMdocDeviceKeyBinder and mdoc_dcql, not only from tests.
//
// The interface exists for what replaces it: an implementation backed by
// StrongBox, TrustZone or the Secure Enclave satisfies the same two methods
// with the key never extractable. See DeviceSignerFromSigner, which is the whole
// seam — a platform key handle only has to implement Public and Sign.
//
// Not to be confused with mdoc_dcql.DeviceKeyBinder, which is the layer above:
// it resolves a device public key to the DeviceSigner that can sign for it, and
// is what mirrors sdjwt.KeyBinder in the DCQL handler's dependencies.
type DeviceSigner interface {
	// PublicKey returns the device public key — the only part of the device key
	// pair an issuer (or anyone else) ever needs.
	PublicKey() *ecdsa.PublicKey

	// SignDeviceAuth builds and signs a fresh DeviceAuthentication for this
	// session. Called at every presentation — never reused.
	SignDeviceAuth(docType string, transcript SessionTranscript) ([]byte, error)
}

// SoftwareDeviceSigner is the software implementation of DeviceSigner: the
// device key is an ordinary in-process key, reached only through crypto.Signer
// so the same code path serves a hardware-backed key.
type SoftwareDeviceSigner struct {
	signer crypto.Signer
	pub    *ecdsa.PublicKey
}

var _ DeviceSigner = (*SoftwareDeviceSigner)(nil)

// GenerateDeviceSigner generates a fresh software device key. In production the
// equivalent key is generated inside Secure Enclave / TrustZone / StrongBox,
// where it is not extractable and every signing operation happens inside the
// hardware — for that, wrap the platform's key handle with
// DeviceSignerFromSigner instead.
func GenerateDeviceSigner() (*SoftwareDeviceSigner, error) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}
	return DeviceSignerFromSigner(deviceKey)
}

// DeviceSignerFromPrivateKey wraps an already-generated device key pair in a
// DeviceSigner. Used by wallet storage layers that persist the device key
// generated at issuance time (e.g. as part of a HolderBindingKey record) and
// need to reconstruct a signer at presentation time, in a later process than the
// one that called GenerateDeviceSigner.
func DeviceSignerFromPrivateKey(deviceKey *ecdsa.PrivateKey) (*SoftwareDeviceSigner, error) {
	if deviceKey == nil {
		return nil, fmt.Errorf("device key is nil")
	}
	return DeviceSignerFromSigner(deviceKey)
}

// DeviceSignerFromSigner wraps any crypto.Signer as a DeviceSigner, which is how
// a non-extractable device key reaches this package: an Android Keystore /
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
// The curve is checked here rather than left to signing time: 9.1.3.6 pairs each
// curve with exactly one algorithm (see deviceAuthAlgorithmFor), and a signer on
// a curve outside that table would otherwise produce a signature the verifier
// rejects with nothing naming the cause.
func DeviceSignerFromSigner(signer crypto.Signer) (*SoftwareDeviceSigner, error) {
	if signer == nil {
		return nil, fmt.Errorf("device key signer is nil")
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("device key must be ECDSA, got %T", signer.Public())
	}
	if _, err := deviceAuthAlgorithmFor(pub.Curve); err != nil {
		return nil, err
	}
	return &SoftwareDeviceSigner{signer: signer, pub: pub}, nil
}

// deviceAuthAlgorithmFor pairs a device key's curve with the COSE algorithm
// ISO/IEC 18013-5 9.1.3.6 requires with it. That clause fixes one algorithm per
// curve rather than leaving the combination open: ES256 goes with P-256, ES384
// with P-384 and ES512 with P-521. It covers the brainpool curves too, which
// this package does not carry.
//
// The pairing is not a free choice, which is why it is resolved from the curve
// rather than passed in. Signing with a mismatched algorithm is not caught by
// go-cose — cose.NewSigner(AlgorithmES256, aP384Key) succeeds — so the wrong
// pairing produces a signature that transmits fine and fails at the verifier
// with nothing naming the cause.
//
// Ed25519 and Ed448 are absent for the reason given on coseCurves: an
// ed25519.PublicKey is not an *ecdsa.PublicKey, and admitting one means widening
// this type and the device-key binder.
func deviceAuthAlgorithmFor(curve elliptic.Curve) (cose.Algorithm, error) {
	switch curve {
	case elliptic.P256():
		return cose.AlgorithmES256, nil
	case elliptic.P384():
		return cose.AlgorithmES384, nil
	case elliptic.P521():
		return cose.AlgorithmES512, nil
	}
	return 0, fmt.Errorf(
		"device key is on %s; ISO/IEC 18013-5 device authentication in this package supports P-256, P-384 and P-521",
		curve.Params().Name)
}

// PublicKey returns the device public key — the only part of the device key pair
// an issuer (or anyone else) ever needs; the private key stays behind the signer
// and is never returned.
func (h *SoftwareDeviceSigner) PublicKey() *ecdsa.PublicKey {
	return h.pub
}

// SignDeviceAuth builds and signs a fresh DeviceAuthentication for this session
// Called at every presentation — never reused
// SessionTranscript ties this signature to a specific verifier + session — defeats replay
func (h *SoftwareDeviceSigner) SignDeviceAuth(docType string, transcript SessionTranscript) ([]byte, error) {
	// deviceNameSpaces = Tag24(empty map). This signer asserts nothing of its own:
	// everything it presents is issuer-signed. A holder-asserted element would
	// need the issuer to have authorized this device key for it in the MSO's
	// keyAuthorizations — see checkDeviceSignedNameSpaces on the verifying side.
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

	// Sign with the device key — a completely separate key pair from the issuer's
	// DS key. The algorithm follows the key's curve per 9.1.3.6 rather than being
	// fixed at ES256; see deviceAuthAlgorithmFor. go-cose takes a crypto.Signer,
	// so a hardware-backed signer needs nothing extra here.
	algorithm, err := deviceAuthAlgorithmFor(h.pub.Curve)
	if err != nil {
		return nil, err
	}
	signer, err := cose.NewSigner(algorithm, h.signer)
	if err != nil {
		return nil, fmt.Errorf("create device signer: %w", err)
	}

	// Untagged, for the reason given in issuer.go: ISO 18013-5's
	// DeviceSignature is a bare COSE_Sign1 array, not COSE_Sign1_Tagged.
	msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers,
		Payload: payload}
	msg.Headers.Protected.SetAlgorithm(algorithm)
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
