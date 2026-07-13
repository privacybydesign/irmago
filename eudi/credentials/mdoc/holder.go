package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// HOLDER
// ============================================================

// Holder represents the wallet app on the user's device
// deviceKey is generated locally — private key never leaves the device (TEE/Secure Enclave in production)
// Only the PUBLIC key is sent to the issuer at issuance time
type Holder struct {
	devicekey *ecdsa.PrivateKey
}

func NewHolder() (*Holder, error) {
	// In production: generated inside Secure Enclave / TrustZone / StrongBox
	// Private key never extractable — all signing operations happen inside the hardware
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}
	return &Holder{devicekey: deviceKey}, nil
}

// PublicKey returns the holder's device public key — the only part of the
// device key pair an issuer (or anyone else) ever needs; the private key
// stays inside Holder and is never returned.
func (h *Holder) PublicKey() *ecdsa.PublicKey {
	return &h.devicekey.PublicKey
}

// SignDeviceAuth builds and signs a fresh DeviceAuthentication for this session
// Called at every presentation — never reused
// SessionTranscript ties this signature to a specific verifier + session — defeats replay
func (h *Holder) SignDeviceAuth(docType string, transcript SessionTranscript) ([]byte, error) {
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

	payload, err := cbor.Marshal(deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("marshal deviceAuthentication: %w", err)
	}

	// Sign with device private key — uses same ES256 (ECDSA P-256 + SHA-256) as issuerAuth
	// but with a completely separate key pair (holder's device key, not issuer's DS key)
	signer, err := cose.NewSigner(cose.AlgorithmES256, h.devicekey)
	if err != nil {
		return nil, fmt.Errorf("create device signer: %w", err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	// unprotected headers intentionally empty — no cert in deviceAuth
	// trust comes from deviceKey being embedded in the already-trusted MSO

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("sign deviceAuth: %w", err)
	}

	// Detach the payload before transmitting: the AV Blueprint spec's own
	// worked example (Annex A §A.11) shows deviceSignature's payload as
	// `null`, not the actual DeviceAuthentication bytes — the verifier
	// already knows every input (its own session transcript, the fixed
	// empty deviceNameSpaces, the docType it requested) and reconstructs
	// this structure itself rather than receiving it explicitly. The
	// signature above was computed over the real payload bytes and
	// remains valid; clearing msg.Payload now only affects what's
	// serialized for transmission, not what was signed.
	msg.Payload = nil

	return cbor.Marshal(msg)
}

// SelectiveDisclose filters the credential to only include the requested attributes
// issuerAuth is reused unchanged — the issuer's signature covers all digests regardless
// of which subset the holder chooses to reveal at any given presentation
func SelectiveDisclose(mdoc *MDoc, namespace string, reveal []string) (*MDoc, error) {
	fmt.Println("\n--- HOLDER: Selective disclosure ---")

	revealSet := make(map[string]bool)
	for _, r := range reveal {
		revealSet[r] = true
	}

	allItems := mdoc.IssuerSigned.NameSpaces[namespace]
	var disclosed []Tag24Item

	for _, tag24item := range allItems {
		// decode Tag-24 wrapped item to peek at the elementIdentifier
		var rawTag cbor.RawTag
		if err := cbor.Unmarshal(tag24item.EncodedItem, &rawTag); err != nil {
			return nil, fmt.Errorf("unwrap tag24: %w", err)
		}
		var innerBytes []byte
		if err := cbor.Unmarshal(rawTag.Content, &innerBytes); err != nil {
			return nil, fmt.Errorf("unwrap inner bytes: %w", err)
		}
		var item IssuerSignedItem
		if err := cbor.Unmarshal(innerBytes, &item); err != nil {
			return nil, fmt.Errorf("decode item: %w", err)
		}

		if revealSet[item.ElementIdentifier] {
			fmt.Printf("  Revealing:   %s\n", item.ElementIdentifier)
			disclosed = append(disclosed, tag24item)
		} else {
			fmt.Printf("  Withholding: %s\n", item.ElementIdentifier)
		}
	}

	return &MDoc{
		DocType: mdoc.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: disclosed},
			IssuerAuth: mdoc.IssuerSigned.IssuerAuth, // reused unchanged
		},
	}, nil
}
