package mdoc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// BuildOID4VPSessionTranscript builds the SessionTranscript CBOR for an
// OpenID4VP mdoc disclosure, per OpenID4VP §B.2.6 and ISO/IEC 18013-7. The
// returned bytes are the CBOR encoding of:
//
//	SessionTranscript = [null, null, OID4VPHandover]
//	OID4VPHandover    = [clientIdHash, responseUriHash, nonce]
//	clientIdHash      = SHA-256( CBOR([clientId, nonce]) )
//	responseUriHash   = SHA-256( CBOR([responseUri, nonce]) )
//
// The wallet signs DeviceAuthentication over this value; the verifier
// rebuilds it from the Authorization Request parameters it issued.
func BuildOID4VPSessionTranscript(clientId, responseUri, nonce string) ([]byte, error) {
	clientIdHash, err := sha256CBORArray([]string{clientId, nonce})
	if err != nil {
		return nil, fmt.Errorf("mdoc: hash clientId: %w", err)
	}
	responseUriHash, err := sha256CBORArray([]string{responseUri, nonce})
	if err != nil {
		return nil, fmt.Errorf("mdoc: hash responseUri: %w", err)
	}
	handover := []any{clientIdHash, responseUriHash, nonce}
	return cbor.Marshal([]any{nil, nil, handover})
}

func sha256CBORArray(arr []string) ([]byte, error) {
	b, err := cbor.Marshal(arr)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// SignDeviceAuth produces the `deviceSigned` CBOR map for an mdoc Document:
//
//	DeviceSigned = {
//	    "nameSpaces": DeviceNameSpacesBytes,   ; #6.24(bstr .cbor {}) — no device attrs
//	    "deviceAuth": {"deviceSignature": COSE_Sign1 (detached payload)}
//	}
//
// The signature is computed over DeviceAuthenticationBytes =
// #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]).
// The COSE_Sign1 payload field is nil (detached).
func SignDeviceAuth(sessionTranscriptCBOR []byte, docType string, deviceKey *ecdsa.PrivateKey) ([]byte, error) {
	if deviceKey == nil {
		return nil, errors.New("mdoc: device key is nil")
	}

	// Empty DeviceNameSpaces, tag-24-wrapped.
	emptyNSBytes, _ := cbor.Marshal(map[string]any{}) // 0xa0
	deviceNameSpacesBytes, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: emptyNSBytes})
	if err != nil {
		return nil, fmt.Errorf("wrap DeviceNameSpaces: %w", err)
	}

	// SessionTranscript is already serialised CBOR — embed unchanged.
	deviceAuthentication := []any{
		"DeviceAuthentication",
		cbor.RawMessage(sessionTranscriptCBOR),
		docType,
		cbor.RawMessage(deviceNameSpacesBytes),
	}
	daBytes, err := cbor.Marshal(deviceAuthentication)
	if err != nil {
		return nil, fmt.Errorf("encode DeviceAuthentication: %w", err)
	}
	deviceAuthenticationBytes, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: daBytes})
	if err != nil {
		return nil, fmt.Errorf("wrap DeviceAuthentication: %w", err)
	}

	// COSE_Sign1 Sig_structure for ES256 with detached payload
	// (RFC 9052 §4.4): ["Signature1", protected, bstr(""), DeviceAuthenticationBytes].
	protectedHeader, err := cbor.Marshal(map[int]int{1: -7})
	if err != nil {
		return nil, err
	}
	sigStruct, err := cbor.Marshal([]any{
		"Signature1",
		protectedHeader,
		[]byte{},
		deviceAuthenticationBytes,
	})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(sigStruct)
	r, s, err := ecdsa.Sign(rand.Reader, deviceKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign: %w", err)
	}
	rawSig := encodeES256Signature(r, s)

	// COSE_Sign1 array with detached payload (3rd element is nil bytes).
	coseSign1 := []any{
		protectedHeader,    // protected bstr
		map[int]any{},      // empty unprotected header
		nil,                // detached payload
		rawSig,             // signature bstr
	}
	coseSign1Bytes, err := cbor.Marshal(coseSign1)
	if err != nil {
		return nil, fmt.Errorf("encode COSE_Sign1: %w", err)
	}

	deviceSigned := map[string]any{
		"nameSpaces": cbor.RawMessage(deviceNameSpacesBytes),
		"deviceAuth": map[string]any{
			"deviceSignature": cbor.RawMessage(coseSign1Bytes),
		},
	}
	return cbor.Marshal(deviceSigned)
}

// VerifyDeviceAuth re-computes Sig_structure and checks the deviceSignature
// against a public key. Useful in tests and later in a verifier.
//
// Returns nil on success.
func VerifyDeviceAuth(deviceSignedCBOR, sessionTranscriptCBOR []byte, docType string, pub *ecdsa.PublicKey) error {
	var m map[string]cbor.RawMessage
	if err := cbor.Unmarshal(deviceSignedCBOR, &m); err != nil {
		return fmt.Errorf("decode DeviceSigned: %w", err)
	}

	deviceAuthRaw, ok := m["deviceAuth"]
	if !ok {
		return errors.New("DeviceSigned has no deviceAuth")
	}
	var deviceAuth map[string]cbor.RawMessage
	if err := cbor.Unmarshal(deviceAuthRaw, &deviceAuth); err != nil {
		return fmt.Errorf("decode deviceAuth: %w", err)
	}
	sigRaw, ok := deviceAuth["deviceSignature"]
	if !ok {
		return errors.New("deviceAuth has no deviceSignature")
	}

	// COSE_Sign1 array: [protected, unprotected, payload, signature].
	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(sigRaw, &coseSign1); err != nil {
		return fmt.Errorf("decode COSE_Sign1 array: %w", err)
	}
	if len(coseSign1) != 4 {
		return fmt.Errorf("COSE_Sign1 has %d elements, want 4", len(coseSign1))
	}
	var protectedHeader, signature []byte
	if err := cbor.Unmarshal(coseSign1[0], &protectedHeader); err != nil {
		return fmt.Errorf("decode protected header: %w", err)
	}
	if err := cbor.Unmarshal(coseSign1[3], &signature); err != nil {
		return fmt.Errorf("decode signature bstr: %w", err)
	}

	// DeviceNameSpaces comes from DeviceSigned.nameSpaces — preserve the
	// exact bytes the signer used.
	deviceNameSpacesBytes, ok := m["nameSpaces"]
	if !ok {
		return errors.New("DeviceSigned has no nameSpaces")
	}

	deviceAuthentication := []any{
		"DeviceAuthentication",
		cbor.RawMessage(sessionTranscriptCBOR),
		docType,
		cbor.RawMessage(deviceNameSpacesBytes),
	}
	daBytes, err := cbor.Marshal(deviceAuthentication)
	if err != nil {
		return err
	}
	deviceAuthenticationBytes, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: daBytes})
	if err != nil {
		return err
	}

	sigStruct, err := cbor.Marshal([]any{
		"Signature1",
		protectedHeader,
		[]byte{},
		deviceAuthenticationBytes,
	})
	if err != nil {
		return err
	}
	digest := sha256.Sum256(sigStruct)

	if len(signature) != 64 {
		return fmt.Errorf("ES256 signature length = %d, want 64", len(signature))
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("mdoc: DeviceAuth signature did not verify")
	}
	return nil
}

// encodeES256Signature converts the (r, s) pair from ecdsa.Sign into the
// fixed-width 64-byte r‖s encoding COSE uses for ES256.
func encodeES256Signature(r, s *big.Int) []byte {
	const coordLen = 32
	out := make([]byte, 2*coordLen)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[coordLen-len(rb):coordLen], rb)
	copy(out[2*coordLen-len(sb):], sb)
	return out
}
