package mdoc

import (
	"crypto/ecdsa"
	"crypto/hpke"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// THE org-iso-mdoc ENVELOPE — W3C Digital Credentials API,
// ISO/IEC 18013-7 Annex C
// ============================================================
//
// `org-iso-mdoc` is the protocol identifier a relying party puts in a W3C
// Digital Credentials API request to say "answer me in ISO 18013-5, not
// OpenID4VP". The payload it selects is the ordinary DeviceRequest and
// DeviceResponse this package already speaks; what this file adds is the thin
// envelope either side is wrapped in, and nothing more:
//
//	request data       = {"deviceRequest": base64url, "encryptionInfo": base64url}
//	EncryptionInfo     = ["dcapi", {"nonce": bstr, "recipientPublicKey": COSE_Key}]
//	EncryptedResponse  = ["dcapi", {"enc": bstr, "cipherText": bstr}]
//
// The whole DeviceResponse travels sealed inside cipherText — HPKE, with `enc`
// carrying the encapsulated key as an uncompressed EC point. That is the one
// real departure from proximity, where 9.1.1.5's SKDevice/SKReader do the same
// job and do not transfer here.
//
// # Where these shapes come from
//
// ISO/IEC 18013-7 is not in hand, so neither structure is quoted from it. Both
// were read off a captured Age Verification exchange byte by byte and confirmed
// against Multipaz's reader implementation (VerificationUtil.kt, the
// "org-iso-mdoc" branch), which is the same conformance target zkp.go uses and
// for the same reason. Where the two agreed, that is what is encoded here.
//
// # The re-encoding hazard
//
// The DC API session transcript does not hash this structure. It hashes the
// base64url text of the bytes as they arrived:
//
//	SessionTranscript = [null, null, ["dcapi", SHA-256(cbor([base64url(EncryptionInfo), origin]))]]
//
// So a wallet must carry the received string through to the transcript and must
// never rebuild it from a decoded DCAPIEncryptionInfo. Canonical CBOR makes the
// round trip byte-identical for every sample seen so far, but "so far" is not a
// guarantee: a reader is free to emit a non-canonical map, and re-encoding it
// would move the digest, break deviceAuth, and do so with an error pointing at
// the signature rather than at the encoder. RecipientPublicKey is kept as
// cbor.RawMessage for the same reason — the COSE_Key is passed through verbatim
// rather than decoded and rebuilt.
const dcapiEnvelopeTag = "dcapi"

// dcapiEncMode is the encoder for the structures in this file.
//
// SortCanonical only: there are no time fields here, so none of tdateEncMode's
// concerns apply, but 8.1's canonical ordering does — these bytes get
// base64url'd and hashed into a session transcript, and an encoder whose map
// order drifted between calls would produce a different transcript each time.
var dcapiEncMode, _ = cbor.EncOptions{
	Sort: cbor.SortCanonical,
}.EncMode()

// decodeDCAPIEnvelope unwraps the ["dcapi", {...}] two-element array both
// structures share and returns the still-encoded payload map.
//
// The tag check is not ceremony. An OpenID4VP DC API response is also a CBOR
// blob arriving in a field called "response", and rejecting it here names the
// protocol mismatch instead of surfacing it as a missing map key three frames
// further in.
func decodeDCAPIEnvelope(data []byte, what string) (cbor.RawMessage, error) {
	var envelope []cbor.RawMessage
	if err := Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("decode %s: not a CBOR array: %w", what, err)
	}
	if len(envelope) != 2 {
		return nil, fmt.Errorf("decode %s: want a 2-element array, got %d", what, len(envelope))
	}
	var tag string
	if err := Unmarshal(envelope[0], &tag); err != nil {
		return nil, fmt.Errorf("decode %s: first element is not a text string: %w", what, err)
	}
	if tag != dcapiEnvelopeTag {
		return nil, fmt.Errorf("decode %s: first element is %q, want %q (is this an org-iso-mdoc message?)",
			what, tag, dcapiEnvelopeTag)
	}
	return envelope[1], nil
}

// ============================================================
// EncryptionInfo — the reader's half
// ============================================================

// DCAPIEncryptionInfo is the encryptionInfo field of an org-iso-mdoc request:
// the nonce, and the public key the wallet seals its DeviceResponse to.
//
// RecipientPublicKey stays encoded. See the re-encoding hazard above; use
// RecipientKey to read it.
type DCAPIEncryptionInfo struct {
	Nonce              []byte
	RecipientPublicKey cbor.RawMessage
}

type dcapiEncryptionInfoWire struct {
	Nonce              []byte          `cbor:"nonce"`
	RecipientPublicKey cbor.RawMessage `cbor:"recipientPublicKey"`
}

// NewDCAPIEncryptionInfo builds the structure a reader sends, from the public
// half of the ephemeral key it will decrypt the response with.
func NewDCAPIEncryptionInfo(nonce []byte, recipient *ecdsa.PublicKey) (DCAPIEncryptionInfo, error) {
	if len(nonce) == 0 {
		return DCAPIEncryptionInfo{}, fmt.Errorf("build EncryptionInfo: nonce is empty")
	}
	if recipient == nil {
		return DCAPIEncryptionInfo{}, fmt.Errorf("build EncryptionInfo: recipient key is nil")
	}
	key, err := coseKeyFromECDSA(recipient)
	if err != nil {
		return DCAPIEncryptionInfo{}, fmt.Errorf("build EncryptionInfo: %w", err)
	}
	encoded, err := dcapiEncMode.Marshal(key)
	if err != nil {
		return DCAPIEncryptionInfo{}, fmt.Errorf("build EncryptionInfo: encode recipientPublicKey: %w", err)
	}
	return DCAPIEncryptionInfo{Nonce: nonce, RecipientPublicKey: encoded}, nil
}

// MarshalCBOR encodes the ["dcapi", {...}] envelope.
func (e DCAPIEncryptionInfo) MarshalCBOR() ([]byte, error) {
	if len(e.Nonce) == 0 {
		return nil, fmt.Errorf("encode EncryptionInfo: nonce is empty")
	}
	if len(e.RecipientPublicKey) == 0 {
		return nil, fmt.Errorf("encode EncryptionInfo: recipientPublicKey is empty")
	}
	return dcapiEncMode.Marshal([]any{
		dcapiEnvelopeTag,
		dcapiEncryptionInfoWire{Nonce: e.Nonce, RecipientPublicKey: e.RecipientPublicKey},
	})
}

// UnmarshalCBOR decodes the envelope a reader sent.
func (e *DCAPIEncryptionInfo) UnmarshalCBOR(data []byte) error {
	body, err := decodeDCAPIEnvelope(data, "EncryptionInfo")
	if err != nil {
		return err
	}
	var wire dcapiEncryptionInfoWire
	if err := Unmarshal(body, &wire); err != nil {
		return fmt.Errorf("decode EncryptionInfo: %w", err)
	}
	if len(wire.Nonce) == 0 {
		return fmt.Errorf("decode EncryptionInfo: nonce is absent or empty")
	}
	if len(wire.RecipientPublicKey) == 0 {
		return fmt.Errorf("decode EncryptionInfo: recipientPublicKey is absent")
	}
	e.Nonce = wire.Nonce
	e.RecipientPublicKey = wire.RecipientPublicKey
	return nil
}

// RecipientKey decodes recipientPublicKey into the key HPKE seals to.
//
// It routes through ecdsaPublicKeyFromCOSE rather than cose.Key.PublicKey for
// the reason given there: these coordinates come off the wire and the on-curve
// check stays load-bearing.
func (e DCAPIEncryptionInfo) RecipientKey() (*ecdsa.PublicKey, error) {
	if len(e.RecipientPublicKey) == 0 {
		return nil, fmt.Errorf("EncryptionInfo carries no recipientPublicKey")
	}
	var key cose.Key
	if err := Unmarshal(e.RecipientPublicKey, &key); err != nil {
		return nil, fmt.Errorf("decode recipientPublicKey as COSE_Key: %w", err)
	}
	return ecdsaPublicKeyFromCOSE(&key)
}

// ============================================================
// The sealed response — the wallet's half
// ============================================================

// DCAPIEncryptedResponse is what comes back in the DC API response field: an
// HPKE-sealed DeviceResponse.
//
// Enc is the encapsulated key, an uncompressed EC point (0x04 || X || Y) — 65
// bytes for the P-256 KEM the profile uses. CipherText is the whole
// DeviceResponse; sizes in the hundreds of kilobytes are ordinary once a
// zero-knowledge proof is inside it.
//
// Opening it is deliberately not this type's job. The HPKE info parameter is
// the encoded session transcript, so decryption cannot be done without the
// origin — a value that reaches the wallet from the browser or OS and from no
// field of the request.
type DCAPIEncryptedResponse struct {
	Enc        []byte
	CipherText []byte
}

type dcapiEncryptedResponseWire struct {
	Enc        []byte `cbor:"enc"`
	CipherText []byte `cbor:"cipherText"`
}

// MarshalCBOR encodes the ["dcapi", {...}] envelope.
func (r DCAPIEncryptedResponse) MarshalCBOR() ([]byte, error) {
	if len(r.Enc) == 0 {
		return nil, fmt.Errorf("encode encrypted response: enc is empty")
	}
	if len(r.CipherText) == 0 {
		return nil, fmt.Errorf("encode encrypted response: cipherText is empty")
	}
	return dcapiEncMode.Marshal([]any{
		dcapiEnvelopeTag,
		dcapiEncryptedResponseWire{Enc: r.Enc, CipherText: r.CipherText},
	})
}

// UnmarshalCBOR decodes the envelope a wallet returned.
func (r *DCAPIEncryptedResponse) UnmarshalCBOR(data []byte) error {
	body, err := decodeDCAPIEnvelope(data, "encrypted response")
	if err != nil {
		return err
	}
	var wire dcapiEncryptedResponseWire
	if err := Unmarshal(body, &wire); err != nil {
		return fmt.Errorf("decode encrypted response: %w", err)
	}
	if len(wire.Enc) == 0 {
		return fmt.Errorf("decode encrypted response: enc is absent or empty")
	}
	if len(wire.CipherText) == 0 {
		return fmt.Errorf("decode encrypted response: cipherText is absent or empty")
	}
	r.Enc = wire.Enc
	r.CipherText = wire.CipherText
	return nil
}

// ============================================================
// HPKE — sealing the response
// ============================================================

// The cipher suite the profile fixes: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
// AES-128-GCM.
//
// Pinned rather than negotiated, and not read from anything on the wire. The
// envelope carries no suite identifier — `enc` is a bare EC point and
// `cipherText` a bare byte string — so both parties have to already agree, and
// the only safe way to agree on something untransmitted is to hard-code it. A
// reader using a different suite fails to open the response, which is the
// correct outcome and not something to recover from by trying alternatives.
func dcapiSuite() (hpke.KDF, hpke.AEAD) {
	return hpke.HKDFSHA256(), hpke.AES128GCM()
}

// dcapiHPKEInfo is the HPKE `info` parameter: the encoded SessionTranscript.
//
// This is what ties the encryption to the session. The transcript already binds
// the origin and the EncryptionInfo (see NewDCAPISessionTranscript), so deriving
// the HPKE context from it means a response sealed for one origin cannot be
// opened in another — the same job `external_aad` does for reader
// authentication, achieved here through key schedule rather than through signed
// bytes.
//
// It is the *bare* encoding, not SessionTranscriptBytes. 9.1.5.1's
// `#6.24(bstr .cbor SessionTranscript)` wrapping is what goes inside
// DeviceAuthentication; the HPKE info is the transcript itself. Using the tag-24
// form here would produce a context neither Multipaz nor the reference
// implementation shares, and the symptom would be an AEAD authentication failure
// with nothing to say why.
func dcapiHPKEInfo(transcript SessionTranscript) ([]byte, error) {
	encoded, err := dcapiEncMode.Marshal(transcript)
	if err != nil {
		return nil, fmt.Errorf("encode session transcript for HPKE info: %w", err)
	}
	return encoded, nil
}

// SealDCAPIResponse encrypts an encoded DeviceResponse to the reader's ephemeral
// key, producing the `enc` and `cipherText` an org-iso-mdoc response carries.
//
// recipient is the key from the request's EncryptionInfo — see
// DCAPIEncryptionInfo.RecipientKey. transcript must be the one built from *that
// same* EncryptionInfo and the request's origin: the two are inputs to the same
// exchange, and pairing a transcript with a key from a different request yields
// a response the reader cannot open, reported as a decryption failure rather
// than as the mismatch it is.
//
// aad is empty. The profile puts everything that would otherwise be associated
// data into the transcript, and so into `info`.
func SealDCAPIResponse(deviceResponse []byte, recipient *ecdsa.PublicKey, transcript SessionTranscript) (DCAPIEncryptedResponse, error) {
	if len(deviceResponse) == 0 {
		return DCAPIEncryptedResponse{}, fmt.Errorf("seal response: nothing to seal")
	}
	if recipient == nil {
		return DCAPIEncryptedResponse{}, fmt.Errorf("seal response: recipient key is nil")
	}

	ecdhPub, err := recipient.ECDH()
	if err != nil {
		return DCAPIEncryptedResponse{}, fmt.Errorf(
			"seal response: recipient key is not usable for ECDH: %w", err)
	}
	publicKey, err := hpke.NewDHKEMPublicKey(ecdhPub)
	if err != nil {
		return DCAPIEncryptedResponse{}, fmt.Errorf("seal response: %w", err)
	}

	info, err := dcapiHPKEInfo(transcript)
	if err != nil {
		return DCAPIEncryptedResponse{}, fmt.Errorf("seal response: %w", err)
	}

	kdf, aead := dcapiSuite()
	enc, sender, err := hpke.NewSender(publicKey, kdf, aead, info)
	if err != nil {
		return DCAPIEncryptedResponse{}, fmt.Errorf("seal response: set up HPKE sender: %w", err)
	}
	cipherText, err := sender.Seal(nil, deviceResponse)
	if err != nil {
		return DCAPIEncryptedResponse{}, fmt.Errorf("seal response: %w", err)
	}

	return DCAPIEncryptedResponse{Enc: enc, CipherText: cipherText}, nil
}

// OpenDCAPIResponse is the reader's half: decrypt a sealed DeviceResponse with
// the private half of the key it advertised in EncryptionInfo.
//
// A failure here is not diagnosable beyond "it did not open", and deliberately
// so — AEAD gives no partial information. In practice the cause is one of a
// transcript the two parties disagree on (a different origin, or an
// EncryptionInfo re-encoded rather than passed through), the wrong private key,
// or a tampered response; none of them can be told apart from the ciphertext,
// and guessing in the error message would mislead more often than help.
func OpenDCAPIResponse(response DCAPIEncryptedResponse, recipient *ecdsa.PrivateKey, transcript SessionTranscript) ([]byte, error) {
	if len(response.Enc) == 0 || len(response.CipherText) == 0 {
		return nil, fmt.Errorf("open response: envelope is missing enc or cipherText")
	}
	if recipient == nil {
		return nil, fmt.Errorf("open response: recipient private key is nil")
	}

	ecdhPriv, err := recipient.ECDH()
	if err != nil {
		return nil, fmt.Errorf("open response: recipient key is not usable for ECDH: %w", err)
	}
	privateKey, err := hpke.NewDHKEMPrivateKey(ecdhPriv)
	if err != nil {
		return nil, fmt.Errorf("open response: %w", err)
	}

	info, err := dcapiHPKEInfo(transcript)
	if err != nil {
		return nil, fmt.Errorf("open response: %w", err)
	}

	kdf, aead := dcapiSuite()
	recipientCtx, err := hpke.NewRecipient(response.Enc, privateKey, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("open response: set up HPKE recipient: %w", err)
	}
	plaintext, err := recipientCtx.Open(nil, response.CipherText)
	if err != nil {
		return nil, fmt.Errorf(
			"open response: decryption failed (the session transcript, the recipient key or the ciphertext disagree; AEAD cannot say which): %w", err)
	}
	return plaintext, nil
}
