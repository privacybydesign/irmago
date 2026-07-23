package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"

	"github.com/mr-tron/base58/base58"
)

type MultibaseHeader byte

const (
	MultibaseHeader_Base58BTC      MultibaseHeader = 'z'
	MultibaseHeader_Base64UrlNoPad MultibaseHeader = 'u'

	multicodecHeaderEd25519 = "\xed\x01"
	multicodecHeaderP256    = "\x80\x24"
	multicodecHeaderP384    = "\x81\x24"
)

type Encoder interface {
	Encode(data []byte) string
}

type Base58Encoder struct{}
type Base64UrlNoPadEncoder struct{}

func (e Base58Encoder) Encode(data []byte) string {
	encoded := base58.Encode(data)
	return string(MultibaseHeader_Base58BTC) + encoded
}

func (e Base64UrlNoPadEncoder) Encode(data []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return string(MultibaseHeader_Base64UrlNoPad) + encoded
}

func createMultibaseVerificationMethod[T ecdsa.PublicKey | ed25519.PublicKey](publicKey T, encoder Encoder) (*VerificationMethod, error) {
	multibase, err := CreateMultibaseFromPublicKey(publicKey, encoder)
	if err != nil {
		return nil, err
	}

	return &VerificationMethod{
		Type:               VerificationMethodType_Multikey,
		PublicKeyMultibase: &multibase,
	}, nil
}

func CreateMultibaseFromPublicKey[T ecdsa.PublicKey | ed25519.PublicKey](publicKey T, encoder Encoder) (string, error) {
	var publicKeyBytes []byte
	var err error

	switch t := any(publicKey).(type) {
	case ecdsa.PublicKey:
		publicKeyBytes, err = multibaseBytesFromEcsdaPublicKey(t)
	case ed25519.PublicKey:
		publicKeyBytes = multibaseFromEd25519PublicKey(t)
	default:
		return "", fmt.Errorf("unsupported public key type: %T", publicKey)
	}

	if err != nil {
		return "", err
	}

	return encoder.Encode(publicKeyBytes), nil
}

func multibaseBytesFromEcsdaPublicKey(publicKey ecdsa.PublicKey) ([]byte, error) {
	c := publicKey.Params().Name

	b := []byte{}

	switch c {
	case "P-256":
		b = append(b, multicodecHeaderP256...)
	case "P-384":
		b = append(b, multicodecHeaderP384...)
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", c)
	}

	return append(b, elliptic.MarshalCompressed(publicKey.Curve, publicKey.X, publicKey.Y)...), nil
}

func multibaseFromEd25519PublicKey(publicKey ed25519.PublicKey) []byte {
	b := []byte{}
	b = append(b, multicodecHeaderEd25519...)
	return append(b, publicKey...)
}

func ResolvePublicKeyFromMultibase(multibase string) (any, error) {
	if len(multibase) == 0 {
		return nil, fmt.Errorf("multibase string is empty")
	}

	header := MultibaseHeader(multibase[0])
	encodedData := multibase[1:]

	var decodedData []byte
	var err error

	switch header {
	case MultibaseHeader_Base58BTC:
		decodedData, err = base58.Decode(encodedData)
	case MultibaseHeader_Base64UrlNoPad:
		decodedData, err = base64.RawURLEncoding.DecodeString(encodedData)
	default:
		return nil, fmt.Errorf("unsupported multibase header: %c", header)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decode multibase data: %v", err)
	}

	return publicKeyFromMultibaseBytes(decodedData)
}

func publicKeyFromMultibaseBytes(data []byte) (any, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("multibase data is too short to contain a valid header")
	}

	header := data[:2]
	keyData := data[2:]

	switch string(header) {
	case multicodecHeaderEd25519: // Ed25519 multicodec header
		if len(keyData) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key size: expected %d bytes, got %d bytes", ed25519.PublicKeySize, len(keyData))
		}
		return ed25519.PublicKey(keyData), nil
	case multicodecHeaderP256: // P-256 multicodec header
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), keyData)
		if x == nil || y == nil {
			return nil, fmt.Errorf("invalid P-256 public key data")
		}
		return ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case multicodecHeaderP384: // P-384 multicodec header
		x, y := elliptic.UnmarshalCompressed(elliptic.P384(), keyData)
		if x == nil || y == nil {
			return nil, fmt.Errorf("invalid P-384 public key data")
		}
		return ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported multicodec header: %x", header)
	}
}
