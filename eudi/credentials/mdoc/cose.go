// This file contains the COSE primitives used by mdoc: COSE_Key conversion
// between the EC2/P-256 wire form and Go's crypto types and JWKs, and thin
// wrappers around veraison/go-cose for producing and verifying the untagged
// COSE_Sign1 objects that ISO/IEC 18013-5 uses for issuerAuth and
// deviceSignature.
package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/v3/jwk"
	cose "github.com/veraison/go-cose"
)

// AlgorithmES256 is the COSE algorithm identifier for ECDSA w/ SHA-256, the
// only signing algorithm mandated by the ISO/IEC 18013-5 mdoc profile.
const AlgorithmES256 = cose.AlgorithmES256

// COSE_Key labels and values for EC2 keys (RFC 9052 §7, IANA COSE registries).
const (
	coseKeyLabelKty = 1  // key type
	coseKeyLabelCrv = -1 // EC curve
	coseKeyLabelX   = -2 // x coordinate
	coseKeyLabelY   = -3 // y coordinate
	coseKeyLabelD   = -4 // private key

	coseKeyTypeEC2 = 2 // EC2 key type
	coseCurveP256  = 1 // NIST P-256 / secp256r1
)

// p256CoordLen is the fixed length of a P-256 coordinate (and private scalar).
const p256CoordLen = 32

// coseEC2Key is the CBOR shape of an EC2 COSE_Key as used by mdoc. Only the
// labels required for P-256 are modelled; the private scalar D is optional.
type coseEC2Key struct {
	Kty int    `cbor:"1,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
	D   []byte `cbor:"-4,keyasint,omitempty"`
}

// padCoord left-pads a big-endian coordinate to the fixed P-256 length. Go's
// big.Int.Bytes() trims leading zero octets which RFC 9052 requires to be
// preserved, so we restore them here.
func padCoord(b []byte) []byte {
	if len(b) >= p256CoordLen {
		return b
	}
	out := make([]byte, p256CoordLen)
	copy(out[p256CoordLen-len(b):], b)
	return out
}

// ECDSAPublicKeyToCOSEKey encodes a P-256 public key as a COSE_Key CBOR map
// {1: 2, -1: 1, -2: x, -3: y}.
func ECDSAPublicKeyToCOSEKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("mdoc: nil public key")
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("mdoc: unsupported curve %v, only P-256 is supported", pub.Curve)
	}
	return encMode.Marshal(coseEC2Key{
		Kty: coseKeyTypeEC2,
		Crv: coseCurveP256,
		X:   padCoord(pub.X.Bytes()),
		Y:   padCoord(pub.Y.Bytes()),
	})
}

// ECDSAPrivateKeyToCOSEKey encodes a P-256 private key as a COSE_Key CBOR map,
// including the private scalar at label -4.
func ECDSAPrivateKeyToCOSEKey(priv *ecdsa.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("mdoc: nil private key")
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("mdoc: unsupported curve %v, only P-256 is supported", priv.Curve)
	}
	return encMode.Marshal(coseEC2Key{
		Kty: coseKeyTypeEC2,
		Crv: coseCurveP256,
		X:   padCoord(priv.X.Bytes()),
		Y:   padCoord(priv.Y.Bytes()),
		D:   padCoord(priv.D.Bytes()),
	})
}

// COSEKeyToECDSAPublicKey decodes an EC2/P-256 COSE_Key into an ecdsa.PublicKey.
func COSEKeyToECDSAPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	var k coseEC2Key
	if err := decMode.Unmarshal(data, &k); err != nil {
		return nil, fmt.Errorf("mdoc: invalid COSE_Key: %w", err)
	}
	if k.Kty != coseKeyTypeEC2 {
		return nil, fmt.Errorf("mdoc: unsupported COSE_Key type %d, expected EC2", k.Kty)
	}
	if k.Crv != coseCurveP256 {
		return nil, fmt.Errorf("mdoc: unsupported COSE_Key curve %d, expected P-256", k.Crv)
	}
	if len(k.X) == 0 || len(k.Y) == 0 {
		return nil, fmt.Errorf("mdoc: COSE_Key is missing x or y coordinate")
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(k.X),
		Y:     new(big.Int).SetBytes(k.Y),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("mdoc: COSE_Key point is not on the P-256 curve")
	}
	return pub, nil
}

// COSEKeyToECDSAPrivateKey decodes an EC2/P-256 COSE_Key (including label -4)
// into an ecdsa.PrivateKey.
func COSEKeyToECDSAPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	var k coseEC2Key
	if err := decMode.Unmarshal(data, &k); err != nil {
		return nil, fmt.Errorf("mdoc: invalid COSE_Key: %w", err)
	}
	if k.Kty != coseKeyTypeEC2 || k.Crv != coseCurveP256 {
		return nil, fmt.Errorf("mdoc: unsupported COSE_Key (kty=%d crv=%d)", k.Kty, k.Crv)
	}
	if len(k.D) == 0 {
		return nil, fmt.Errorf("mdoc: COSE_Key has no private scalar")
	}
	pub, err := COSEKeyToECDSAPublicKey(data)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(k.D),
	}, nil
}

// COSEKeyToJWK converts an EC2/P-256 COSE_Key into a jwk.Key.
func COSEKeyToJWK(data []byte) (jwk.Key, error) {
	pub, err := COSEKeyToECDSAPublicKey(data)
	if err != nil {
		return nil, err
	}
	return jwk.Import(pub)
}

// JWKToCOSEKey converts an EC P-256 public jwk.Key into a COSE_Key CBOR map.
func JWKToCOSEKey(key jwk.Key) ([]byte, error) {
	var pub ecdsa.PublicKey
	if err := jwk.Export(key, &pub); err != nil {
		return nil, fmt.Errorf("mdoc: cannot export JWK to ECDSA public key: %w", err)
	}
	return ECDSAPublicKeyToCOSEKey(&pub)
}

// Sign1 produces an untagged COSE_Sign1 over payload, signed with key. The
// signing algorithm is placed in the protected header. If certChain is
// non-empty its DER certificates are added as the x5chain (label 33)
// unprotected header — a single bstr for one certificate, an array otherwise,
// as used by mdoc issuerAuth.
func Sign1(key *ecdsa.PrivateKey, alg cose.Algorithm, payload []byte, certChain [][]byte) ([]byte, error) {
	signer, err := cose.NewSigner(alg, key)
	if err != nil {
		return nil, fmt.Errorf("mdoc: cannot create COSE signer: %w", err)
	}
	headers := cose.Headers{
		Protected:   cose.ProtectedHeader{cose.HeaderLabelAlgorithm: alg},
		Unprotected: cose.UnprotectedHeader{},
	}
	if v := x5chainHeaderValue(certChain); v != nil {
		headers.Unprotected[cose.HeaderLabelX5Chain] = v
	}
	return cose.Sign1Untagged(rand.Reader, signer, headers, payload, nil)
}

// Verify1 verifies an untagged COSE_Sign1 against pub using alg. The payload
// must be attached (mdoc never uses detached payloads for issuerAuth or
// deviceSignature).
func Verify1(coseSign1 []byte, pub *ecdsa.PublicKey, alg cose.Algorithm) error {
	var msg cose.UntaggedSign1Message
	if err := msg.UnmarshalCBOR(coseSign1); err != nil {
		return fmt.Errorf("mdoc: cannot decode COSE_Sign1: %w", err)
	}
	verifier, err := cose.NewVerifier(alg, pub)
	if err != nil {
		return fmt.Errorf("mdoc: cannot create COSE verifier: %w", err)
	}
	return msg.Verify(nil, verifier)
}

// x5chainHeaderValue builds the value for the x5chain (label 33) header from a
// list of DER-encoded certificates: nil for none, a single bstr for one, an
// array of bstr for several (RFC 9360 §2).
func x5chainHeaderValue(certChain [][]byte) any {
	switch len(certChain) {
	case 0:
		return nil
	case 1:
		return certChain[0]
	default:
		chain := make([]any, len(certChain))
		for i, c := range certChain {
			chain[i] = c
		}
		return chain
	}
}

// X5Chain extracts the certificate chain from the x5chain (label 33) header of
// an untagged COSE_Sign1, parsing each DER certificate. The header may appear
// in either the protected or unprotected bucket.
func X5Chain(coseSign1 []byte) ([]*x509.Certificate, error) {
	var msg cose.UntaggedSign1Message
	if err := msg.UnmarshalCBOR(coseSign1); err != nil {
		return nil, fmt.Errorf("mdoc: cannot decode COSE_Sign1: %w", err)
	}
	raw, ok := msg.Headers.Unprotected[cose.HeaderLabelX5Chain]
	if !ok {
		raw, ok = msg.Headers.Protected[cose.HeaderLabelX5Chain]
	}
	if !ok {
		return nil, fmt.Errorf("mdoc: COSE_Sign1 has no x5chain header")
	}

	var ders [][]byte
	switch v := raw.(type) {
	case []byte:
		ders = [][]byte{v}
	case []any:
		for _, item := range v {
			der, ok := item.([]byte)
			if !ok {
				return nil, fmt.Errorf("mdoc: x5chain entry is not a byte string (got %T)", item)
			}
			ders = append(ders, der)
		}
	default:
		return nil, fmt.Errorf("mdoc: unexpected x5chain header type %T", raw)
	}

	certs := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("mdoc: cannot parse x5chain certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
