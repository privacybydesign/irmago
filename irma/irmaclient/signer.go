package irmaclient

import (
	"encoding/asn1"
	"encoding/base64"
	gobig "math/big"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type Signer interface {
	// PublicKey fetches the public key.
	PublicKey(keyname string) ([]byte, error)

	// Sign the specified message using the private key.
	Sign(keyname string, msg []byte) ([]byte, error)
}

// signatureJwtEncoding is a helper function converting an ASN.1 encoded signature as returned by Sign to the
// encoding used for JWTs (in which the bytes of r and s are concatenated after each other in one
// byte slice).
func signatureJwtEncoding(signature []byte) ([]byte, error) {
	ints := make([]*gobig.Int, 2)
	_, err := asn1.Unmarshal(signature, &ints)
	if err != nil {
		return nil, err
	}

	keyBytes := 256 / 8
	out := make([]byte, 2*keyBytes)
	ints[0].FillBytes(out[0:keyBytes])
	ints[1].FillBytes(out[keyBytes:])

	return out, nil
}

func SignerCreateJWT(signer Signer, keyname string, claims jwt.Claims) (string, error) {
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SigningString()
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(keyname, []byte(unsigned))
	if err != nil {
		return "", err
	}

	// JWTs use a different encoding for ECDSA signatures than our Signer does, so convert
	sig, err = signatureJwtEncoding(sig)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{unsigned, base64.RawURLEncoding.EncodeToString(sig)}, "."), nil
}
