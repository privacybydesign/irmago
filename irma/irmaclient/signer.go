package irmaclient

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	gobig "math/big"
	"strings"

	"github.com/go-errors/errors"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/internal/jose"
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

// SignerCreateJWT signs claims into a compact JWS using the given Signer.
//
// The JWS is assembled here instead of by jws.Sign, because a Signer holds a private key that
// this process never gets to see: it may live in the device keystore, and only signs the bytes
// it is handed. So this function produces those bytes, the JWS signing input, and appends the
// signature the Signer returns.
func SignerCreateJWT(signer Signer, keyname string, claims any) (string, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.AlgorithmKey, jwa.ES256()); err != nil {
		return "", errors.WrapPrefix(err, "failed to set JWT alg header", 0)
	}
	if err := headers.Set(jws.TypeKey, jose.TypeHeader); err != nil {
		return "", errors.WrapPrefix(err, "failed to set JWT typ header", 0)
	}
	headerJson, err := json.Marshal(headers)
	if err != nil {
		return "", errors.WrapPrefix(err, "failed to marshal JWT header", 0)
	}
	claimsJson, err := json.Marshal(claims)
	if err != nil {
		return "", errors.WrapPrefix(err, "failed to marshal JWT claims", 0)
	}

	unsigned := strings.Join([]string{
		base64.RawURLEncoding.EncodeToString(headerJson),
		base64.RawURLEncoding.EncodeToString(claimsJson),
	}, ".")

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
