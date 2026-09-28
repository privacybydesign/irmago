// Package holdersigning is how the OpenID4VC protocols sign with holder keys
// without knowing what holds them. A credential format resolves the key a
// presentation must be signed with to a Key, and hands the exact bytes to sign
// to a Signer, all of one presentation in one call. Whether the key is a
// software key signed with in process or a key behind something that first
// has to be unlocked is the Signer's business, not the protocol's.
package holdersigning

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// Key is a holder key to sign with: either a software key, or a reference to
// a key held elsewhere that only a Signer knows how to reach.
type Key struct {
	software *ecdsa.PrivateKey
	ref      string
}

// Software returns the Key for a private key in this process.
func Software(key *ecdsa.PrivateKey) Key {
	return Key{software: key}
}

// External returns the Key for a key held outside this process, named by the
// reference its holder gave it.
func External(ref string) Key {
	return Key{ref: ref}
}

// SoftwareKey returns the private key of a software Key, or nil.
func (k Key) SoftwareKey() *ecdsa.PrivateKey {
	return k.software
}

// ExternalRef returns the reference of an external Key, or "".
func (k Key) ExternalRef() string {
	return k.ref
}

// JwsAlgorithm is the JWS alg a signature by the key carries: the one its
// curve pairs with for a software key, ES256 for an external key, which is
// the only algorithm external key holders sign with.
func (k Key) JwsAlgorithm() (string, error) {
	if k.software == nil {
		return "ES256", nil
	}
	switch k.software.Curve {
	case elliptic.P256():
		return "ES256", nil
	case elliptic.P384():
		return "ES384", nil
	case elliptic.P521():
		return "ES512", nil
	}
	return "", fmt.Errorf("holdersigning: unsupported curve %s", k.software.Curve.Params().Name)
}

// Request is one signature to make.
type Request struct {
	Key Key
	// Input is exactly the bytes to sign: a JWS signing input, a COSE
	// Sig_structure. The signer hashes it with the hash its key's curve pairs
	// with (SHA-256 for P-256).
	Input []byte
}

// Signer makes the signatures of one presentation. Each is the raw r‖s form
// JWS and COSE carry, in request order.
type Signer interface {
	Sign(ctx context.Context, reqs []Request) ([][]byte, error)
}

// ErrExternalKey is returned by SignSoftware for a key it cannot sign with.
var ErrExternalKey = errors.New("holdersigning: key is not a software key")

// SignSoftware signs input with a software key.
func SignSoftware(key Key, input []byte) ([]byte, error) {
	if key.software == nil {
		return nil, ErrExternalKey
	}
	h, err := hashFor(key.software.Curve)
	if err != nil {
		return nil, err
	}
	h.Write(input)
	r, s, err := ecdsa.Sign(rand.Reader, key.software, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	size := (key.software.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return sig, nil
}

// hashFor is the hash JWS (RFC 7518 §3.4) and COSE (RFC 9053 §2.1) pair with
// an ECDSA curve.
func hashFor(curve elliptic.Curve) (hash.Hash, error) {
	switch curve {
	case elliptic.P256():
		return sha256.New(), nil
	case elliptic.P384():
		return sha512.New384(), nil
	case elliptic.P521():
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("holdersigning: unsupported curve %s", curve.Params().Name)
}
