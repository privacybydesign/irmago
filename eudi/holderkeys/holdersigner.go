package holderkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// HolderSigner is the source of SD-JWT VC holder binding keys and holder-key
// signatures. It is the seam that lets the holder key live outside the irmago
// process — e.g. in a WSCA (Wallet Secure Cryptographic Application) backed by
// an HSM and the device possession key. Implementations never expose private
// key material.
//
// The default implementation (SoftwareHolderSigner) keeps ECDSA keys in memory
// and reproduces today's behavior. A WSCA-backed implementation lives outside
// irmago (in the wallet-provider module) and plugs in via eudi/wallet.Config.
type HolderSigner interface {
	// GenerateKeys creates num P-256 holder keys and returns, for each, a stable
	// opaque reference plus its public key.
	GenerateKeys(num uint) (refs []string, pubs []*ecdsa.PublicKey, err error)

	// SignES256 signs the JWS signing input (the ASCII "base64url(header).base64url(payload)")
	// with the referenced key and returns the raw 64-byte r||s ES256 signature
	// ready to be base64url-encoded as the JWS signature.
	SignES256(ref string, signingInput []byte) (sig []byte, err error)

	// Reference resolves the reference for a previously generated public key.
	// Used at presentation time, where only the credential's cnf public key is
	// known.
	Reference(pub jwk.Key) (ref string, err error)

	// Remove deletes the referenced keys.
	Remove(refs []string) error
}

// derToRawES256 converts an ASN.1 DER (r,s) ECDSA signature (as produced by
// standard signers, including the WSCA/HSM) into the raw fixed-width r||s form
// required by JWS ES256: r and s each left-padded to 32 bytes (P-256).
func derToRawES256(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("holderkeys: failed to parse DER ECDSA signature: %w", err)
	}
	const size = 32 // P-256 coordinate size
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

// ecdsaJWKThumbprint returns the RFC 7638 SHA-256 JWK thumbprint of a public key,
// used as the stable map key from a credential's cnf public key to a signer
// reference.
func ecdsaJWKThumbprint(pub *ecdsa.PublicKey) (string, error) {
	k, err := jwk.Import(pub)
	if err != nil {
		return "", err
	}
	return jwkThumbprint(k)
}

func jwkThumbprint(k jwk.Key) (string, error) {
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", tp), nil
}

// SoftwareHolderSigner keeps ECDSA P-256 holder keys in memory. It reproduces
// the wallet's default (non-WSCA) behavior and is used by tests and as the
// fallback when no external signer is configured.
type SoftwareHolderSigner struct {
	mu   sync.Mutex
	keys map[string]*ecdsa.PrivateKey // thumbprint -> key
}

// NewSoftwareHolderSigner returns an in-memory HolderSigner.
func NewSoftwareHolderSigner() *SoftwareHolderSigner {
	return &SoftwareHolderSigner{keys: map[string]*ecdsa.PrivateKey{}}
}

func (s *SoftwareHolderSigner) GenerateKeys(num uint) ([]string, []*ecdsa.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := make([]string, 0, num)
	pubs := make([]*ecdsa.PublicKey, 0, num)
	for i := uint(0); i < num; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("holderkeys: failed to generate holder key: %w", err)
		}
		ref, err := ecdsaJWKThumbprint(&priv.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		s.keys[ref] = priv
		refs = append(refs, ref)
		pubs = append(pubs, &priv.PublicKey)
	}
	return refs, pubs, nil
}

func (s *SoftwareHolderSigner) SignES256(ref string, signingInput []byte) ([]byte, error) {
	s.mu.Lock()
	priv, ok := s.keys[ref]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("holderkeys: no holder key for reference %q", ref)
	}
	digest := sha256.Sum256(signingInput)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("holderkeys: failed to sign: %w", err)
	}
	// Convert to raw r||s so software and WSCA (DER) paths are identical downstream.
	return derToRawES256(der)
}

func (s *SoftwareHolderSigner) Reference(pub jwk.Key) (string, error) {
	return jwkThumbprint(pub)
}

func (s *SoftwareHolderSigner) Remove(refs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ref := range refs {
		delete(s.keys, ref)
	}
	return nil
}

var _ HolderSigner = (*SoftwareHolderSigner)(nil)
