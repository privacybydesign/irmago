package didkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/privacybydesign/irmago/eudi/did"
)

const Prefix = "did:key:"

func Create[T ecdsa.PublicKey | ed25519.PublicKey](publicKey T) (string, error) {
	multibase, err := did.CreateMultibaseFromPublicKey(publicKey, did.Base58Encoder{})
	if err != nil {
		return "", err
	}
	return Prefix + multibase, nil
}

// Resolve parses a did:key DID string and returns the embedded public key.
// The DID string may include a fragment (e.g., "did:key:z6Mk...#z6Mk...") which is stripped.
func Resolve(didKey string) (any, error) {
	// Strip fragment
	if idx := strings.Index(didKey, "#"); idx != -1 {
		didKey = didKey[:idx]
	}

	if !strings.HasPrefix(didKey, Prefix) {
		return nil, fmt.Errorf("invalid did:key: %s", didKey)
	}

	return did.ResolvePublicKeyFromMultibase(strings.TrimPrefix(didKey, Prefix))
}
