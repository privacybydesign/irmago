// Package didkey implements the did:key DID method
// (https://w3c-ccg.github.io/did-key-spec/), which encodes a public key directly in
// the DID, so no network resolution is needed to obtain it.
package didkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/privacybydesign/irmago/eudi/did"
)

const Prefix = "did:key:"

// Create encodes a public key as a did:key DID. The method-specific identifier is
// always base58-btc encoded, which is what the spec's creation algorithm prescribes
// (https://w3c-ccg.github.io/did-key-spec/#format).
//
// The returned DID carries no verification method fragment. The spec references the
// key inside the DID document as `did:key:z...#z...`; Resolve accepts either form.
func Create[T ecdsa.PublicKey | ed25519.PublicKey](publicKey T) (string, error) {
	multibase, err := did.CreateMultibaseFromPublicKey(publicKey, did.Base58Encoder{})
	if err != nil {
		return "", err
	}
	return Prefix + multibase, nil
}

// Resolve returns the public key encoded in a did:key DID. The DID may include the
// verification method fragment (`did:key:z...#z...`), which is how the spec
// references the key inside the DID document, so DIDs produced by other
// implementations resolve as well as the fragmentless form Create emits.
func Resolve(didKey string) (any, error) {
	multibase, err := parseMultibaseValue(didKey)
	if err != nil {
		return nil, err
	}
	return did.ResolvePublicKeyFromMultibase(multibase)
}

// parseMultibaseValue validates a did:key DID and returns its multibase value,
// applying the identifier checks of the spec's creation algorithm
// (https://w3c-ccg.github.io/did-key-spec/#create).
func parseMultibaseValue(didKey string) (string, error) {
	if !strings.HasPrefix(didKey, Prefix) {
		return "", fmt.Errorf("not a did:key DID: %s", didKey)
	}

	multibase, fragment, hasFragment := strings.Cut(strings.TrimPrefix(didKey, Prefix), "#")

	// The spec requires the multibase value to begin with 'z': base58-btc is the only
	// encoding its creation algorithm defines for the method-specific identifier.
	if !strings.HasPrefix(multibase, string(did.MultibaseHeader_Base58BTC)) {
		return "", fmt.Errorf("did:key multibase value must be base58-btc encoded: %s", didKey)
	}

	// For the key the DID itself encodes, the verification method id is the DID plus a
	// fragment repeating the multibase value, so a fragment naming a different value
	// means the DID URL and the key it resolves to disagree. (Ed25519 DID documents
	// also carry a derived X25519 keyAgreement method whose fragment does differ; that
	// key type is unsupported here, so rejecting it is correct either way.)
	if hasFragment && fragment != multibase {
		return "", fmt.Errorf("did:key fragment does not match its multibase value: %s", didKey)
	}

	return multibase, nil
}
