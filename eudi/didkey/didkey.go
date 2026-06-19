package didkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
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

func Resolve(didKey string) (any, error) {
	return did.ResolvePublicKeyFromMultibase(strings.TrimPrefix(didKey, Prefix))
}
