package eudi_sdjwt_dcql

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/storage"
)

// eudiKeyBindingStorage implements sdjwtvc.KeyBindingStorage by reading holder
// binding private keys from the eudi SQLite storage.
type eudiKeyBindingStorage struct {
	keyStore storage.HolderBindingKeyStore
}

var _ sdjwtvc.KeyBindingStorage = (*eudiKeyBindingStorage)(nil)

func (s *eudiKeyBindingStorage) GetAndRemovePrivateKey(pubKey jwk.Key) (*ecdsa.PrivateKey, error) {
	// Try lookup by DID URL first (if kid is set on the key, e.g. from did:jwk cnf resolution)
	kid, hasKid := pubKey.KeyID()
	if hasKid && kid != "" {
		storedKey, err := s.keyStore.GetByDidUrl(kid)
		if err == nil {
			return decodePrivateKey(storedKey.PrivateKey)
		}
		// Strip fragment and try the base DID
		if idx := len(kid) - 1; idx > 0 {
			if baseDid := stripFragment(kid); baseDid != kid {
				storedKey, err = s.keyStore.GetByDidUrl(baseDid)
				if err == nil {
					return decodePrivateKey(storedKey.PrivateKey)
				}
			}
		}
	}

	// Fall back to thumbprint lookup
	thumbprintBytes, err := pubKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to compute thumbprint: %v", err)
	}
	thumbprint := hex.EncodeToString(thumbprintBytes)

	storedKey, err := s.keyStore.GetByThumbprint(thumbprint)
	if err != nil {
		return nil, fmt.Errorf("failed to find holder binding key for thumbprint %s or kid %s: %v", thumbprint, kid, err)
	}

	return decodePrivateKey(storedKey.PrivateKey)
}

func decodePrivateKey(pkcs8Bytes []byte) (*ecdsa.PrivateKey, error) {
	privKeyAny, err := x509.ParsePKCS8PrivateKey(pkcs8Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %v", err)
	}
	ecdsaKey, ok := privKeyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("stored key is not an ECDSA private key")
	}
	return ecdsaKey, nil
}

func stripFragment(didUrl string) string {
	if idx := strings.Index(didUrl, "#"); idx != -1 {
		return didUrl[:idx]
	}
	return didUrl
}

// StorePrivateKeys is not used by the DCQL handler (keys are created during OID4VCI issuance).
func (s *eudiKeyBindingStorage) StorePrivateKeys(keys []*ecdsa.PrivateKey) error {
	return fmt.Errorf("eudiKeyBindingStorage does not support storing keys directly; use the OID4VCI issuance flow")
}

// RemovePrivateKeys is not used by the DCQL handler.
func (s *eudiKeyBindingStorage) RemovePrivateKeys(pubKeys []jwk.Key) error {
	return nil
}

// RemoveAllPrivateKeys is not used by the DCQL handler.
func (s *eudiKeyBindingStorage) RemoveAllPrivateKeys() error {
	return nil
}
