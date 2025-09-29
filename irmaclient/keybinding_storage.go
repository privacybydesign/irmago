package irmaclient

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"go.etcd.io/bbolt"
)

func NewBboltKeyBindingStorage(db *bbolt.DB, aesKey [32]byte) sdjwtvc.KeyBindingStorage {
	return &BboltKeyBindingStorage{
		db:     db,
		aesKey: aesKey,
	}
}

const kbPrivKeysBucketName = "kbPrivKeys"

type BboltKeyBindingStorage struct {
	// Layout for the kbPrivKeys bucket in this database:
	// - kbPrivKeys: bucket
	// ----- jwk-thumbprint: encrypted privkey
	// ----- jwk-thumbprint: encrypted privkey
	// ----- jwk-thumbprint: encrypted privkey
	// ----- jwk-thumbprint: encrypted privkey
	db     *bbolt.DB
	aesKey [32]byte
}

func (s *BboltKeyBindingStorage) StorePrivateKeys(keys []*ecdsa.PrivateKey) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(kbPrivKeysBucketName))
		if err != nil {
			return err
		}

		for _, privKey := range keys {
			privJwk, err := jwk.Import(privKey)
			if err != nil {
				return fmt.Errorf("failed to convert ecdsa priv key to jwk: %v", err)
			}

			pubJwk, err := privJwk.PublicKey()
			if err != nil {
				return fmt.Errorf("failed to obtain pub key from jwk: %v", err)
			}

			thumbprint, err := pubJwk.Thumbprint(crypto.SHA256)
			if err != nil {
				return fmt.Errorf("failed to create thumbprint of jwk pub key: %v", err)
			}

			privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
			if err != nil {
				return fmt.Errorf("failed to marshal private key: %v", err)
			}

			encryptedPrivKey, err := encrypt(privKeyBytes, s.aesKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt private key: %v", err)
			}

			err = bucket.Put(thumbprint, encryptedPrivKey)

			if err != nil {
				return fmt.Errorf("failed to store private key: %v", err)
			}
		}

		return nil
	})
}

func (s *BboltKeyBindingStorage) GetAndRemovePrivateKey(pubKey jwk.Key) (privKey *ecdsa.PrivateKey, err error) {
	err = s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(kbPrivKeysBucketName))
		if bucket == nil {
			return fmt.Errorf("'%s' bucket does not exist", kbPrivKeysBucketName)
		}

		thumbprint, err := pubKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return fmt.Errorf("failed to create thumbprint of jwk pub key: %v", err)
		}

		keyEncryptedBytes := bucket.Get(thumbprint)
		if keyEncryptedBytes == nil {
			return fmt.Errorf("failed to find key bytes for thumbprint: %s", string(thumbprint))
		}

		keyBytes, err := decrypt(keyEncryptedBytes, s.aesKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt private key: %v", err)
		}

		keyAny, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key from bytes: %v", err)
		}

		ecdsaKey, ok := keyAny.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("failed to cast private key to *ecdsa.PrivateKey")
		}

		privKey = ecdsaKey

		return bucket.Delete(thumbprint)
	})
	return
}

func (s *BboltKeyBindingStorage) RemovePrivateKeys(pubKeys []jwk.Key) error {
	if len(pubKeys) == 0 {
		return nil
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		keysBucket := tx.Bucket([]byte(kbPrivKeysBucketName))
		if keysBucket == nil {
			return fmt.Errorf("failed to delete private keys because the bucket doesn't exist")
		}
		for _, pk := range pubKeys {
			thumbprint, err := pk.Thumbprint(crypto.SHA256)
			if err != nil {
				return fmt.Errorf("failed to create thumbprint: %v", err)
			}
			err = keysBucket.Delete(thumbprint)
			if err != nil {
				return fmt.Errorf("failed to delete private key corresponding to thumbprint %s: %v", string(thumbprint), err)
			}
		}

		return nil
	})
}

func (s *BboltKeyBindingStorage) RemoveAllPrivateKeys() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		// can't delete what doesn't exist yet...
		if tx.Bucket([]byte(kbPrivKeysBucketName)) == nil {
			return nil
		}
		return tx.DeleteBucket([]byte(kbPrivKeysBucketName))
	})
}
