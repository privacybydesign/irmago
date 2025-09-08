package irmaclient

import (
	"encoding/json"
	"go.etcd.io/bbolt"
)

const (
	mfaSecretBucketName = "MFASecrets"
)

type MFASecret struct {
	Issuer      string // e.g "cloudflare
	Secret      string
	Period      int
	UserAccount string
	Algorithm   string
}

func NewBboltMFASecretStorage(db *bbolt.DB, aesKey [32]byte) *BboltMFASecretStorage {
	return &BboltMFASecretStorage{db: db, aesKey: aesKey}
}

type BboltMFASecretStorage struct {
	db     *bbolt.DB
	aesKey [32]byte
}

type MfaSecretStorage interface {
	// StoreMFASecret stores the given MFA secret. If a secret with the same Secret field already exists, it is updated.
	StoreMFASecret(secret MFASecret) error

	GetAllSecrets() ([]MFASecret, error)

	DeleteSecretBySecret(secretStr string) error
}

func (s *BboltMFASecretStorage) StoreMFASecret(secret MFASecret) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(mfaSecretBucketName))
		if err != nil {
			return err
		}

		foundDuplicate := false
		err = b.ForEach(func(k, v []byte) error {
			existingSecret, err := unmarshalAndDecryptSecret(v, s.aesKey)
			if err != nil {
				return err
			}
			if existingSecret.Secret == secret.Secret {
				encryptedSecret, err := marshalAndEncryptSecret(secret, s.aesKey)
				if err != nil {
					return err
				}
				b.Put(k, encryptedSecret)
				foundDuplicate = true
				return nil
			}
			return nil
		})
		if err != nil {
			return err
		}
		if foundDuplicate {
			return nil
		}

		encryptedSecret, err := marshalAndEncryptSecret(secret, s.aesKey)
		if err != nil {
			return err
		}
		id, _ := b.NextSequence()

		return b.Put(itob(id), encryptedSecret)
	})
}

func (s *BboltMFASecretStorage) GetAllSecrets() ([]MFASecret, error) {
	var secrets []MFASecret
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(mfaSecretBucketName))
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			secret, err := unmarshalAndDecryptSecret(v, s.aesKey)
			if err != nil {
				return err
			}

			secrets = append(secrets, secret)

			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

func (s *BboltMFASecretStorage) DeleteSecretBySecret(secretStr string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(mfaSecretBucketName))
		if b == nil {
			return nil
		}

		var keyToDelete []byte
		err := b.ForEach(func(k, v []byte) error {
			secret, err := unmarshalAndDecryptSecret(v, s.aesKey)
			if err != nil {
				return err
			}

			if secret.Secret == secretStr {
				keyToDelete = k
				return nil
			}
			return nil
		})
		if err != nil {
			return err
		}

		if keyToDelete != nil {
			return b.Delete(keyToDelete)
		}
		return nil
	})
}

func unmarshalAndDecryptSecret(data []byte, aesKey [32]byte) (MFASecret, error) {
	var secret MFASecret

	decrypted, err := decrypt(data, aesKey)
	if err != nil {
		return secret, err
	}

	err = json.Unmarshal(decrypted, &secret)
	if err != nil {
		return secret, err
	}

	return secret, nil
}

func marshalAndEncryptSecret(secret MFASecret, aesKey [32]byte) ([]byte, error) {
	marshalled, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}

	return encrypt(marshalled, aesKey)
}
