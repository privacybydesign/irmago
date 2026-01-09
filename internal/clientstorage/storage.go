package clientstorage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/internal/common"

	"go.etcd.io/bbolt"
)

// This file contains the storage struct and its methods,
// and some general filesystem functions.

// Storage provider for a Client
type Storage struct {
	Db *bbolt.DB

	storagePath string
	aesKey      [32]byte
}

type Transaction struct {
	*bbolt.Tx
}

// Filenames
const databaseFile = "db2"

// Bucketnames bbolt
// Note: crypto specific buckets should not clash with eachother!
const (
	UserdataBucket = "userdata"    // Key/value: specified below
	PreferencesKey = "preferences" // Value: Preferences
)

func (s *Storage) path(p string) string {
	return filepath.Join(s.storagePath, p)
}

func NewStorage(storagePath string, aesKey [32]byte) *Storage {
	return &Storage{
		storagePath: storagePath,
		aesKey:      aesKey,
	}
}

// Open initializes the credential storage,
// ensuring that it is in a usable state.
// Setting it up in a properly protected location (e.g., with automatic
// backups to iCloud/Google disabled) is the responsibility of the user.
func (s *Storage) Open() error {
	var err error
	if err = common.AssertPathExists(s.storagePath); err != nil {
		return err
	}
	s.Db, err = bbolt.Open(s.path(databaseFile), 0600, &bbolt.Options{Timeout: 1 * time.Second})
	return err
}

func (s *Storage) Close() error {
	return s.Db.Close()
}

func (s *Storage) BucketExists(name []byte) bool {
	return s.Db.View(func(tx *bbolt.Tx) error {
		if tx.Bucket(name) == nil {
			return bbolt.ErrBucketNotFound
		}
		return nil
	}) == nil
}

func (s *Storage) TxStore(tx *Transaction, bucketName string, key string, value interface{}) error {
	b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
	if err != nil {
		return err
	}
	btsValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	ciphertext, err := encrypt(btsValue, s.aesKey)
	if err != nil {
		return err
	}

	return b.Put([]byte(key), ciphertext)
}

func (s *Storage) TxDelete(tx *Transaction, bucketName string, key string) error {
	b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
	if err != nil {
		return err
	}

	return b.Delete([]byte(key))
}

func (s *Storage) TxLoad(tx *Transaction, bucketName string, key string, dest interface{}) (found bool, err error) {
	b := tx.Bucket([]byte(bucketName))
	if b == nil {
		return false, nil
	}
	bts := b.Get([]byte(key))
	b.Sequence()
	if bts == nil {
		return false, nil
	}

	plaintext, err := decrypt(bts, s.aesKey)
	if err != nil {
		return false, err
	}

	return true, json.Unmarshal(plaintext, dest)
}

func (s *Storage) Load(bucketName string, key string, dest interface{}) (found bool, err error) {
	err = s.Db.View(func(tx *bbolt.Tx) error {
		found, err = s.TxLoad(&Transaction{tx}, bucketName, key, dest)
		return err
	})
	return
}

func (s *Storage) Transaction(f func(*Transaction) error) error {
	return s.Db.Update(func(tx *bbolt.Tx) error {
		return f(&Transaction{tx})
	})
}

func (s *Storage) StorePreferences(prefs clientsettings.Preferences) error {
	return s.Transaction(func(tx *Transaction) error {
		return s.TxStorePreferences(tx, prefs)
	})
}

func (s *Storage) TxStorePreferences(tx *Transaction, prefs clientsettings.Preferences) error {
	return s.TxStore(tx, UserdataBucket, PreferencesKey, prefs)
}

func (s *Storage) LoadPreferences(defaultPreferences clientsettings.Preferences) (clientsettings.Preferences, error) {
	config := defaultPreferences
	_, err := s.Load(UserdataBucket, PreferencesKey, &config)
	return config, err
}

func (s *Storage) TxDeleteUserdata(tx *Transaction) error {
	return tx.DeleteBucket([]byte(UserdataBucket))
}

func (s *Storage) TxDeleteAll(tx *Transaction) error {
	if err := s.TxDeleteUserdata(tx); err != nil && err != bbolt.ErrBucketNotFound {
		return err
	}
	return nil
}

func (s *Storage) DeleteAll() error {
	return s.Transaction(func(tx *Transaction) error {
		return s.TxDeleteAll(tx)
	})
}

func (s *Storage) Decrypt(ciphertext []byte) ([]byte, error) {
	return decrypt(ciphertext, s.aesKey)
}

func (s *Storage) Encrypt(plaintext []byte) ([]byte, error) {
	return encrypt(plaintext, s.aesKey)
}

func decrypt(ciphertext []byte, aesKey [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, ciphertext[:12], ciphertext[12:], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func encrypt(bytes []byte, aesKey [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, bytes, nil), nil
}
