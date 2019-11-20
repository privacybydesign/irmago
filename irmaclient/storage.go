package irmaclient

import (
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/go-errors/errors"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/revocation"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"

	"github.com/go-errors/errors"
	"go.etcd.io/bbolt"
)

// This file contains the storage struct and its methods,
// and some general filesystem functions.

// Storage provider for a Client
type storage struct {
	storagePath   string
	db            *bbolt.DB
	Configuration *irma.Configuration
}

type transaction struct {
	*bbolt.Tx
}

// Filenames
const databaseFile = "db"

// Bucketnames bbolt
const (
	userdataBucket = "userdata"    // Key/value: specified below
	skKey          = "sk"          // Value: *secretKey
	preferencesKey = "preferences" // Value: Preferences
	updatesKey     = "updates"     // Value: []update
	kssKey         = "kss"         // Value: map[irma.SchemeManagerIdentifier]*keyshareServer

	attributesBucket = "attrs" // Key: irma.CredentialIdentifier, value: []*irma.AttributeList
	logsBucket       = "logs"  // Key: (auto-increment index), value: *LogEntry
	signaturesBucket = "sigs"  // Key: credential.attrs.Hash, value: *gabi.CLSignature
)

func (s *storage) path(p string) string {
	return filepath.Join(s.storagePath, p)
}

// EnsureStorageExists initializes the credential storage folder,
// ensuring that it is in a usable state.
// Setting it up in a properly protected location (e.g., with automatic
// backups to iCloud/Google disabled) is the responsibility of the user.
func (s *storage) EnsureStorageExists() error {
	var err error
	if err = fs.AssertPathExists(s.storagePath); err != nil {
		return err
	}
	s.db, err = bbolt.Open(s.path(databaseFile), 0600, &bbolt.Options{Timeout: 1 * time.Second})
	return err
}

func (s *storage) Close() error {
	return s.db.Close()
}

func (s *storage) BucketExists(name []byte) bool {
	return s.db.View(func(tx *bbolt.Tx) error {
		if tx.Bucket(name) == nil {
			return bbolt.ErrBucketNotFound
		}
		return nil
	}) == nil
}

func (s *storage) txStore(tx *transaction, bucketName string, key string, value interface{}) error {
	b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
	if err != nil {
		return err
	}
	btsValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return b.Put([]byte(key), btsValue)
}

func (s *storage) txDelete(tx *transaction, bucketName string, key string) error {
	b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
	if err != nil {
		return err
	}

	return b.Delete([]byte(key))
}

func (s *storage) txLoad(tx *transaction, bucketName string, key string, dest interface{}) (found bool, err error) {
	b := tx.Bucket([]byte(bucketName))
	if b == nil {
		return false, nil
	}
	bts := b.Get([]byte(key))
	b.Sequence()
	if bts == nil {
		return false, nil
	}
	return true, json.Unmarshal(bts, dest)
}

func (s *storage) load(bucketName string, key string, dest interface{}) (found bool, err error) {
	err = s.db.View(func(tx *bbolt.Tx) error {
		found, err = s.txLoad(&transaction{tx}, bucketName, key, dest)
		return err
	})
	return
}

func (s *storage) Transaction(f func(*transaction) error) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return f(&transaction{tx})
	})
}

func (s *storage) TxDeleteSignature(tx *transaction, attrs *irma.AttributeList) error {
	return s.txDelete(tx, signaturesBucket, attrs.Hash())
}

func (s *storage) TxDeleteAllSignatures(tx *transaction) error {
	return tx.DeleteBucket([]byte(signaturesBucket))
}

type clSignatureWitness struct {
	*gabi.CLSignature
	Witness *revocation.Witness
}

func (s *storage) TxStoreSignature(tx *transaction, cred *credential) error {
	return s.TxStoreCLSignature(tx, cred.AttributeList().Hash(), &clSignatureWitness{
		CLSignature: cred.Signature,
		Witness:     cred.NonRevocationWitness,
	})
}

func (s *storage) TxStoreCLSignature(tx *transaction, credHash string, sig *clSignatureWitness) error {
	// We take the SHA256 hash over all attributes as the bucket key for the signature.
	// This means that of the signatures of two credentials that have identical attributes
	// only one gets stored, one overwriting the other - but that doesn't
	// matter, because either one of the signatures is valid over both attribute lists,
	// so keeping one of them suffices.
	return s.txStore(tx, signaturesBucket, credHash, sig)
}

func (s *storage) StoreSecretKey(sk *secretKey) error {
	return s.Transaction(func(tx *transaction) error {
		return s.TxStoreSecretKey(tx, sk)
	})
}

func (s *storage) TxStoreSecretKey(tx *transaction, sk *secretKey) error {
	return s.txStore(tx, userdataBucket, skKey, sk)
}

func (s *storage) StoreAttributes(credTypeID irma.CredentialTypeIdentifier, attrlistlist []*irma.AttributeList) error {
	return s.Transaction(func(tx *transaction) error {
		return s.TxStoreAttributes(tx, credTypeID, attrlistlist)
	})
}

func (s *storage) TxStoreAttributes(tx *transaction, credTypeID irma.CredentialTypeIdentifier,
	attrlistlist []*irma.AttributeList) error {

	// If no credentials are left of a certain type, the full entry can be deleted.
	if len(attrlistlist) == 0 {
		return s.txDelete(tx, attributesBucket, credTypeID.String())
	}
	return s.txStore(tx, attributesBucket, credTypeID.String(), attrlistlist)
}

func (s *storage) TxDeleteAllAttributes(tx *transaction) error {
	return tx.DeleteBucket([]byte(attributesBucket))
}

func (s *storage) StoreKeyshareServers(keyshareServers map[irma.SchemeManagerIdentifier]*keyshareServer) error {
	return s.Transaction(func(tx *transaction) error {
		return s.TxStoreKeyshareServers(tx, keyshareServers)
	})
}

func (s *storage) TxStoreKeyshareServers(tx *transaction, keyshareServers map[irma.SchemeManagerIdentifier]*keyshareServer) error {
	return s.txStore(tx, userdataBucket, kssKey, keyshareServers)
}

func (s *storage) AddLogEntry(entry *LogEntry) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return s.TxAddLogEntry(&transaction{tx}, entry)
	})
}

func (s *storage) TxAddLogEntry(tx *transaction, entry *LogEntry) error {
	b, err := tx.CreateBucketIfNotExists([]byte(logsBucket))
	if err != nil {
		return err
	}

	entry.ID, err = b.NextSequence()
	if err != nil {
		return err
	}
	k := s.logEntryKeyToBytes(entry.ID)
	v, err := json.Marshal(entry)

	return b.Put(k, v)
}

func (s *storage) logEntryKeyToBytes(id uint64) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, id)
	return k
}

func (s *storage) StorePreferences(prefs Preferences) error {
	return s.Transaction(func(tx *transaction) error {
		return s.TxStorePreferences(tx, prefs)
	})
}

func (s *storage) TxStorePreferences(tx *transaction, prefs Preferences) error {
	return s.txStore(tx, userdataBucket, preferencesKey, prefs)
}

func (s *storage) StoreUpdates(updates []update) (err error) {
	return s.Transaction(func(tx *transaction) error {
		return s.TxStoreUpdates(tx, updates)
	})
}

func (s *storage) TxStoreUpdates(tx *transaction, updates []update) error {
	return s.txStore(tx, userdataBucket, updatesKey, updates)
}

func (s *storage) LoadSignature(attrs *irma.AttributeList) (*gabi.CLSignature, *revocation.Witness, error) {
	sig := new(clSignatureWitness)
	found, err := s.load(signaturesBucket, attrs.Hash(), sig)
	if err != nil {
		return nil, nil, err
	} else if !found {
		return nil, nil, errors.Errorf("Signature of credential with hash %s cannot be found", attrs.Hash())
	}
	if sig.Witness != nil {
		pk, err := s.Configuration.RevocationStorage.Keys.PublicKey(
			attrs.CredentialType().IssuerIdentifier(),
			sig.Witness.Record.PublicKeyIndex,
		)
		if err != nil {
			return nil, nil, err
		}
		if err = sig.Witness.Verify(pk); err != nil {
			return nil, nil, err
		}
	}
	return sig.CLSignature, sig.Witness, nil
}

// LoadSecretKey retrieves and returns the secret key from bbolt storage, or if no secret key
// was found in storage, it generates, saves, and returns a new secret key.
func (s *storage) LoadSecretKey() (*secretKey, error) {
	sk := &secretKey{}
	found, err := s.load(userdataBucket, skKey, sk)
	if err != nil {
		return nil, err
	}
	if found {
		return sk, nil
	}

	if sk, err = generateSecretKey(); err != nil {
		return nil, err
	}
	if err = s.StoreSecretKey(sk); err != nil {
		return nil, err
	}
	return sk, nil
}

func (s *storage) LoadAttributes() (list map[irma.CredentialTypeIdentifier][]*irma.AttributeList, err error) {
	list = make(map[irma.CredentialTypeIdentifier][]*irma.AttributeList)
	return list, s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(attributesBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(key, value []byte) error {
			credTypeID := irma.NewCredentialTypeIdentifier(string(key))

			var attrlistlist []*irma.AttributeList
			err = json.Unmarshal(value, &attrlistlist)
			if err != nil {
				return err
			}

			// Initialize metadata attributes
			for _, attrlist := range attrlistlist {
				attrlist.MetadataAttribute = irma.MetadataFromInt(attrlist.Ints[0], s.Configuration)
			}

			list[credTypeID] = attrlistlist
			return nil
		})
	})
}

func (s *storage) LoadKeyshareServers() (ksses map[irma.SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
	_, err = s.load(userdataBucket, kssKey, &ksses)
	return
}

// Returns all logs stored before log with ID 'index' sorted from new to old with
// a maximum result length of 'max'.
func (s *storage) LoadLogsBefore(index uint64, max int) ([]*LogEntry, error) {
	return s.loadLogs(max, func(c *bbolt.Cursor) (key, value []byte) {
		c.Seek(s.logEntryKeyToBytes(index))
		return c.Prev()
	})
}

// Returns the latest logs stored sorted from new to old with a maximum result length of 'max'
func (s *storage) LoadNewestLogs(max int) ([]*LogEntry, error) {
	return s.loadLogs(max, func(c *bbolt.Cursor) (key, value []byte) {
		return c.Last()
	})
}

// Returns the logs stored sorted from new to old with a maximum result length of 'max' where the starting position
// of the bbolt cursor can be manipulated by the anonymous function 'startAt'. 'startAt' should return
// the key and the value of the first element from the bbolt database that should be loaded.
func (s *storage) loadLogs(max int, startAt func(*bbolt.Cursor) (key, value []byte)) ([]*LogEntry, error) {
	logs := make([]*LogEntry, 0, max)
	return logs, s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(logsBucket))
		if bucket == nil {
			return nil
		}
		c := bucket.Cursor()

		for k, v := startAt(c); k != nil && len(logs) < max; k, v = c.Prev() {
			var log LogEntry
			if err := json.Unmarshal(v, &log); err != nil {
				return err
			}

			logs = append(logs, &log)
		}
		return nil
	})
}

func (s *storage) LoadUpdates() (updates []update, err error) {
	updates = []update{}
	_, err = s.load(userdataBucket, updatesKey, &updates)
	return
}

func (s *storage) LoadPreferences() (Preferences, error) {
	config := defaultPreferences
	_, err := s.load(userdataBucket, preferencesKey, &config)
	return config, err
}

func (s *storage) TxDeleteUserdata(tx *transaction) error {
	return tx.DeleteBucket([]byte(userdataBucket))
}

func (s *storage) TxDeleteLogs(tx *transaction) error {
	return tx.DeleteBucket([]byte(logsBucket))
}

func (s *storage) TxDeleteAll(tx *transaction) error {
	if err := s.TxDeleteAllAttributes(tx); err != nil && err != bbolt.ErrBucketNotFound {
		return err
	}
	if err := s.TxDeleteAllSignatures(tx); err != nil && err != bbolt.ErrBucketNotFound {
		return err
	}
	if err := s.TxDeleteUserdata(tx); err != nil && err != bbolt.ErrBucketNotFound {
		return err
	}
	if err := s.TxDeleteLogs(tx); err != nil && err != bbolt.ErrBucketNotFound {
		return err
	}
	return nil
}

func (s *storage) DeleteAll() error {
	return s.Transaction(func(tx *transaction) error {
		return s.TxDeleteAll(tx)
	})
}
