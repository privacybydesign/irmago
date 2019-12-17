package irmaclient

import (
	"encoding/binary"
	"encoding/json"
	"github.com/go-errors/errors"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
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

// Filenames in which we store stuff
const (
	skFile          = "sk"
	attributesFile  = "attrs"
	kssFile         = "kss"
	updatesFile     = "updates"
	logsFile        = "logs"
	preferencesFile = "preferences"
	signaturesDir   = "sigs"

	databaseFile = "db"
)

// Bucketnames bbolt
const (
	userdataBucket   = "userdata"    // Key/value: specified below
	skKey            = "sk"          // Value: *secretKey
	preferencesKey   = "preferences" // Value: Preferences
	updatesKey       = "updates"     // Value: []update
	kssKey           = "kss"         // Value: map[irma.SchemeManagerIdentifier]*keyshareServer
	attributesBucket = "attrs"       // Key: irma.CredentialIdentifier, value: []*irma.AttributeList
	logsBucket       = "logs"        // Key: (auto-increment index), value: *LogEntry
	signaturesBucket = "sigs"        // Key: credential.attrs.Hash, value: *gabi.CLSignature
)

func (s *storage) path(p string) string {
	return filepath.Join(s.storagePath, p)
}

// EnsureStorageExists initializes the credential storage folder,
// ensuring that it is in a usable state.
// NOTE: we do not create the folder if it does not exist!
// Setting it up in a properly protected location (e.g., with automatic
// backups to iCloud/Google disabled) is the responsibility of the user.
func (s *storage) EnsureStorageExists() error {
	var err error
	if err = fs.AssertPathExists(s.storagePath); err != nil {
		return err
	}
	if err = fs.EnsureDirectoryExists(s.path(signaturesDir)); err != nil {
		return err
	}
	s.db, err = bbolt.Open(s.path(databaseFile), 0600, &bbolt.Options{Timeout: 1 * time.Second})
	return err
}

func (s *storage) loadFromFile(dest interface{}, path string) (err error) {
	exists, err := fs.PathExists(s.path(path))
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(s.path(path))
	if err != nil {
		return
	}
	return json.Unmarshal(bytes, dest)
}

func (s *storage) store(contents interface{}, file string) error {
	bts, err := json.Marshal(contents)
	if err != nil {
		return err
	}
	return fs.SaveFile(s.path(file), bts)
}

func (s *storage) txStore(tx *bbolt.Tx, key interface{}, value interface{}, bucketName string) error {
	b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
	if err != nil {
		return err
	}
	btsKey, err := json.Marshal(key)
	if err != nil {
		return err
	}
	btsValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return b.Put(btsKey, btsValue)
}

func (s *storage) txLoad(tx *bbolt.Tx, key interface{}, dest interface{}, bucketName string) (found bool, err error) {
	b := tx.Bucket([]byte(bucketName))
	if b == nil {
		return false, nil
	}
	btsKey, err := json.Marshal(key)
	if err != nil {
		return false, err
	}
	bts := b.Get(btsKey)
	if bts == nil {
		return false, nil
	}
	return true, json.Unmarshal(bts, dest)
}

func (s *storage) load(key interface{}, dest interface{}, bucketName string) (found bool, err error) {
	err = s.db.View(func(tx *bbolt.Tx) error {
		found, err = s.txLoad(tx, key, dest, bucketName)
		return err
	})
	return
}

func (s *storage) signatureFilename(attrs *irma.AttributeList) string {
	// We take the SHA256 hash over all attributes as the filename for the signature.
	// This means that the signatures of two credentials that have identical attributes
	// will be written to the same file, one overwriting the other - but that doesn't
	// matter, because either one of the signatures is valid over both attribute lists,
	// so keeping one of them suffices.
	return filepath.Join(signaturesDir, attrs.Hash())
}

func (s *storage) DeleteSignature(attrs *irma.AttributeList) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(signaturesBucket))
		if err != nil {
			return err
		}
		return b.Delete([]byte(attrs.Hash()))
	})
}

func (s *storage) StoreSignature(cred *credential) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return s.TxStoreSignature(tx, cred.attrs.Hash(), cred.Signature)
	})
}

func (s *storage) TxStoreSignature(tx *bbolt.Tx, credHash string, sig *gabi.CLSignature) error {
	// We take the SHA256 hash over all attributes as the bucket key for the signature.
	// This means that of the signatures of two credentials that have identical attributes
	// only one gets stored, one overwriting the other - but that doesn't
	// matter, because either one of the signatures is valid over both attribute lists,
	// so keeping one of them suffices.
	return s.txStore(tx, credHash, sig, signaturesBucket)
}

func (s *storage) StoreSecretKey(sk *secretKey) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return s.TxStoreSecretKey(tx, sk)
	})
}

func (s *storage) TxStoreSecretKey(tx *bbolt.Tx, sk *secretKey) error {
	return s.txStore(tx, skKey, sk, userdataBucket)
}

func (s *storage) StoreAttributes(credTypeID irma.CredentialTypeIdentifier, attrlistlist []*irma.AttributeList) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return s.TxStoreAttributes(tx, credTypeID, attrlistlist)
	})
}

func (s *storage) TxStoreAttributes(tx *bbolt.Tx, credTypeID irma.CredentialTypeIdentifier,
	attrlistlist []*irma.AttributeList) error {

	return s.txStore(tx, credTypeID.String(), attrlistlist, attributesBucket)
}

func (s *storage) StoreAllAttributes(
	attributes map[irma.CredentialTypeIdentifier][]*irma.AttributeList) error {

	return s.db.Update(func(tx *bbolt.Tx) error {
		return s.TxStoreAllAttributes(tx, attributes)
	})
}

func (s *storage) TxStoreAllAttributes(tx *bbolt.Tx,
	attrs map[irma.CredentialTypeIdentifier][]*irma.AttributeList) error {

	for credTypeID, attrlistlist := range attrs {
		err := s.TxStoreAttributes(tx, credTypeID, attrlistlist)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *storage) StoreKeyshareServers(keyshareServers map[irma.SchemeManagerIdentifier]*keyshareServer) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return s.TxStoreKeyshareServers(tx, keyshareServers)
	})
}

func (s *storage) TxStoreKeyshareServers(tx *bbolt.Tx, keyshareServers map[irma.SchemeManagerIdentifier]*keyshareServer) error {
	return s.txStore(tx, kssKey, &keyshareServers, userdataBucket)
}

func (s *storage) AddLogEntry(entry *LogEntry) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return s.TxAddLogEntry(tx, entry)
	})
}

func (s *storage) TxAddLogEntry(tx *bbolt.Tx, entry *LogEntry) error {
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
	return s.db.Update(func(tx *bbolt.Tx) error {
		return s.TxStorePreferences(tx, prefs)
	})
}

func (s *storage) TxStorePreferences(tx *bbolt.Tx, prefs Preferences) error {
	return s.txStore(tx, preferencesKey, prefs, userdataBucket)
}

func (s *storage) StoreUpdates(updates []update) (err error) {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return s.TxStoreUpdates(tx, updates)
	})
}

func (s *storage) TxStoreUpdates(tx *bbolt.Tx, updates []update) error {
	return s.txStore(tx, updatesKey, updates, userdataBucket)
}

func (s *storage) LoadSignatureFile(attrs *irma.AttributeList) (signature *gabi.CLSignature, err error) {
	sigpath := s.signatureFilename(attrs)
	if err := fs.AssertPathExists(s.path(sigpath)); err != nil {
		return nil, err
	}
	signature = new(gabi.CLSignature)
	if err := s.loadFromFile(signature, sigpath); err != nil {
		return nil, err
	}
	return signature, nil
}

func (s *storage) LoadSignature(attrs *irma.AttributeList) (signature *gabi.CLSignature, err error) {
	signature = new(gabi.CLSignature)
	found, err := s.load(attrs.Hash(), signature, signaturesBucket)
	if err != nil {
		return nil, err
	} else if !found {
		return nil, errors.Errorf("Signature of credential with hash %s cannot be found", attrs.Hash())
	}
	return
}

// LoadSecretKeyFile retrieves and returns the secret key from file storage. When no secret key
// file is found, nil is returned.
func (s *storage) LoadSecretKeyFile() (*secretKey, error) {
	var err error
	sk := &secretKey{}
	if err = s.loadFromFile(sk, skFile); err != nil {
		return nil, err
	}
	if sk.Key != nil {
		return sk, nil
	}
	return nil, nil
}

// LoadSecretKey retrieves and returns the secret key from bbolt storage, or if no secret key
// was found in storage, it generates, saves, and returns a new secret key.
func (s *storage) LoadSecretKey() (*secretKey, error) {
	sk := &secretKey{}
	found, err := s.load(skKey, sk, userdataBucket)
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

func (s *storage) LoadAttributesFile() (list map[irma.CredentialTypeIdentifier][]*irma.AttributeList, err error) {
	// The attributes are stored as a list of instances of AttributeList
	temp := []*irma.AttributeList{}
	if err = s.loadFromFile(&temp, attributesFile); err != nil {
		return
	}

	list = make(map[irma.CredentialTypeIdentifier][]*irma.AttributeList)
	for _, attrlist := range temp {
		attrlist.MetadataAttribute = irma.MetadataFromInt(attrlist.Ints[0], s.Configuration)
		id := attrlist.CredentialType()
		var ct irma.CredentialTypeIdentifier
		if id != nil {
			ct = id.Identifier()
		}
		if _, contains := list[ct]; !contains {
			list[ct] = []*irma.AttributeList{}
		}
		list[ct] = append(list[ct], attrlist)
	}

	return list, nil
}

func (s *storage) LoadAttributes() (list map[irma.CredentialTypeIdentifier][]*irma.AttributeList, err error) {
	list = make(map[irma.CredentialTypeIdentifier][]*irma.AttributeList)
	return list, s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(attributesBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(key, value []byte) error {
			var (
				credTypeID   irma.CredentialTypeIdentifier
				attrlistlist []*irma.AttributeList
			)
			err := json.Unmarshal(key, &credTypeID)
			if err != nil {
				return err
			}
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

func (s *storage) LoadKeyshareServersFile() (ksses map[irma.SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
	if err := s.loadFromFile(&ksses, kssFile); err != nil {
		return nil, err
	}
	return ksses, nil
}

func (s *storage) LoadKeyshareServers() (ksses map[irma.SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
	_, err = s.load(kssKey, &ksses, userdataBucket)
	return ksses, err
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

func (s *storage) LoadUpdatesFile() (updates []update, err error) {
	updates = []update{}
	if err := s.loadFromFile(&updates, updatesFile); err != nil {
		return nil, err
	}
	return updates, nil
}

func (s *storage) LoadUpdates() (updates []update, err error) {
	updates = []update{}
	_, err = s.load(updatesKey, &updates, userdataBucket)
	return
}

func (s *storage) LoadPreferencesFile() (Preferences, error) {
	config := defaultPreferences
	return config, s.loadFromFile(&config, preferencesFile)
}

func (s *storage) LoadPreferences() (Preferences, error) {
	config := defaultPreferences
	_, err := s.load(preferencesKey, &config, userdataBucket)
	return config, err
}
