package irmaclient

import (
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"os"
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
	logsBucket = "logs"
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

func (s *storage) load(dest interface{}, path string) (err error) {
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

func (s *storage) signatureFilename(attrs *irma.AttributeList) string {
	// We take the SHA256 hash over all attributes as the filename for the signature.
	// This means that the signatures of two credentials that have identical attributes
	// will be written to the same file, one overwriting the other - but that doesn't
	// matter, because either one of the signatures is valid over both attribute lists,
	// so keeping one of them suffices.
	return filepath.Join(signaturesDir, attrs.Hash())
}

func (s *storage) DeleteSignature(attrs *irma.AttributeList) error {
	return os.Remove(s.path(s.signatureFilename(attrs)))
}

func (s *storage) StoreSignature(cred *credential) error {
	return s.store(cred.Signature, s.signatureFilename(cred.AttributeList()))
}

func (s *storage) StoreSecretKey(sk *secretKey) error {
	return s.store(sk, skFile)
}

func (s *storage) StoreAttributes(attributes map[irma.CredentialTypeIdentifier][]*irma.AttributeList) error {
	temp := []*irma.AttributeList{}
	for _, attrlistlist := range attributes {
		for _, attrlist := range attrlistlist {
			temp = append(temp, attrlist)
		}
	}

	return s.store(temp, attributesFile)
}

func (s *storage) StoreKeyshareServers(keyshareServers map[irma.SchemeManagerIdentifier]*keyshareServer) error {
	return s.store(keyshareServers, kssFile)
}

func (s *storage) StoreLogs(logs []*LogEntry) error {
	return s.store(logs, logsFile)
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
	return s.store(prefs, preferencesFile)
}

func (s *storage) StoreUpdates(updates []update) (err error) {
	return s.store(updates, updatesFile)
}

func (s *storage) LoadSignature(attrs *irma.AttributeList) (signature *gabi.CLSignature, err error) {
	sigpath := s.signatureFilename(attrs)
	if err := fs.AssertPathExists(s.path(sigpath)); err != nil {
		return nil, err
	}
	signature = new(gabi.CLSignature)
	if err := s.load(signature, sigpath); err != nil {
		return nil, err
	}
	return signature, nil
}

// LoadSecretKey retrieves and returns the secret key from storage, or if no secret key
// was found in storage, it generates, saves, and returns a new secret key.
func (s *storage) LoadSecretKey() (*secretKey, error) {
	var err error
	sk := &secretKey{}
	if err = s.load(sk, skFile); err != nil {
		return nil, err
	}
	if sk.Key != nil {
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
	// The attributes are stored as a list of instances of AttributeList
	temp := []*irma.AttributeList{}
	if err = s.load(&temp, attributesFile); err != nil {
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

func (s *storage) LoadKeyshareServers() (ksses map[irma.SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
	if err := s.load(&ksses, kssFile); err != nil {
		return nil, err
	}
	return ksses, nil
}

// Returns all logs stored before log with ID 'startBeforeIndex' sorted from new to old with
// a maximum result length of 'max'.
func (s *storage) LoadLogsBefore(startBeforeIndex uint64, max int) ([]*LogEntry, error) {
	return s.loadLogsFromBbolt(max, func(c *bbolt.Cursor) (key, value []byte) {
		c.Seek(s.logEntryKeyToBytes(startBeforeIndex))
		return c.Prev()
	})
}

// Returns the latest logs stored sorted from new to old with a maximum result length of 'max'
func (s *storage) LoadNewestLogs(max int) ([]*LogEntry, error) {
	return s.loadLogsFromBbolt(max, func(c *bbolt.Cursor) (key, value []byte) {
		return c.Last()
	})
}

// Returns the logs stored sorted from new to old with a maximum result length of 'max' where the starting position
// of the bbolt cursor can be manipulated by the anonymous function 'startAt'. 'startAt' should return
// the key and the value of the first element from the bbolt database that should be loaded.
func (s *storage) loadLogsFromBbolt(max int, startAt func(*bbolt.Cursor) (key, value []byte)) ([]*LogEntry, error) {
	var logs []*LogEntry
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
	if err := s.load(&updates, updatesFile); err != nil {
		return nil, err
	}
	return updates, nil
}

func (s *storage) LoadPreferences() (Preferences, error) {
	config := defaultPreferences
	return config, s.load(&config, preferencesFile)
}
