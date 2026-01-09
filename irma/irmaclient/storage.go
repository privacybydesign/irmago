package irmaclient

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/revocation"
	clientstorage "github.com/privacybydesign/irmago/internal/clientstorage"
	"github.com/privacybydesign/irmago/irma"

	"github.com/go-errors/errors"
	"go.etcd.io/bbolt"
)

// This file contains the storage struct and its methods,
// and some general filesystem functions.

// Storage provider for a Client
type storage struct {
	dbStorage     *clientstorage.Storage
	Configuration *irma.Configuration
}

// Filenames
const databaseFile = "db2"

// Bucketnames bbolt
const (
	skKey           = "sk"           // Value: *secretKey
	credTypeKeysKey = "credTypeKeys" // Value: map[irma.CredentialTypeIdentifier][]byte
	updatesKey      = "updates"      // Value: []update
	kssKey          = "kss"          // Value: map[irma.SchemeManagerIdentifier]*keyshareServer

	attributesBucket = "attrs" // Key: []byte, value: []*irma.AttributeList
	logsBucket       = "logs"  // Key: (auto-increment index), value: *LogEntry
	signaturesBucket = "sigs"  // Key: credential.attrs.Hash, value: *gabi.CLSignature
)

func NewIrmaStorage(s *clientstorage.Storage, config *irma.Configuration) *storage {
	return &storage{
		dbStorage:     s,
		Configuration: config,
	}
}

func (s *storage) BucketExists(name []byte) bool {
	return s.dbStorage.Db.View(func(tx *bbolt.Tx) error {
		if tx.Bucket(name) == nil {
			return bbolt.ErrBucketNotFound
		}
		return nil
	}) == nil
}

func (s *storage) TxDeleteSignature(tx *clientstorage.Transaction, hash string) error {
	return s.dbStorage.TxDelete(tx, signaturesBucket, hash)
}

func (s *storage) TxDeleteAllSignatures(tx *clientstorage.Transaction) error {
	return tx.DeleteBucket([]byte(signaturesBucket))
}

type clSignatureWitness struct {
	*gabi.CLSignature
	Witness *revocation.Witness
}

func (s *storage) StoreSignature(cred *credential) error {
	return s.dbStorage.Transaction(func(tx *clientstorage.Transaction) error {
		return s.TxStoreSignature(tx, cred)
	})
}

func (s *storage) TxStoreSignature(tx *clientstorage.Transaction, cred *credential) error {
	return s.TxStoreCLSignature(tx, cred.attrs.Hash(), &clSignatureWitness{
		CLSignature: cred.Signature,
		Witness:     cred.NonRevocationWitness,
	})
}

func (s *storage) TxStoreCLSignature(tx *clientstorage.Transaction, credHash string, sig *clSignatureWitness) error {
	// We take the SHA256 hash over all attributes as the bucket key for the signature.
	// This means that of the signatures of two credentials that have identical attributes
	// only one gets stored, one overwriting the other - but that doesn't
	// matter, because either one of the signatures is valid over both attribute lists,
	// so keeping one of them suffices.
	return s.dbStorage.TxStore(tx, signaturesBucket, credHash, sig)
}

func (s *storage) StoreSecretKey(sk *secretKey) error {
	return s.dbStorage.Transaction(func(tx *clientstorage.Transaction) error {
		return s.TxStoreSecretKey(tx, sk)
	})
}

func (s *storage) TxStoreSecretKey(tx *clientstorage.Transaction, sk *secretKey) error {
	return s.dbStorage.TxStore(tx, clientstorage.UserdataBucket, skKey, sk)
}

func (s *storage) StoreAttributes(credTypeID irma.CredentialTypeIdentifier, attrlistlist []*irma.AttributeList) error {
	return s.dbStorage.Transaction(func(tx *clientstorage.Transaction) error {
		return s.TxStoreAttributes(tx, credTypeID, attrlistlist)
	})
}

func (s *storage) TxStoreAttributes(tx *clientstorage.Transaction, credTypeID irma.CredentialTypeIdentifier,
	attrlistlist []*irma.AttributeList) error {

	// If no credentials are left of a certain type, the full entry can be deleted.
	if len(attrlistlist) == 0 {
		randomId, err := s.removeCredTypeKey(tx, credTypeID)
		if err != nil {
			return err
		}

		return s.dbStorage.TxDelete(tx, attributesBucket, randomId)
	}

	randomId, err := s.credTypeKey(tx, credTypeID)
	if err != nil {
		return err
	}

	return s.dbStorage.TxStore(tx, attributesBucket, string(randomId), attrlistlist)
}

func (s *storage) removeCredTypeKey(tx *clientstorage.Transaction, credTypeID irma.CredentialTypeIdentifier) (string, error) {
	credTypeIDs := map[irma.CredentialTypeIdentifier][]byte{}
	_, err := s.dbStorage.TxLoad(tx, clientstorage.UserdataBucket, credTypeKeysKey, &credTypeIDs)
	if err != nil {
		return "", err
	}

	res := string(credTypeIDs[credTypeID])

	delete(credTypeIDs, credTypeID)
	if len(credTypeIDs) == 0 {
		err = s.dbStorage.TxDelete(tx, clientstorage.UserdataBucket, credTypeKeysKey)
		if err != nil {
			return "", err
		}
	}
	err = s.dbStorage.TxStore(tx, clientstorage.UserdataBucket, credTypeKeysKey, credTypeIDs)
	if err != nil {
		return "", err
	}

	return res, nil
}

func (s *storage) credTypeKey(tx *clientstorage.Transaction, credTypeID irma.CredentialTypeIdentifier) ([]byte, error) {
	credTypeIDs := map[irma.CredentialTypeIdentifier][]byte{}
	_, err := s.dbStorage.TxLoad(tx, clientstorage.UserdataBucket, credTypeKeysKey, &credTypeIDs)
	if err != nil {
		return nil, err
	}

	if val, ok := credTypeIDs[credTypeID]; ok {
		return val, nil
	}

	randomId := make([]byte, 32)
	_, _ = rand.Read(randomId)

	credTypeIDs[credTypeID] = randomId
	err = s.dbStorage.TxStore(tx, clientstorage.UserdataBucket, credTypeKeysKey, credTypeIDs)
	if err != nil {
		return nil, err
	}

	return randomId, nil
}

func (s *storage) TxDeleteAllAttributes(tx *clientstorage.Transaction) error {
	err := tx.DeleteBucket([]byte(attributesBucket))
	if err != nil {
		return err
	}
	return s.dbStorage.TxDelete(tx, clientstorage.UserdataBucket, credTypeKeysKey)
}

func (s *storage) StoreKeyshareServers(keyshareServers map[irma.SchemeManagerIdentifier]*keyshareServer) error {
	return s.dbStorage.Transaction(func(tx *clientstorage.Transaction) error {
		return s.TxStoreKeyshareServers(tx, keyshareServers)
	})
}

func (s *storage) TxStoreKeyshareServers(tx *clientstorage.Transaction, keyshareServers map[irma.SchemeManagerIdentifier]*keyshareServer) error {
	return s.dbStorage.TxStore(tx, clientstorage.UserdataBucket, kssKey, keyshareServers)
}

func (s *storage) StoreUpdates(updates []update) (err error) {
	return s.dbStorage.Transaction(func(tx *clientstorage.Transaction) error {
		return s.TxStoreUpdates(tx, updates)
	})
}

func (s *storage) TxStoreUpdates(tx *clientstorage.Transaction, updates []update) error {
	return s.dbStorage.TxStore(tx, clientstorage.UserdataBucket, updatesKey, updates)
}

func (s *storage) LoadSignature(attrs *irma.AttributeList) (*gabi.CLSignature, *revocation.Witness, error) {
	credType := attrs.CredentialType()
	if credType == nil {
		return nil, nil, errors.New("credential not known in configuration")
	}
	if _, ok := s.Configuration.DisabledSchemeManagers[credType.SchemeManagerIdentifier()]; ok {
		return nil, nil, errors.Errorf("scheme %s is disabled", credType.SchemeManagerIdentifier())
	}

	sig := new(clSignatureWitness)
	found, err := s.dbStorage.Load(signaturesBucket, attrs.Hash(), sig)
	if err != nil {
		return nil, nil, err
	} else if !found {
		return nil, nil, errors.Errorf("signature of credential with hash %s cannot be found", attrs.Hash())
	}
	if sig.Witness != nil {
		pk, err := s.Configuration.Revocation.Keys.PublicKey(
			credType.IssuerIdentifier(),
			sig.Witness.SignedAccumulator.PKCounter,
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
	found, err := s.dbStorage.Load(clientstorage.UserdataBucket, skKey, sk)
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
	return list, s.dbStorage.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(attributesBucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(key, value []byte) error {
			credTypeID := irma.NewCredentialTypeIdentifier(string(key))
			var attrlistlist []*irma.AttributeList

			plaintext, err := s.dbStorage.Decrypt(value)
			if err != nil {
				return err
			}

			err = json.Unmarshal(plaintext, &attrlistlist)
			if err != nil {
				return err
			}

			// Initialize metadata attributes
			for _, attrlist := range attrlistlist {
				attrlist.MetadataAttribute = irma.MetadataFromInt(attrlist.Ints[0], s.Configuration)
			}

			credType := attrlistlist[0].CredentialType()
			if credType == nil {
				return errors.Errorf("credential %s not known in configuration", credTypeID)
			}
			if _, ok := s.Configuration.DisabledSchemeManagers[credType.SchemeManagerIdentifier()]; ok {
				return errors.Errorf("scheme %s is disabled", credType.SchemeManagerIdentifier())
			}

			list[credType.Identifier()] = attrlistlist
			return nil
		})
	})
}

func (s *storage) LoadKeyshareServers() (ksses map[irma.SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
	_, err = s.dbStorage.Load(clientstorage.UserdataBucket, kssKey, &ksses)
	if err != nil {
		return
	}
	for schemeID := range ksses {
		if schemeManager, ok := s.Configuration.SchemeManagers[schemeID]; !ok || !schemeManager.Distributed() {
			return nil, errors.Errorf("scheme %s not known in configuration", schemeManager.Identifier())
		}
		if _, ok := s.Configuration.DisabledSchemeManagers[schemeID]; ok {
			return nil, errors.Errorf("scheme %s is disabled", schemeID)
		}
	}
	return
}

func logEntryKeyToBytes(id uint64) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, id)
	return k
}

func (s *storage) AddLogEntry(entry *LogEntry) error {
	return s.dbStorage.Db.Update(func(tx *bbolt.Tx) error {
		return s.TxAddLogEntry(&clientstorage.Transaction{Tx: tx}, entry)
	})
}

func (s *storage) TxAddLogEntry(tx *clientstorage.Transaction, entry *LogEntry) error {
	b, err := tx.CreateBucketIfNotExists([]byte(logsBucket))
	if err != nil {
		return err
	}

	entry.ID, err = b.NextSequence()
	if err != nil {
		return err
	}
	k := logEntryKeyToBytes(entry.ID)
	v, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	ciphertext, err := s.dbStorage.Encrypt(v)
	if err != nil {
		return err
	}

	return b.Put(k, ciphertext)
}

func (s *storage) DeleteLogEntry(id uint64) error {
	return s.dbStorage.Transaction(func(tx *clientstorage.Transaction) error {
		return s.TxDeleteLogEntry(tx, id)
	})
}

func (s *storage) TxDeleteLogEntry(tx *clientstorage.Transaction, id uint64) error {
	b := tx.Bucket([]byte(logsBucket))
	if b == nil {
		return nil
	}
	return b.Delete(logEntryKeyToBytes(id))
}

func (s *storage) DeleteLogs() error {
	return s.dbStorage.Transaction(func(tx *clientstorage.Transaction) error {
		return s.TxDeleteLogs(tx)
	})
}

func (s *storage) TxDeleteLogs(tx *clientstorage.Transaction) error {
	return tx.DeleteBucket([]byte(logsBucket))
}

// Returns all logs stored before log with ID 'index' sorted from new to old with
// a maximum result length of 'max'.
func (s *storage) LoadLogsBefore(index uint64, max int) ([]*LogEntry, error) {
	return s.loadLogs(max, func(c *bbolt.Cursor) (key, value []byte) {
		c.Seek(logEntryKeyToBytes(index))
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
	return logs, s.dbStorage.Db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(logsBucket))
		if bucket == nil {
			return nil
		}
		c := bucket.Cursor()

		for k, v := startAt(c); k != nil && len(logs) < max; k, v = c.Prev() {
			log, err := s.decryptLog(v)
			if err != nil {
				return err
			}

			logs = append(logs, log)
		}
		return nil
	})
}

// TxIterateLogs iterates over all logs sorted by time, starting with the newest one.
func (s *storage) TxIterateLogs(tx *clientstorage.Transaction, handler func(log *LogEntry) error) error {
	bucket := tx.Bucket([]byte(logsBucket))
	if bucket == nil {
		return nil
	}
	c := bucket.Cursor()

	for k, v := c.Last(); k != nil; k, v = c.Prev() {
		log, err := s.decryptLog(v)
		if err != nil {
			return err
		}
		if err = handler(log); err != nil {
			return err
		}
	}
	return nil
}

func (s *storage) decryptLog(encryptedLog []byte) (*LogEntry, error) {
	plaintext, err := s.dbStorage.Decrypt(encryptedLog)
	if err != nil {
		return nil, err
	}

	var log LogEntry
	if err = json.Unmarshal(plaintext, &log); err != nil {
		return nil, err
	}

	// Validate whether log entry is consistent with configuration.
	sr, err := log.SessionRequest()
	if err != nil {
		return nil, err
	}
	if sr != nil {
		for schemeID := range sr.Identifiers().SchemeManagers {
			if _, ok := s.Configuration.DisabledSchemeManagers[schemeID]; ok {
				return nil, errors.Errorf("scheme %s is disabled", schemeID)
			}
			if _, ok := s.Configuration.SchemeManagers[schemeID]; !ok {
				return nil, errors.Errorf("scheme %s not known in configuration", schemeID)
			}
		}
	}
	for credID := range log.Removed {
		schemeID := credID.SchemeManagerIdentifier()
		if _, ok := s.Configuration.DisabledSchemeManagers[schemeID]; ok {
			return nil, errors.Errorf("scheme %s is disabled", schemeID)
		}
		if _, ok := s.Configuration.SchemeManagers[schemeID]; !ok {
			return nil, errors.Errorf("scheme %s not known in configuration", schemeID)
		}
	}

	return &log, nil
}

func (s *storage) LoadUpdates() (updates []update, err error) {
	updates = []update{}
	_, err = s.dbStorage.Load(clientstorage.UserdataBucket, updatesKey, &updates)
	return
}

func (s *storage) TxDeleteUserdata(tx *clientstorage.Transaction) error {
	return tx.DeleteBucket([]byte(clientstorage.UserdataBucket))
}

func (s *storage) TxDeleteAll(tx *clientstorage.Transaction) error {
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
	return s.dbStorage.Transaction(func(tx *clientstorage.Transaction) error {
		return s.TxDeleteAll(tx)
	})
}
