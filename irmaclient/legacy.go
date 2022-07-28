package irmaclient

import (
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/revocation"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"

	"github.com/go-errors/errors"
)

// This files contains both the legacy fileStorage struct with its methods and the legacy unencrypted
// bbolt `storageOld` with its methods.

// This following code contains the storageOld struct and its methods,
// and some general filesystem functions.

// storageOld provider for a Client
type storageOld struct {
	storageOldPath string
	db             *bbolt.DB
	Configuration  *irma.Configuration
}

// Filenames
const oldDatabaseFile = "db"

func (s *storageOld) path(p string) string {
	return filepath.Join(s.storageOldPath, p)
}

// Open initializes the credential storageOld,
// ensuring that it is in a usable state.
// Setting it up in a properly protected location (e.g., with automatic
// backups to iCloud/Google disabled) is the responsibility of the user.
func (s *storageOld) Open() error {
	var err error
	if err = common.AssertPathExists(s.storageOldPath); err != nil {
		return err
	}
	s.db, err = bbolt.Open(s.path(oldDatabaseFile), 0600, &bbolt.Options{Timeout: 1 * time.Second})
	return err
}

func (s *storageOld) Close() error {
	return s.db.Close()
}

func (s *storageOld) txStore(tx *transaction, bucketName string, key string, value interface{}) error {
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

func (s *storageOld) txDelete(tx *transaction, bucketName string, key string) error {
	b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
	if err != nil {
		return err
	}

	return b.Delete([]byte(key))
}

func (s *storageOld) txLoad(tx *transaction, bucketName string, key string, dest interface{}) (found bool, err error) {
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

func (s *storageOld) load(bucketName string, key string, dest interface{}) (found bool, err error) {
	err = s.db.View(func(tx *bbolt.Tx) error {
		found, err = s.txLoad(&transaction{tx}, bucketName, key, dest)
		return err
	})
	return
}

func (s *storageOld) Transaction(f func(*transaction) error) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return f(&transaction{tx})
	})
}

func (s *storageOld) TxDeleteAllSignatures(tx *transaction) error {
	return tx.DeleteBucket([]byte(signaturesBucket))
}

func (s *storageOld) TxStoreCLSignature(tx *transaction, credHash string, sig *clSignatureWitness) error {
	// We take the SHA256 hash over all attributes as the bucket key for the signature.
	// This means that of the signatures of two credentials that have identical attributes
	// only one gets stored, one overwriting the other - but that doesn't
	// matter, because either one of the signatures is valid over both attribute lists,
	// so keeping one of them suffices.
	return s.txStore(tx, signaturesBucket, credHash, sig)
}

func (s *storageOld) StoreSecretKey(sk *secretKey) error {
	return s.Transaction(func(tx *transaction) error {
		return s.TxStoreSecretKey(tx, sk)
	})
}

func (s *storageOld) TxStoreSecretKey(tx *transaction, sk *secretKey) error {
	return s.txStore(tx, userdataBucket, skKey, sk)
}

func (s *storageOld) TxStoreAttributes(tx *transaction, credTypeID irma.CredentialTypeIdentifier,
	attrlistlist []*irma.AttributeList) error {

	// If no credentials are left of a certain type, the full entry can be deleted.
	if len(attrlistlist) == 0 {
		return s.txDelete(tx, attributesBucket, credTypeID.String())
	}
	return s.txStore(tx, attributesBucket, credTypeID.String(), attrlistlist)
}

func (s *storageOld) TxDeleteAllAttributes(tx *transaction) error {
	return tx.DeleteBucket([]byte(attributesBucket))
}

func (s *storageOld) StoreKeyshareServers(keyshareServers map[irma.SchemeManagerIdentifier]*keyshareServer) error {
	return s.Transaction(func(tx *transaction) error {
		return s.TxStoreKeyshareServers(tx, keyshareServers)
	})
}

func (s *storageOld) TxStoreKeyshareServers(tx *transaction, keyshareServers map[irma.SchemeManagerIdentifier]*keyshareServer) error {
	return s.txStore(tx, userdataBucket, kssKey, keyshareServers)
}

func (s *storageOld) TxAddLogEntry(tx *transaction, entry *LogEntry) error {
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
	if err != nil {
		return err
	}

	return b.Put(k, v)
}

func (s *storageOld) logEntryKeyToBytes(id uint64) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, id)
	return k
}

func (s *storageOld) TxStorePreferences(tx *transaction, prefs Preferences) error {
	return s.txStore(tx, userdataBucket, preferencesKey, prefs)
}

func (s *storageOld) TxStoreUpdates(tx *transaction, updates []update) error {
	return s.txStore(tx, userdataBucket, updatesKey, updates)
}

func (s *storageOld) LoadSignature(attrs *irma.AttributeList) (*gabi.CLSignature, *revocation.Witness, error) {
	sig := new(clSignatureWitness)
	found, err := s.load(signaturesBucket, attrs.Hash(), sig)
	if err != nil {
		return nil, nil, err
	} else if !found {
		return nil, nil, errors.Errorf("Signature of credential with hash %s cannot be found", attrs.Hash())
	}
	if sig.Witness != nil {
		pk, err := s.Configuration.Revocation.Keys.PublicKey(
			attrs.CredentialType().IssuerIdentifier(),
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

// LoadSecretKey retrieves and returns the secret key from bbolt storageOld, or if no secret key
// was found in storageOld, it generates, saves, and returns a new secret key.
func (s *storageOld) LoadSecretKey() (*secretKey, error) {
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

func (s *storageOld) LoadAttributes() (list map[irma.CredentialTypeIdentifier][]*irma.AttributeList, err error) {
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

func (s *storageOld) LoadKeyshareServers() (ksses map[irma.SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
	_, err = s.load(userdataBucket, kssKey, &ksses)
	return
}

func (s *storageOld) LoadUpdates() (updates []update, err error) {
	updates = []update{}
	_, err = s.load(userdataBucket, updatesKey, &updates)
	return
}

func (s *storageOld) LoadPreferences() (Preferences, error) {
	config := defaultPreferences
	_, err := s.load(userdataBucket, preferencesKey, &config)
	return config, err
}

func (s *storageOld) TxDeleteUserdata(tx *transaction) error {
	return tx.DeleteBucket([]byte(userdataBucket))
}

func (s *storageOld) TxDeleteLogs(tx *transaction) error {
	return tx.DeleteBucket([]byte(logsBucket))
}

func (s *storageOld) TxDeleteAll(tx *transaction) error {
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

func (s *storageOld) DeleteAll() error {
	return s.Transaction(func(tx *transaction) error {
		return s.TxDeleteAll(tx)
	})
}

// This following code contains the legacy storage based on files. These functions are needed
// in the upgrade path to convert the file based storage to the bbolt based storage.
// The new storage functions for bbolt can be found in storage.go.

type fileStorage struct {
	storagePath   string
	Configuration *irma.Configuration
}

// Legacy filenames in which we stored stuff
const (
	skFile          = "sk"
	attributesFile  = "attrs"
	kssFile         = "kss"
	updatesFile     = "updates"
	logsFile        = "logs"
	preferencesFile = "preferences"
	signaturesDir   = "sigs"
)

func (f *fileStorage) path(p string) string {
	return filepath.Join(f.storagePath, p)
}

func (f *fileStorage) load(dest interface{}, path string) (err error) {
	info, exists, err := common.Stat(f.path(path))
	if err != nil || !exists {
		return
	}
	if info.IsDir() || !info.Mode().IsRegular() {
		return errors.New("invalid file")
	}
	bytes, err := ioutil.ReadFile(f.path(path))
	if err != nil {
		return
	}
	return json.Unmarshal(bytes, dest)
}

func (f *fileStorage) signatureFilename(attrs *irma.AttributeList) string {
	// We take the SHA256 hash over all attributes as the filename for the signature.
	// This means that the signatures of two credentials that have identical attributes
	// will be written to the same file, one overwriting the other - but that doesn't
	// matter, because either one of the signatures is valid over both attribute lists,
	// so keeping one of them suffices.
	return filepath.Join(signaturesDir, attrs.Hash())
}

func (f *fileStorage) LoadSignature(attrs *irma.AttributeList) (signature *gabi.CLSignature, witness *revocation.Witness, err error) {
	sigpath := f.signatureFilename(attrs)
	if err := common.AssertPathExists(f.path(sigpath)); err != nil {
		return nil, nil, err
	}
	sig := &clSignatureWitness{}
	if err := f.load(sig, sigpath); err != nil {
		return nil, nil, err
	}
	return sig.CLSignature, sig.Witness, nil
}

// LoadSecretKey retrieves and returns the secret key from file storage. When no secret key
// file is found, nil is returned.
func (f *fileStorage) LoadSecretKey() (*secretKey, error) {
	var err error
	sk := &secretKey{}
	if err = f.load(sk, skFile); err != nil {
		return nil, err
	}
	if sk.Key != nil {
		return sk, nil
	}
	return nil, nil
}

func (f *fileStorage) LoadAttributes() (list map[irma.CredentialTypeIdentifier][]*irma.AttributeList, err error) {
	// The attributes are stored as a list of instances of AttributeList
	temp := []*irma.AttributeList{}
	if err = f.load(&temp, attributesFile); err != nil {
		return
	}

	list = make(map[irma.CredentialTypeIdentifier][]*irma.AttributeList)
	for _, attrlist := range temp {
		attrlist.MetadataAttribute = irma.MetadataFromInt(attrlist.Ints[0], f.Configuration)
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

func (f *fileStorage) LoadKeyshareServers() (ksses map[irma.SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
	if err := f.load(&ksses, kssFile); err != nil {
		return nil, err
	}
	return ksses, nil
}

func (f *fileStorage) LoadUpdates() (updates []update, err error) {
	updates = []update{}
	if err := f.load(&updates, updatesFile); err != nil {
		return nil, err
	}
	return updates, nil
}

func (f *fileStorage) LoadPreferences() (Preferences, error) {
	config := defaultPreferences
	return config, f.load(&config, preferencesFile)
}

func (f *fileStorage) LoadLogs() (logs []*LogEntry, err error) {
	return logs, f.load(&logs, logsFile)
}

func (f *fileStorage) DeleteAll() error {
	// Remove all legacy storage files
	files := []string{skFile, attributesFile, kssFile, updatesFile, logsFile, preferencesFile}
	for _, file := range files {
		path := f.path(file)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	// Remove all legacy signatures
	path := f.path(signaturesDir)
	if err := os.RemoveAll(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// registerPublicKey registers our public key used in the ECDSA challenge-response
// sub-protocol part of the keyshare protocol at the keyshare server.
func (kss *keyshareServer) registerPublicKey(client *Client, transport *irma.HTTPTransport, pin string) (*irma.KeysharePinStatus, error) {
	keyname := challengeResponseKeyName(kss.SchemeManagerIdentifier)

	pk, err := client.signer.PublicKey(keyname)
	if err != nil {
		return nil, err
	}
	jwtt, err := SignerCreateJWT(client.signer, keyname, irma.KeyshareKeyRegistrationClaims{
		KeyshareKeyRegistrationData: irma.KeyshareKeyRegistrationData{
			Username:  kss.Username,
			Pin:       kss.HashedPin(pin),
			PublicKey: pk,
		},
	})
	if err != nil {
		err = errors.WrapPrefix(err, "failed to sign public key registration JWT", 0)
		return nil, err
	}

	result := &irma.KeysharePinStatus{}
	err = transport.Post("users/register_publickey", result, irma.KeyshareKeyRegistration{PublicKeyRegistrationJWT: jwtt})
	if err != nil {
		err = errors.WrapPrefix(err, "failed to register public key", 0)
		return nil, err
	}

	if result.Status == kssPinSuccess {
		// We leave dealing with any other case up to the calling code
		kss.ChallengeResponse = true
		err = client.storage.StoreKeyshareServers(client.keyshareServers)
		if err != nil {
			err = errors.WrapPrefix(err, "failed to store updated keyshare server", 0)
		}
	}

	return result, nil
}
