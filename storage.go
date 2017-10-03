package irmago

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// This file contains the storage struct and its methods,
// and some general filesystem functions.

// Storage provider for a CredentialManager
type storage struct {
	storagePath        string
	ConfigurationStore *ConfigurationStore
}

// Filenames in which we store stuff
const (
	skFile         = "sk"
	attributesFile = "attrs"
	kssFile        = "kss"
	paillierFile   = "paillier"
	updatesFile    = "updates"
	logsFile       = "logs"
	signaturesDir  = "sigs"
)

// AssertPathExists returns nil only if it has been successfully
// verified that the specified path exists.
func AssertPathExists(path string) error {
	exist, err := PathExists(path)
	if err != nil {
		return err
	}
	if !exist {
		return errors.Errorf("Path %s does not exist", path)
	}
	return nil
}

// PathExists checks if the specified path exists.
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func ensureDirectoryExists(path string) error {
	exists, err := PathExists(path)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return os.Mkdir(path, 0700)
}

// Save the filecontents at the specified path atomically:
// - first save the content in a temp file with a random filename in the same dir
// - then rename the temp file to the specified filepath, overwriting the old file
func saveFile(filepath string, content []byte) (err error) {
	dir := path.Dir(filepath)

	// Read random data for filename and convert to hex
	randBytes := make([]byte, 16)
	_, err = rand.Read(randBytes)
	if err != nil {
		return
	}
	tempfilename := hex.EncodeToString(randBytes)

	// Create temp file
	err = ioutil.WriteFile(dir+"/"+tempfilename, content, 0600)
	if err != nil {
		return
	}

	// Rename, overwriting old file
	return os.Rename(dir+"/"+tempfilename, filepath)
}

func (s *storage) path(p string) string {
	return s.storagePath + "/" + p
}

// EnsureStorageExists initializes the credential storage folder,
// ensuring that it is in a usable state.
// NOTE: we do not create the folder if it does not exist!
// Setting it up in a properly protected location (e.g., with automatic
// backups to iCloud/Google disabled) is the responsibility of the user.
func (s *storage) EnsureStorageExists() error {
	if err := AssertPathExists(s.storagePath); err != nil {
		return err
	}
	return ensureDirectoryExists(s.path(signaturesDir))
}

func (s *storage) load(dest interface{}, path string) (err error) {
	exists, err := PathExists(s.path(path))
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
	return saveFile(s.path(file), bts)
}

func (s *storage) signatureFilename(attrs *AttributeList) string {
	// We take the SHA256 hash over all attributes as the filename for the signature.
	// This means that the signatures of two credentials that have identical attributes
	// will be written to the same file, one overwriting the other - but that doesn't
	// matter, because either one of the signatures is valid over both attribute lists,
	// so keeping one of them suffices.
	return signaturesDir + "/" + attrs.hash()
}

func (s *storage) DeleteSignature(attrs *AttributeList) error {
	return os.Remove(s.path(s.signatureFilename(attrs)))
}

func (s *storage) StoreSignature(cred *credential) error {
	return s.store(cred.Signature, s.signatureFilename(cred.AttributeList()))
}

func (s *storage) StoreSecretKey(sk *secretKey) error {
	return s.store(sk, skFile)
}

func (s *storage) StoreAttributes(attributes map[CredentialTypeIdentifier][]*AttributeList) error {
	temp := []*AttributeList{}
	for _, attrlistlist := range attributes {
		for _, attrlist := range attrlistlist {
			temp = append(temp, attrlist)
		}
	}

	return s.store(temp, attributesFile)
}

func (s *storage) StoreKeyshareServers(keyshareServers map[SchemeManagerIdentifier]*keyshareServer) (err error) {
	return s.store(keyshareServers, kssFile)
}

func (s *storage) StorePaillierKeys(key *paillierPrivateKey) (err error) {
	return s.store(key, paillierFile)
}

func (s *storage) StoreLogs(logs []*LogEntry) (err error) {
	return s.store(logs, logsFile)
}

func (s *storage) StoreUpdates(updates []update) (err error) {
	return s.store(updates, updatesFile)
}

func (s *storage) LoadSignature(attrs *AttributeList) (signature *gabi.CLSignature, err error) {
	sigpath := s.signatureFilename(attrs)
	if err := AssertPathExists(s.path(sigpath)); err != nil {
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

func (s *storage) LoadAttributes() (list map[CredentialTypeIdentifier][]*AttributeList, err error) {
	// The attributes are stored as a list of instances of AttributeList
	temp := []*AttributeList{}
	if err = s.load(&temp, attributesFile); err != nil {
		return
	}

	list = make(map[CredentialTypeIdentifier][]*AttributeList)
	for _, attrlist := range temp {
		attrlist.MetadataAttribute = MetadataFromInt(attrlist.Ints[0], s.ConfigurationStore)
		id := attrlist.CredentialType()
		var ct CredentialTypeIdentifier
		if id != nil {
			ct = id.Identifier()
		}
		if _, contains := list[ct]; !contains {
			list[ct] = []*AttributeList{}
		}
		list[ct] = append(list[ct], attrlist)
	}

	return list, nil
}

func (s *storage) LoadKeyshareServers() (ksses map[SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[SchemeManagerIdentifier]*keyshareServer)
	if err := s.load(&ksses, kssFile); err != nil {
		return nil, err
	}
	return ksses, nil
}

func (s *storage) LoadPaillierKeys() (key *paillierPrivateKey, err error) {
	key = new(paillierPrivateKey)
	if err := s.load(key, paillierFile); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *storage) LoadLogs() (logs []*LogEntry, err error) {
	logs = []*LogEntry{}
	if err := s.load(&logs, logsFile); err != nil {
		return nil, err
	}
	return logs, nil
}

func (s *storage) LoadUpdates() (updates []update, err error) {
	updates = []update{}
	if err := s.load(&updates, updatesFile); err != nil {
		return nil, err
	}
	return updates, nil
}
