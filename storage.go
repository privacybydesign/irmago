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

func generateSecretKey() (*secretKey, error) {
	key, err := gabi.RandomBigInt(gabi.DefaultSystemParameters[1024].Lm)
	if err != nil {
		return nil, err
	}
	return &secretKey{Key: key}, nil
}

func (s *storage) path(p string) string {
	return s.storagePath + "/" + p
}

func (s *storage) signatureFilename(attrs *AttributeList) string {
	// We take the SHA256 hash over all attributes as the filename for the signature.
	// This means that the signatures of two credentials that have identical attributes
	// will be written to the same file, one overwriting the other - but that doesn't
	// matter, because either one of the signatures is valid over both attribute lists,
	// so keeping one of them suffices.
	return s.path(signaturesDir) + "/" + attrs.hash()
}

// ensureStorageExists initializes the credential storage folder,
// ensuring that it is in a usable state.
// NOTE: we do not create the folder if it does not exist!
// Setting it up in a properly protected location (e.g., with automatic
// backups to iCloud/Google disabled) is the responsibility of the user.
func (s *storage) ensureStorageExists() error {
	if err := AssertPathExists(s.storagePath); err != nil {
		return err
	}
	return ensureDirectoryExists(s.path(signaturesDir))
}

func (s *storage) storeSecretKey(sk *secretKey) error {
	bytes, err := json.Marshal(sk)
	if err != nil {
		return err
	}
	return saveFile(s.path(skFile), bytes)
}

func (s *storage) storeSignature(cred *credential) (err error) {
	if cred.CredentialType() == nil {
		return errors.New("cannot add unknown credential type")
	}

	credbytes, err := json.Marshal(cred.Signature)
	if err != nil {
		return err
	}

	filename := s.signatureFilename(cred.AttributeList())
	err = saveFile(filename, credbytes)
	return
}

func (s *storage) storeAttributes(attributes map[CredentialTypeIdentifier][]*AttributeList) error {
	temp := []*AttributeList{}
	for _, attrlistlist := range attributes {
		for _, attrlist := range attrlistlist {
			temp = append(temp, attrlist)
		}
	}

	if attrbytes, err := json.Marshal(temp); err == nil {
		return saveFile(s.path(attributesFile), attrbytes)
	} else {
		return err
	}
}

func (s *storage) storeKeyshareServers(keyshareServers map[SchemeManagerIdentifier]*keyshareServer) (err error) {
	bts, err := json.Marshal(keyshareServers)
	if err != nil {
		return
	}
	err = saveFile(s.path(kssFile), bts)
	return
}

func (s *storage) storePaillierKeys(key *paillierPrivateKey) (err error) {
	bts, err := json.Marshal(key)
	if err != nil {
		return
	}
	err = saveFile(s.path(paillierFile), bts)
	return
}

func (s *storage) storeLogs(logs []*LogEntry) (err error) {
	bts, err := json.Marshal(logs)
	if err != nil {
		return
	}
	err = saveFile(s.path(logsFile), bts)
	return
}

func (s *storage) storeUpdates(updates []update) (err error) {
	bts, err := json.Marshal(updates)
	if err != nil {
		return
	}
	err = saveFile(s.path(updatesFile), bts)
	return
}

func (s *storage) loadSignature(attrs *AttributeList) (signature *gabi.CLSignature, err error) {
	sigpath := s.signatureFilename(attrs)
	if err := AssertPathExists(sigpath); err != nil {
		return nil, err
	}
	bytes, err := ioutil.ReadFile(sigpath)
	if err != nil {
		return
	}
	signature = new(gabi.CLSignature)
	err = json.Unmarshal(bytes, signature)
	return
}

// loadSecretKey retrieves and returns the secret key from storage, or if no secret key
// was found in storage, it generates, saves, and returns a new secret key.
func (s *storage) loadSecretKey() (*secretKey, error) {
	sk := &secretKey{}
	var err error
	exists, err := PathExists(s.path(skFile))
	if err != nil {
		return nil, err
	}
	if exists {
		var bytes []byte
		if bytes, err = ioutil.ReadFile(s.path(skFile)); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(bytes, sk); err != nil {
			return nil, err
		}
		return sk, err
	}

	sk, err = generateSecretKey()
	if err != nil {
		return nil, err
	}
	err = s.storeSecretKey(sk)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func (s *storage) loadAttributes() (list map[CredentialTypeIdentifier][]*AttributeList, err error) {
	exists, err := PathExists(s.path(attributesFile))
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(s.path(attributesFile))
	if err != nil {
		return nil, err
	}

	// The attributes are stored as a list of instances of AttributeList
	temp := []*AttributeList{}
	list = make(map[CredentialTypeIdentifier][]*AttributeList)
	if err = json.Unmarshal(bytes, &temp); err != nil {
		return nil, err
	}
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

func (s *storage) loadKeyshareServers() (ksses map[SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[SchemeManagerIdentifier]*keyshareServer)
	exists, err := PathExists(s.path(kssFile))
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(s.path(kssFile))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &ksses)
	if err != nil {
		return nil, err
	}
	return
}

func (s *storage) loadPaillierKeys() (key *paillierPrivateKey, err error) {
	exists, err := PathExists(s.path(paillierFile))
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(s.path(paillierFile))
	if err != nil {
		return nil, err
	}
	key = new(paillierPrivateKey)
	err = json.Unmarshal(bytes, key)
	if err != nil {
		return nil, err
	}
	return
}

func (s *storage) loadLogs() (logs []*LogEntry, err error) {
	logs = []*LogEntry{}
	exists, err := PathExists(s.path(logsFile))
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(s.path(logsFile))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &logs)
	if err != nil {
		return nil, err
	}
	return
}

func (s *storage) loadUpdates() (updates []update, err error) {
	updates = []update{}
	exists, err := PathExists(s.path(updatesFile))
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(s.path(updatesFile))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &updates)
	if err != nil {
		return nil, err
	}
	return
}
