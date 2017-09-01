package irmago

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"strconv"

	"crypto/rand"
	"encoding/hex"
	"math/big"
	"path"

	"github.com/mhe/gabi"
)

// Filenames in which we store stuff
const (
	skFile         = "sk"
	attributesFile = "attrs"
	signaturesDir  = "sigs"
	cardemuXML     = "../cardemu.xml"
)

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

func (cm *CredentialManager) path(file string) string {
	return cm.storagePath + "/" + file
}

func (cm *CredentialManager) signatureFilename(id string, counter int) string {
	return cm.path(signaturesDir) + "/" + id + "-" + strconv.Itoa(counter)
}

// ensureStorageExists initializes the credential storage folder,
// ensuring that it is in a usable state.
// NOTE: we do not create the folder if it does not exist!
// Setting it up in a properly protected location (e.g., with automatic
// backups to iCloud/Google disabled) is the responsibility of the user.
func (cm *CredentialManager) ensureStorageExists() (err error) {
	exist, err := PathExists(cm.storagePath)
	if err != nil {
		return
	}
	if !exist {
		return errors.New("credential storage path does not exist")
	}

	exist, err = PathExists(cm.path(signaturesDir))
	if err != nil {
		return err
	}
	if !exist {
		err = os.Mkdir(cm.path(signaturesDir), 0700)
	}

	return
}

func (cm *CredentialManager) storeSecretKey(sk *big.Int) error {
	return ioutil.WriteFile(cm.path(skFile), sk.Bytes(), 0600)
}

// Save the filecontents at the specified path atomically:
// - first save the content in a temp file with a random filename in the same dir
// - then rename the temp file to the specified filepath, overwriting the old file
func (cm *CredentialManager) saveFile(filepath string, content []byte) (err error) {
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

func (cm *CredentialManager) storeSignature(cred *credential, counter int) (err error) {
	if cred.CredentialType() == nil {
		return errors.New("cannot add unknown credential type")
	}

	credbytes, err := json.Marshal(cred.Signature)
	if err != nil {
		return err
	}

	// TODO existence check
	filename := cm.signatureFilename(cred.CredentialType().Identifier().String(), counter)
	err = ioutil.WriteFile(filename, credbytes, 0600)
	return
}

func (cm *CredentialManager) storeAttributes() (err error) {
	// Unfortunately, the type of cm.attributes (map[CredentialTypeIdentifier][]*AttributeList)
	// cannot be passed directly to json.Marshal(), so we copy it into a temp list.
	temp := make(map[string][]*AttributeList)
	for credid, list := range cm.attributes {
		temp[credid.String()] = list
	}
	attrbytes, err := json.Marshal(temp)
	if err != nil {
		return err
	}

	// TODO existence check
	err = ioutil.WriteFile(cm.path(attributesFile), attrbytes, 0600)
	return
}

func (cm *CredentialManager) loadSignature(id CredentialTypeIdentifier, counter int) (signature *gabi.CLSignature, err error) {
	path := cm.signatureFilename(id.String(), counter)
	exists, err := PathExists(path)
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	signature = new(gabi.CLSignature)
	err = json.Unmarshal(bytes, signature)
	return
}

// loadSecretKey retrieves and returns the secret key from storage, or if no secret key
// was found in storage, it generates, saves, and returns a new secret key.
func (cm *CredentialManager) loadSecretKey() (*big.Int, error) {
	exists, err := PathExists(cm.path(skFile))
	if err != nil {
		return nil, err
	}
	if exists {
		var bytes []byte
		if bytes, err = ioutil.ReadFile(cm.path(skFile)); err == nil {
			return new(big.Int).SetBytes(bytes), nil
		}
		return nil, err
	}

	sk, err := cm.generateSecretKey()
	if err != nil {
		return nil, err
	}
	err = cm.storeSecretKey(sk)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func (cm *CredentialManager) loadAttributes() (list map[CredentialTypeIdentifier][]*AttributeList, err error) {
	list = make(map[CredentialTypeIdentifier][]*AttributeList)
	temp := make(map[string][]*AttributeList)

	exists, err := PathExists(cm.path(attributesFile))
	if err != nil || !exists {
		return
	}

	bytes, err := ioutil.ReadFile(cm.path(attributesFile))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &temp)
	if err != nil {
		return nil, err
	}

	for credid, attrs := range temp {
		list[NewCredentialTypeIdentifier(credid)] = attrs
	}
	return list, nil
}
