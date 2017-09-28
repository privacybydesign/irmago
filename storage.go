package irmago

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"html"
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
	kssFile        = "kss"
	paillierFile   = "paillier"
	signaturesDir  = "sigs"
	cardemuXML     = "../cardemu.xml"
)

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

// NewCredentialManager deserializes the credentials from storage.
func NewCredentialManager(
	storagePath string,
	irmaConfigurationPath string,
	keyshareHandler KeyshareHandler,
) (*CredentialManager, error) {
	var err error
	cm := &CredentialManager{
		credentials:     make(map[CredentialTypeIdentifier]map[int]*credential),
		keyshareServers: make(map[SchemeManagerIdentifier]*keyshareServer),
	}

	if err = MetaStore.ParseFolder(irmaConfigurationPath); err != nil {
		return nil, err
	}

	cm.storagePath = storagePath
	if err = cm.ensureStorageExists(); err != nil {
		return nil, err
	}
	if cm.secretkey, err = cm.loadSecretKey(); err != nil {
		return nil, err
	}
	if cm.attributes, err = cm.loadAttributes(); err != nil {
		return nil, err
	}
	if cm.paillierKeyCache, err = cm.loadPaillierKeys(); err != nil {
		return nil, err
	}
	if cm.keyshareServers, err = cm.loadKeyshareServers(); err != nil {
		return nil, err
	}

	unenrolled := cm.unenrolledKeyshareServers()
	switch len(unenrolled) {
	case 0: // nop
	case 1:
		if keyshareHandler == nil {
			return nil, errors.New("Keyshare server found but no KeyshareHandler was given")
		}
		keyshareHandler.StartRegistration(unenrolled[0], func(email, pin string) {
			cm.KeyshareEnroll(unenrolled[0].Identifier(), email, pin)
		})
	default:
		return nil, errors.New("Too many keyshare servers")
	}

	return cm, nil
}

// ParseAndroidStorage parses an Android cardemu.xml shared preferences file
// from the old Android IRMA app, parsing its credentials into the current instance,
// and saving them to storage.
// CAREFUL: this method overwrites any existing secret keys and attributes on storage.
func (cm *CredentialManager) ParseAndroidStorage() (err error) {
	exists, err := PathExists(cm.path(cardemuXML))
	if err != nil {
		return
	}
	if !exists {
		return errors.New("cardemu.xml not found at " + cardemuXML)
	}

	bytes, err := ioutil.ReadFile(cm.path(cardemuXML))
	if err != nil {
		return
	}
	parsedxml := struct {
		Strings []struct {
			Name    string `xml:"name,attr"`
			Content string `xml:",chardata"`
		} `xml:"string"`
	}{}
	xml.Unmarshal(bytes, &parsedxml)

	parsedjson := make(map[string][]*gabi.Credential)
	cm.keyshareServers = make(map[SchemeManagerIdentifier]*keyshareServer)
	for _, xmltag := range parsedxml.Strings {
		if xmltag.Name == "credentials" {
			jsontag := html.UnescapeString(xmltag.Content)
			if err = json.Unmarshal([]byte(jsontag), &parsedjson); err != nil {
				return
			}
		}
		if xmltag.Name == "keyshare" {
			jsontag := html.UnescapeString(xmltag.Content)
			if err = json.Unmarshal([]byte(jsontag), &cm.keyshareServers); err != nil {
				return
			}
		}
		if xmltag.Name == "KeyshareKeypairs" {
			jsontag := html.UnescapeString(xmltag.Content)
			keys := make([]*paillierPrivateKey, 0, 3)
			if err = json.Unmarshal([]byte(jsontag), &keys); err != nil {
				return
			}
			cm.paillierKeyCache = keys[0]
		}
	}

	for _, list := range parsedjson {
		cm.secretkey = list[0].Attributes[0]
		for _, gabicred := range list {
			cred := newCredential(gabicred)
			if cred.CredentialType() == nil {
				return errors.New("cannot add unknown credential type")
			}

			err = cm.addCredential(cred, false)
			if err != nil {
				return err
			}
		}
	}

	if len(cm.credentials) > 0 {
		err = cm.storeAttributes()
		if err != nil {
			return err
		}
		err = cm.storeSecretKey(cm.secretkey)
		if err != nil {
			return err
		}
	}

	if len(cm.keyshareServers) > 0 {
		err = cm.storeKeyshareServers()
		if err != nil {
			return err
		}
	}

	err = cm.storePaillierKeys()
	if err != nil {
		return err
	}
	if cm.paillierKeyCache == nil {
		cm.paillierKey(false) // trigger calculating a new one
	}

	return
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
	attrbytes, err := json.Marshal(cm.attributes)
	if err != nil {
		return err
	}

	// TODO existence check
	err = ioutil.WriteFile(cm.path(attributesFile), attrbytes, 0600)
	return
}

func (cm *CredentialManager) storeKeyshareServers() (err error) {
	bts, err := json.Marshal(cm.keyshareServers)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(cm.path(kssFile), bts, 0600)
	return
}

func (cm *CredentialManager) storePaillierKeys() (err error) {
	bts, err := json.Marshal(cm.paillierKeyCache)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(cm.path(paillierFile), bts, 0600)
	return
}

func (cm *CredentialManager) loadSignature(id CredentialTypeIdentifier, counter int) (signature *gabi.CLSignature, err error) {
	sigpath := cm.signatureFilename(id.String(), counter)
	exists, err := PathExists(sigpath)
	if err != nil {
		return
	}
	if !exists {
		return nil, errors.New("Signature file not found")
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
	exists, err := PathExists(cm.path(attributesFile))
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(cm.path(attributesFile))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &list)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func (cm *CredentialManager) loadKeyshareServers() (ksses map[SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[SchemeManagerIdentifier]*keyshareServer)
	exists, err := PathExists(cm.path(kssFile))
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(cm.path(kssFile))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &ksses)
	if err != nil {
		return nil, err
	}
	return
}

func (cm *CredentialManager) loadPaillierKeys() (key *paillierPrivateKey, err error) {
	exists, err := PathExists(cm.path(paillierFile))
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(cm.path(paillierFile))
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
