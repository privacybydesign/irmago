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

// Init deserializes the credentials from storage.
func (cm *CredentialManager) Init(path string, keyshareHandler KeyshareHandler) (err error) {
	cm.storagePath = path

	err = cm.ensureStorageExists()
	if err != nil {
		return err
	}
	cm.secretkey, err = cm.loadSecretKey()
	if err != nil {
		return
	}
	cm.attributes, err = cm.loadAttributes()
	if err != nil {
		return
	}
	cm.paillierKeyCache, err = cm.loadPaillierKeys()
	if err != nil {
		return
	}

	cm.keyshareServers, err = cm.loadKeyshareServers()
	if err != nil {
		return
	}

	unenrolled := cm.unenrolledKeyshareServers()
	switch len(unenrolled) {
	case 0:
		return
	case 1:
		if keyshareHandler == nil {
			return errors.New("Keyshare server found but no KeyshareHandler was given")
		}
		keyshareHandler.StartRegistration(unenrolled[0], func(email, pin string) {
			cm.KeyshareEnroll(unenrolled[0].Identifier(), email, pin)
		})
	default:
		return errors.New("Too many keyshare servers")
	}

	return nil
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
	parsedksses := make(map[string]*keyshareServer)
	for _, xmltag := range parsedxml.Strings {
		if xmltag.Name == "credentials" {
			jsontag := html.UnescapeString(xmltag.Content)
			if err = json.Unmarshal([]byte(jsontag), &parsedjson); err != nil {
				return
			}
		}
		if xmltag.Name == "keyshare" {
			jsontag := html.UnescapeString(xmltag.Content)
			if err = json.Unmarshal([]byte(jsontag), &parsedksses); err != nil {
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

	for name, kss := range parsedksses {
		cm.keyshareServers[NewSchemeManagerIdentifier(name)] = kss
	}

	for _, list := range parsedjson {
		cm.secretkey = list[0].Attributes[0]
		for i, gabicred := range list {
			cred := newCredential(gabicred)
			if cred.CredentialType() == nil {
				return errors.New("cannot add unknown credential type")
			}

			cm.addCredential(cred)
			err = cm.storeSignature(cred, i)
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

func (cm *CredentialManager) storeKeyshareServers() (err error) {
	temp := make(map[string]*keyshareServer)
	for name, kss := range cm.keyshareServers {
		temp[name.String()] = kss
	}
	bts, err := json.Marshal(temp)
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
	if err != nil || !exists {
		return
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

func (cm *CredentialManager) loadKeyshareServers() (ksses map[SchemeManagerIdentifier]*keyshareServer, err error) {
	ksses = make(map[SchemeManagerIdentifier]*keyshareServer)
	temp := make(map[string]*keyshareServer)

	exists, err := PathExists(cm.path(kssFile))
	if err != nil || !exists {
		return
	}
	bytes, err := ioutil.ReadFile(cm.path(kssFile))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &temp)
	if err != nil {
		return nil, err
	}
	for name, kss := range temp {
		ksses[NewSchemeManagerIdentifier(name)] = kss
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
