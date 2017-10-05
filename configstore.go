package irmago

import (
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"crypto/sha256"

	"fmt"

	"strings"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

// ConfigurationStore keeps track of scheme managers, issuers, credential types and public keys.
type ConfigurationStore struct {
	SchemeManagers map[SchemeManagerIdentifier]*SchemeManager
	Issuers        map[IssuerIdentifier]*Issuer
	Credentials    map[CredentialTypeIdentifier]*CredentialType

	publicKeys    map[IssuerIdentifier][]*gabi.PublicKey
	reverseHashes map[string]CredentialTypeIdentifier
	path          string
	initialized   bool
}

// NewConfigurationStore returns a new configuration store. After this
// ParseFolder() should be called to parse the specified path.
func NewConfigurationStore(path string, assets string) (store *ConfigurationStore, err error) {
	store = &ConfigurationStore{
		path: path,
	}

	var exist bool
	if exist, err = PathExists(store.path); err != nil {
		return nil, err
	}
	if !exist {
		if err = ensureDirectoryExists(store.path); err != nil {
			return nil, err
		}
		if assets != "" {
			if err = store.Copy(assets, false); err != nil {
				return nil, err
			}
		}
	}

	return
}

// ParseFolder populates the current store by parsing the storage path,
// listing the containing scheme managers, issuers and credential types.
func (store *ConfigurationStore) ParseFolder() error {
	// Init all maps
	store.SchemeManagers = make(map[SchemeManagerIdentifier]*SchemeManager)
	store.Issuers = make(map[IssuerIdentifier]*Issuer)
	store.Credentials = make(map[CredentialTypeIdentifier]*CredentialType)
	store.publicKeys = make(map[IssuerIdentifier][]*gabi.PublicKey)
	store.reverseHashes = make(map[string]CredentialTypeIdentifier)

	err := iterateSubfolders(store.path, func(dir string) error {
		manager := &SchemeManager{}
		exists, err := pathToDescription(dir+"/description.xml", manager)
		if err != nil {
			return err
		}
		if exists {
			store.SchemeManagers[manager.Identifier()] = manager
			return store.parseIssuerFolders(dir)
		}
		return nil
	})
	if err != nil {
		return err
	}
	store.initialized = true
	return nil
}

// PublicKey returns the specified public key, or nil if not present in the ConfigurationStore.
func (store *ConfigurationStore) PublicKey(id IssuerIdentifier, counter int) (*gabi.PublicKey, error) {
	if _, contains := store.publicKeys[id]; !contains {
		store.publicKeys[id] = []*gabi.PublicKey{}
		err := store.parseKeysFolder(id)
		if err != nil {
			return nil, err
		}
	}

	list := store.publicKeys[id]
	if len(list) > counter {
		return list[counter], nil
	}

	return nil, nil
}

func (store *ConfigurationStore) addReverseHash(credid CredentialTypeIdentifier) {
	hash := sha256.Sum256([]byte(credid.String()))
	store.reverseHashes[base64.StdEncoding.EncodeToString(hash[:16])] = credid
}

func (store *ConfigurationStore) hashToCredentialType(hash []byte) *CredentialType {
	if str, exists := store.reverseHashes[base64.StdEncoding.EncodeToString(hash)]; exists {
		return store.Credentials[str]
	}
	return nil
}

// IsInitialized indicates whether this instance has successfully been initialized.
func (store *ConfigurationStore) IsInitialized() bool {
	return store.initialized
}

func (store *ConfigurationStore) parseIssuerFolders(path string) error {
	return iterateSubfolders(path, func(dir string) error {
		issuer := &Issuer{}
		exists, err := pathToDescription(dir+"/description.xml", issuer)
		if err != nil {
			return err
		}
		if exists {
			store.Issuers[issuer.Identifier()] = issuer
			if err = store.parseCredentialsFolder(dir + "/Issues/"); err != nil {
				return err
			}
		}
		return nil
	})
}

func (store *ConfigurationStore) parseKeysFolder(issuerid IssuerIdentifier) error {
	issuer := store.Issuers[issuerid]
	path := store.path + "/" +
		issuer.Identifier().SchemeManagerIdentifier().String() +
		"/" + issuer.ID + "/PublicKeys/"

	for i := 0; ; i++ {
		file := path + strconv.Itoa(i) + ".xml"
		if _, err := os.Stat(file); err != nil {
			break
		}
		pk, err := gabi.NewPublicKeyFromFile(file)
		if err != nil {
			return err
		}
		pk.Issuer = issuer.Identifier().String()
		store.publicKeys[issuer.Identifier()] = append(store.publicKeys[issuer.Identifier()], pk)
	}
	return nil
}

func (store *ConfigurationStore) parseCredentialsFolder(path string) error {
	return iterateSubfolders(path, func(dir string) error {
		cred := &CredentialType{}
		exists, err := pathToDescription(dir+"/description.xml", cred)
		if err != nil {
			return err
		}
		if exists {
			credid := cred.Identifier()
			store.Credentials[credid] = cred
			store.addReverseHash(credid)
		}
		return nil
	})
}

// iterateSubfolders iterates over the subfolders of the specified path,
// calling the specified handler each time. If anything goes wrong, or
// if the caller returns a non-nil error, an error is immediately returned.
func iterateSubfolders(path string, handler func(string) error) error {
	dirs, err := filepath.Glob(path + "/*")
	if err != nil {
		return err
	}

	for _, dir := range dirs {
		stat, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if !stat.IsDir() {
			continue
		}
		err = handler(dir)
		if err != nil {
			return err
		}
	}

	return nil
}

func pathToDescription(path string, description interface{}) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return false, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return true, err
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return true, err
	}

	err = xml.Unmarshal(bytes, description)
	if err != nil {
		return true, err
	}

	return true, nil
}

// Contains checks if the store contains the specified credential type.
func (store *ConfigurationStore) Contains(cred CredentialTypeIdentifier) bool {
	return store.SchemeManagers[cred.IssuerIdentifier().SchemeManagerIdentifier()] != nil &&
		store.Issuers[cred.IssuerIdentifier()] != nil &&
		store.Credentials[cred] != nil
}

func (store *ConfigurationStore) Copy(source string, parse bool) error {
	if err := ensureDirectoryExists(store.path); err != nil {
		return err
	}

	err := filepath.Walk(source, filepath.WalkFunc(
		func(path string, info os.FileInfo, err error) error {
			if path == source {
				return nil
			}
			subpath := path[len(source):]
			if info.IsDir() {
				if err := ensureDirectoryExists(store.path + subpath); err != nil {
					return err
				}
			} else {
				srcfile, err := os.Open(path)
				if err != nil {
					return err
				}
				defer srcfile.Close()
				bytes, err := ioutil.ReadAll(srcfile)
				if err != nil {
					return err
				}
				if err := saveFile(store.path+subpath, bytes); err != nil {
					return err
				}
			}
			return nil
		}),
	)

	if err != nil {
		return err
	}
	if parse {
		return store.ParseFolder()
	}
	return nil
}

func (store *ConfigurationStore) DownloadSchemeManager(url string) (*SchemeManager, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	if url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	if strings.HasSuffix(url, "/description.xml") {
		url = url[:len(url)-len("/description.xml")]
	}
	b, err := NewHTTPTransport(url).GetBytes("/description.xml")
	if err != nil {
		return nil, err
	}
	manager := &SchemeManager{}
	if err = xml.Unmarshal(b, manager); err != nil {
		return nil, err
	}

	manager.URL = url // TODO?
	return manager, nil
}

func (store *ConfigurationStore) RemoveSchemeManager(id SchemeManagerIdentifier) error {
	// Remove everything falling under the manager's responsibility
	for credid := range store.Credentials {
		if credid.IssuerIdentifier().SchemeManagerIdentifier() == id {
			delete(store.Credentials, credid)
		}
	}
	for issid := range store.Issuers {
		if issid.SchemeManagerIdentifier() == id {
			delete(store.Issuers, issid)
		}
	}
	for issid := range store.publicKeys {
		if issid.SchemeManagerIdentifier() == id {
			delete(store.publicKeys, issid)
		}
	}
	// Remove from storage
	return os.RemoveAll(fmt.Sprintf("%s/%s", store.path, id.String()))
	// or, remove above iterations and call .ParseFolder()?
}

func (store *ConfigurationStore) AddSchemeManager(manager *SchemeManager) error {
	name := manager.ID
	if err := ensureDirectoryExists(fmt.Sprintf("%s/%s", store.path, name)); err != nil {
		return err
	}
	b, err := xml.Marshal(manager)
	if err != nil {
		return err
	}
	if err := saveFile(fmt.Sprintf("%s/%s/description.xml", store.path, name), b); err != nil {
		return err
	}
	store.SchemeManagers[NewSchemeManagerIdentifier(name)] = manager
	return nil
}

func (store *ConfigurationStore) Download(set *IrmaIdentifierSet) error {
	var contains bool
	for manid := range set.SchemeManagers {
		if _, contains = store.SchemeManagers[manid]; !contains {
			return errors.Errorf("Unknown scheme manager: %s", manid)
		}
	}

	transport := NewHTTPTransport("")
	for issid := range set.Issuers {
		if _, contains = store.Issuers[issid]; !contains {
			url := store.SchemeManagers[issid.SchemeManagerIdentifier()].URL + "/" + issid.Name()
			path := fmt.Sprintf("%s/%s/%s", store.path, issid.SchemeManagerIdentifier().String(), issid.Name())
			transport.GetFile(url+"/description.xml", path+"/description.xml")
			transport.GetFile(url+"/logo.png", path+"/logo.png")
		}
		for issid, list := range set.PublicKeys {
			for _, count := range list {
				manager := issid.SchemeManagerIdentifier()
				suffix := fmt.Sprintf("/%s/PublicKeys/%d.xml", issid.Name(), count)
				path := fmt.Sprintf("%s/%s/%s", store.path, manager.String(), suffix)
				transport.GetFile(store.SchemeManagers[manager].URL+suffix, path)
			}
		}
	}
	for credid := range set.CredentialTypes {
		if _, contains := store.Credentials[credid]; !contains {
			manager := credid.IssuerIdentifier().SchemeManagerIdentifier()
			suffix := fmt.Sprintf("/%s/Issues/%s/description.xml", credid.IssuerIdentifier().Name(), credid.Name())
			path := fmt.Sprintf("%s/%s/%s", store.path, manager.String(), suffix)
			transport.GetFile(store.SchemeManagers[manager].URL+suffix, path)
		}
	}

	return store.ParseFolder()
}
