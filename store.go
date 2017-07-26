package irmago

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/mhe/gabi"
)

// MetaStore is the global instance of ConfigurationStore
var MetaStore = newConfigurationStore()

// ConfigurationStore keeps track of scheme managers, issuers, credential types and public keys.
// Use the global MetaStore instance.
type ConfigurationStore struct {
	SchemeManagers map[SchemeManagerIdentifier]*SchemeManager
	Issuers        map[IssuerIdentifier]*Issuer
	Credentials    map[CredentialTypeIdentifier]*CredentialType
	PublicKeys     map[IssuerIdentifier][]*gabi.PublicKey

	reverseHashes map[string]CredentialTypeIdentifier
	initialized   bool
}

func newConfigurationStore() (store *ConfigurationStore) {
	store = &ConfigurationStore{
		SchemeManagers: make(map[SchemeManagerIdentifier]*SchemeManager),
		Issuers:        make(map[IssuerIdentifier]*Issuer),
		Credentials:    make(map[CredentialTypeIdentifier]*CredentialType),
		PublicKeys:     make(map[IssuerIdentifier][]*gabi.PublicKey),
		reverseHashes:  make(map[string]CredentialTypeIdentifier),
	}
	return
}

// PublicKey returns the specified public key, or nil if not present in the ConfigurationStore.
func (store *ConfigurationStore) PublicKey(id IssuerIdentifier, counter int) *gabi.PublicKey {
	if list, ok := MetaStore.PublicKeys[id]; ok {
		if len(list) > counter {
			return list[counter]
		}
	}
	return nil
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

// ParseFolder populates the current store by parsing the specified irma_configuration folder,
// listing the containing scheme managers, issuers, credential types and public keys.
func (store *ConfigurationStore) ParseFolder(path string) error {
	err := iterateSubfolders(path, func(dir string) error {
		manager := &SchemeManager{}
		exists, err := pathToDescription(dir+"/description.xml", manager)
		if err != nil {
			return err
		}
		if exists {
			MetaStore.SchemeManagers[manager.Identifier()] = manager
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
			return store.parseKeysFolder(issuer, dir+"/PublicKeys/")
		}
		return nil
	})
}

func (store *ConfigurationStore) parseKeysFolder(issuer *Issuer, path string) error {
	for i := 0; ; i++ {
		file := path + strconv.Itoa(i) + ".xml"
		if _, err := os.Stat(file); err != nil {
			break
		}
		pk, err := gabi.NewPublicKeyFromFile(file)
		if err != nil {
			return err
		}
		MetaStore.PublicKeys[issuer.Identifier()] = append(MetaStore.PublicKeys[issuer.Identifier()], pk)
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
