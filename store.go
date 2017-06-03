package irmago

import (
	"encoding/xml"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/mhe/gabi"
)

// MetaStore is the global instance of ConfigurationStore
var MetaStore = ConfigurationStore{
	make(map[string]*SchemeManagerDescription),
	make(map[string]*IssuerDescription),
	make(map[string]*CredentialDescription),
	make(map[string]*gabi.PublicKey),
}

// ConfigurationStore ...
type ConfigurationStore struct {
	managers    map[string]*SchemeManagerDescription
	issuers     map[string]*IssuerDescription
	credentials map[string]*CredentialDescription
	publickeys  map[string]*gabi.PublicKey
}

// ParseFolder populates the current store by parsing the specified irma_configuration folder,
// listing the containing scheme managers, issuers, credential types and public keys.
func (store *ConfigurationStore) ParseFolder(path string) error {
	return iterateSubfolders(path, func(dir string) error {
		manager := &SchemeManagerDescription{}
		exists, err := pathToDescription(dir+"/description.xml", manager)
		if err != nil {
			return err
		}
		if exists {
			MetaStore.managers[manager.Name] = manager
			return store.parseIssuerFolders(dir)
		}
		return nil
	})
}

func (store *ConfigurationStore) parseIssuerFolders(path string) error {
	return iterateSubfolders(path, func(dir string) error {
		issuer := &IssuerDescription{}
		exists, err := pathToDescription(dir+"/description.xml", issuer)
		if err != nil {
			return err
		}
		if exists {
			store.issuers[issuer.Identifier().string] = issuer
			if err = store.parseCredentialsFolder(dir + "/Issues/"); err != nil {
				return err
			}
			return store.parseKeysFolder(issuer.Identifier(), dir+"/PublicKeys/")
		}
		return nil
	})
}

func (store *ConfigurationStore) parseKeysFolder(issuer *IssuerIdentifier, path string) error {
	for i := 0; ; i++ {
		file := path + strconv.Itoa(i) + ".xml"
		if _, err := os.Stat(file); err != nil {
			break
		}
		pk, err := gabi.NewPublicKeyFromFile(file)
		if err != nil {
			return err
		}
		MetaStore.publickeys[issuer.string] = pk
	}
	return nil
}

func (store *ConfigurationStore) parseCredentialsFolder(path string) error {
	return iterateSubfolders(path, func(dir string) error {
		cred := &CredentialDescription{}
		exists, err := pathToDescription(dir+"/description.xml", cred)
		if err != nil {
			return err
		}
		if exists {
			store.credentials[cred.Identifier().string] = cred
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
