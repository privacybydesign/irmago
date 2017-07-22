package irmago

import (
	"errors"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/mhe/gabi"
)

const (
	skFile         = "sk"
	attributesFile = "attrs"
	signaturesDir  = "sigs"
)

// CredentialManager manages credentials.
type CredentialManager struct {
	secretkey   *big.Int
	storagePath string
	attributes  map[string][]AttributeList
	signatures  map[string][]*gabi.CLSignature
}

func pathExists(path string) (bool, error) {
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

func (cm *CredentialManager) ensureStorageExists() (err error) {
	exist, err := pathExists(cm.storagePath)
	if err != nil {
		return
	}
	if !exist {
		return errors.New("credential storage path does not exist")
	}

	var file *os.File
	exist, err = pathExists(cm.path(skFile))
	if err != nil {
		return
	}
	if !exist {
		sk := big.NewInt(1) // TODO
		file, err = os.Create(cm.path(skFile))
		if err != nil {
			return
		}
		defer file.Close()
		_, err = file.Write(sk.Bytes())
		if err != nil {
			return
		}
	}

	exist, err = pathExists(cm.path(attributesFile))
	if err != nil {
		return err
	}
	if !exist {
		file, err = os.Create(cm.path(attributesFile))
		if err != nil {
			return
		}
		defer file.Close()
		_, err = file.Write([]byte("{}"))
		if err != nil {
			return
		}
	}

	return nil
}

func (cm *CredentialManager) init(path string) (err error) {
	cm.storagePath = path

	cm.ensureStorageExists()

	bytes, err := ioutil.ReadFile(cm.path(skFile))
	if err != nil {
		return
	}
	cm.secretkey = new(big.Int).SetBytes(bytes)

	return
}
