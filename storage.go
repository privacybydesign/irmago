package irmago

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/mhe/gabi"
)

// Filenames in which we store stuff
const (
	skFile         = "sk"
	attributesFile = "attrs"
	signaturesDir  = "sigs"
	cardemuXML     = "cardemu.xml"
)

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
		err = cm.generateSecretKey()
		if err != nil {
			return
		}
		file, err = os.Create(cm.path(skFile))
		if err != nil {
			return
		}
		defer file.Close()
		_, err = file.Write(cm.secretkey.Bytes())
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

	exist, err = pathExists(cm.path(signaturesDir))
	if err != nil {
		return err
	}
	if !exist {
		err = os.Mkdir(cm.path(signaturesDir), 0700)
	}

	return
}

func (cm *CredentialManager) storeKey() error {
	return ioutil.WriteFile(cm.path(skFile), cm.secretkey.Bytes(), 0600)
}

func (cm *CredentialManager) storeSignature(cred *gabi.Credential, counter int) (err error) {
	if cred.CredentialType() == nil {
		return errors.New("cannot add unknown credential type")
	}

	credbytes, err := json.Marshal(cred.Signature)
	if err != nil {
		return err
	}

	// TODO existence check
	filename := cm.path(signaturesDir) + "/" + cred.CredentialType().Identifier() + "-" + strconv.Itoa(counter)
	err = ioutil.WriteFile(filename, credbytes, 0600)
	return
}

func (cm *CredentialManager) storeAttributes() (err error) {
	attrbytes, err := json.Marshal(cm.attributes)
	if err != nil {
		return
	}

	// TODO existence check
	err = ioutil.WriteFile(cm.path(attributesFile), attrbytes, 0600)
	return
}
