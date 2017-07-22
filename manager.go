package irmago

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"html"
	"io/ioutil"
	"math/big"

	"github.com/mhe/gabi"
)

// Manager is the global instance of CredentialManager.
var Manager = CredentialManager{
	attributes:  make(map[string][]*AttributeList),
	credentials: make(map[string][]*gabi.Credential),
}

// CredentialManager manages credentials.
type CredentialManager struct {
	secretkey   *big.Int
	storagePath string
	attributes  map[string][]*AttributeList
	credentials map[string][]*gabi.Credential
}

func (cm *CredentialManager) generateSecretKey() (err error) {
	cm.secretkey, err = gabi.RandomBigInt(gabi.DefaultSystemParameters[1024].Lm)
	return
}

// Init deserializes the credentials from storage.
func (cm *CredentialManager) Init(path string) (err error) {
	cm.storagePath = path

	cm.ensureStorageExists()

	bytes, err := ioutil.ReadFile(cm.path(skFile))
	if err != nil {
		return
	}
	cm.secretkey = new(big.Int).SetBytes(bytes)

	return
}

// ParseAndroidStorage parses an Android cardemu.xml shared preferences file
// from the old Android IRMA app, parsing its credentials into the current instance.
func (cm *CredentialManager) ParseAndroidStorage() (err error) {
	exists, err := pathExists(cm.path(cardemuXML))
	if err != nil || !exists {
		return
	}

	bytes, err := ioutil.ReadFile(cm.path(cardemuXML))
	parsed := struct {
		Strings []struct {
			Name    string `xml:"name,attr"`
			Content string `xml:",chardata"`
		} `xml:"string"`
	}{}
	xml.Unmarshal(bytes, &parsed)

	for _, xmltag := range parsed.Strings {
		if xmltag.Name == "credentials" {
			jsontag := html.UnescapeString(xmltag.Content)
			if err = json.Unmarshal([]byte(jsontag), &cm.credentials); err != nil {
				return
			}
		}
	}

	for _, list := range cm.credentials {
		if list != nil && len(list) > 0 {
			cm.secretkey = list[0].Attributes[0]
		}
		for i, cred := range list {
			// TODO move this metadata initialisation somehow into gabi.Credential?
			cred.MetadataAttribute = gabi.MetadataFromInt(cred.Attributes[1])
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
		err = cm.storeKey()
		if err != nil {
			return err
		}
	}

	return
}

func (cm *CredentialManager) addCredential(cred *gabi.Credential) {
	id := cred.CredentialType().Identifier()
	if _, exists := cm.attributes[id]; !exists {
		cm.attributes[id] = make([]*AttributeList, 0, 1)
	}
	cm.attributes[id] = append(cm.attributes[id], NewAttributeListFromInts(cred.Attributes[1:]))

	if _, exists := cm.credentials[id]; !exists {
		cm.credentials[id] = make([]*gabi.Credential, 0, 1)
	}
	cm.credentials[id] = append(cm.credentials[id], cred)
}

// Add adds the specified credential to the CredentialManager.
func (cm *CredentialManager) Add(cred *gabi.Credential) (err error) {
	if cred.CredentialType() == nil {
		return errors.New("cannot add unknown credential type")
	}

	cm.addCredential(cred)
	counter := len(cm.credentials) - 1

	err = cm.storeSignature(cred, counter)
	if err != nil {
		return
	}
	err = cm.storeAttributes()
	return
}
