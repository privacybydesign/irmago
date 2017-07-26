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
var Manager = newCredentialManager()

// CredentialManager manages credentials.
type CredentialManager struct {
	secretkey   *big.Int
	storagePath string
	attributes  map[CredentialIdentifier][]*AttributeList
	credentials map[CredentialIdentifier]map[int]*Credential
}

func newCredentialManager() *CredentialManager {
	return &CredentialManager{
		credentials: make(map[CredentialIdentifier]map[int]*Credential),
	}
}

func (cm *CredentialManager) generateSecretKey() (sk *big.Int, err error) {
	return gabi.RandomBigInt(gabi.DefaultSystemParameters[1024].Lm)
}

// Init deserializes the credentials from storage.
func (cm *CredentialManager) Init(path string) (err error) {
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
	return

}

// attrs returns cm.attributes[id], initializing it to an empty slice if neccesary
func (cm *CredentialManager) attrs(id CredentialIdentifier) []*AttributeList {
	list, exists := cm.attributes[id]
	if !exists {
		list = make([]*AttributeList, 0, 1)
		cm.attributes[id] = list
	}
	return list
}

// creds returns cm.credentials[id], initializing it to an empty map if neccesary
func (cm *CredentialManager) creds(id CredentialIdentifier) map[int]*Credential {
	list, exists := cm.credentials[id]
	if !exists {
		list = make(map[int]*Credential)
		cm.credentials[id] = list
	}
	return list
}

// Attributes returns the attribute list of the requested credential, or nil if we do not have it.
func (cm *CredentialManager) Attributes(id CredentialIdentifier, counter int) (attributes *AttributeList) {
	list := cm.attrs(id)
	if len(list) <= counter {
		return
	}
	return list[counter]
}

// Credential returns the requested credential, or nil if we do not have it.
func (cm *CredentialManager) Credential(id CredentialIdentifier, counter int) (cred *Credential, err error) {
	// If the requested credential is not in credential map, we check if its attributes were
	// deserialized during Init(). If so, there should be a corresponding signature file,
	// so we read that, construct the credential, and add it to the credential map
	if _, exists := cm.creds(id)[counter]; !exists {
		attrs := cm.Attributes(id, counter)
		if attrs == nil { // We do not have the requested cred
			return
		}
		ints := append([]*big.Int{cm.secretkey}, attrs.Ints...)
		sig, err := cm.loadSignature(id, counter)
		if err != nil {
			return nil, err
		}
		if sig == nil {
			err = errors.New("signature file not found")
			return nil, err
		}
		meta := MetadataFromInt(ints[1])
		pk := meta.PublicKey()
		if pk == nil {
			return nil, errors.New("unknown public key")
		}
		cred := newCredential(&gabi.Credential{
			Attributes: ints,
			Signature:  sig,
			Pk:         pk,
		})
		cm.credentials[id][counter] = cred
	}

	return cm.credentials[id][counter], nil
}

// ParseAndroidStorage parses an Android cardemu.xml shared preferences file
// from the old Android IRMA app, parsing its credentials into the current instance,
// and saving them to storage.
// CAREFUL: this method overwrites any existing secret keys and attributes on storage.
func (cm *CredentialManager) ParseAndroidStorage() (err error) {
	exists, err := pathExists(cm.path(cardemuXML))
	if err != nil || !exists {
		return
	}

	bytes, err := ioutil.ReadFile(cm.path(cardemuXML))
	parsedxml := struct {
		Strings []struct {
			Name    string `xml:"name,attr"`
			Content string `xml:",chardata"`
		} `xml:"string"`
	}{}
	xml.Unmarshal(bytes, &parsedxml)

	parsedjson := make(map[string][]*gabi.Credential)
	for _, xmltag := range parsedxml.Strings {
		if xmltag.Name == "credentials" {
			jsontag := html.UnescapeString(xmltag.Content)
			if err = json.Unmarshal([]byte(jsontag), &parsedjson); err != nil {
				return
			}
		}
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

	return
}

func (cm *CredentialManager) addCredential(cred *Credential) {
	id := cred.CredentialType().Identifier()
	cm.attributes[id] = append(cm.attrs(id), NewAttributeListFromInts(cred.Attributes[1:]))

	if _, exists := cm.credentials[id]; !exists {
		cm.credentials[id] = make(map[int]*Credential)
	}
	counter := len(cm.attributes[id]) - 1
	cm.credentials[id][counter] = cred
}

// Add adds the specified credential to the CredentialManager.
func (cm *CredentialManager) Add(cred *Credential) (err error) {
	if cred.CredentialType() == nil {
		return errors.New("cannot add unknown credential type")
	}

	cm.addCredential(cred)
	counter := len(cm.credentials[cred.CredentialType().Identifier()]) - 1

	err = cm.storeSignature(cred, counter)
	if err != nil {
		return
	}
	err = cm.storeAttributes()
	return
}
