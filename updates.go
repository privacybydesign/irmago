package irmago

import (
	"encoding/json"
	"encoding/xml"
	"html"
	"io/ioutil"
	"math/big"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
)

type update struct {
	When    Timestamp
	Number  int
	Success bool
	Error   *string
}

var credentialManagerUpdates = []func(manager *CredentialManager) error{
	func(manager *CredentialManager) error {
		_, err := manager.ParseAndroidStorage()
		return err
	},
}

// ParseAndroidStorage parses an Android cardemu.xml shared preferences file
// from the old Android IRMA app, parsing its credentials into the current instance,
// and saving them to storage.
// CAREFUL: this method overwrites any existing secret keys and attributes on storage.
func (cm *CredentialManager) ParseAndroidStorage() (present bool, err error) {
	if cm.androidStoragePath == "" {
		return false, nil
	}

	cardemuXML := cm.androidStoragePath + "/shared_prefs/cardemu.xml"
	present, err = PathExists(cardemuXML)
	if err != nil || !present {
		return
	}
	present = true

	bytes, err := ioutil.ReadFile(cardemuXML)
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

	parsedjson := make(map[string][]*struct {
		Signature    *gabi.CLSignature `json:"signature"`
		Pk           *gabi.PublicKey   `json:"-"`
		Attributes   []*big.Int        `json:"attributes"`
		SharedPoints []*big.Int        `json:"public_sks"`
	})
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
		cm.secretkey = &secretKey{Key: list[0].Attributes[0]}
		for _, oldcred := range list {
			gabicred := &gabi.Credential{
				Attributes: oldcred.Attributes,
				Signature:  oldcred.Signature,
			}
			if oldcred.SharedPoints != nil && len(oldcred.SharedPoints) > 0 {
				gabicred.Signature.KeyshareP = oldcred.SharedPoints[0]
			}
			var cred *credential
			if cred, err = newCredential(gabicred, cm.Store); err != nil {
				return
			}
			if cred.CredentialType() == nil {
				err = errors.New("cannot add unknown credential type")
				return
			}

			if err = cm.addCredential(cred, false); err != nil {
				return
			}
		}
	}

	if len(cm.credentials) > 0 {
		if err = cm.storeAttributes(); err != nil {
			return
		}
		if err = cm.storeSecretKey(cm.secretkey); err != nil {
			return
		}
	}

	if len(cm.keyshareServers) > 0 {
		if err = cm.storeKeyshareServers(); err != nil {
			return
		}
	}

	if err = cm.storePaillierKeys(); err != nil {
		return
	}
	if cm.paillierKeyCache == nil {
		cm.paillierKey(false) // trigger calculating a new one
	}

	if err = cm.Store.Copy(cm.androidStoragePath+"/app_store/irma_configuration", false); err != nil {
		return
	}
	// Copy from assets again to ensure we have the latest versions
	return present, cm.Store.Copy(cm.irmaConfigurationPath, true)
}
