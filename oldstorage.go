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
		cm.secretkey = list[0].Attributes[0]
		for _, oldcred := range list {
			gabicred := &gabi.Credential{
				Attributes: oldcred.Attributes,
				Signature:  oldcred.Signature,
			}
			if oldcred.SharedPoints != nil && len(oldcred.SharedPoints) > 0 {
				gabicred.Signature.KeyshareP = oldcred.SharedPoints[0]
			}
			cred, err := newCredential(gabicred, cm.Store)
			if err != nil {
				return err
			}
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
