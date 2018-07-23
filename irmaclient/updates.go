package irmaclient

import (
	"encoding/json"
	"encoding/xml"
	"html"
	"io/ioutil"
	"math/big"
	"regexp"
	"time"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
)

// This file contains the update mechanism for Client
// as well as updates themselves.

type update struct {
	When    irma.Timestamp
	Number  int
	Success bool
	Error   *string
}

var clientUpdates = []func(client *Client) error{
	// 0: Convert old cardemu.xml Android storage to our own storage format
	func(client *Client) error {
		_, err := client.ParseAndroidStorage()
		return err
	},

	// 1: Adding scheme manager index, signature and public key
	// Check the signatures of all scheme managers, if any is not ok,
	// copy the entire irma_configuration folder from assets
	nil, // made irrelevant by irma_configuration-autocopying

	// 2: Rename config -> preferences
	func(client *Client) (err error) {
		exists, err := fs.PathExists(client.storage.path("config"))
		if !exists || err != nil {
			return
		}
		oldStruct := &struct {
			SendCrashReports bool
		}{}
		// Load old file, convert to new struct, and save
		err = client.storage.load(oldStruct, "config")
		if err != nil {
			return err
		}
		client.Preferences = Preferences{
			EnableCrashReporting: oldStruct.SendCrashReports,
		}
		return client.storage.StorePreferences(client.Preferences)
	},

	// 3: Copy new irma_configuration out of assets
	nil, // made irrelevant by irma_configuration-autocopying

	// 4: For each keyshare server, include in its struct the identifier of its scheme manager
	func(client *Client) (err error) {
		keyshareServers, err := client.storage.LoadKeyshareServers()
		if err != nil {
			return err
		}
		for smi, kss := range keyshareServers {
			kss.SchemeManagerIdentifier = smi
		}
		return client.storage.StoreKeyshareServers(keyshareServers)
	},

	// 5: Remove the test scheme manager which was erroneously included in a production build
	nil, // No longer necessary, also broke many unit tests

	// 6: Guess and include version protocol in issuance logs, and convert log entry structure
	// from Response to either IssueCommitment or ProofList
	func(client *Client) (err error) {
		logs, err := client.Logs()
		if err != nil {
			return
		}
		// The logs read above do not contain the Response field as it has been removed from the LogEntry struct.
		// So read the logs again into a slice of a temp struct that does contain this field.
		type oldLogEntry struct {
			Response json.RawMessage
		}
		var oldLogs []*oldLogEntry
		if err = client.storage.load(&oldLogs, logsFile); err != nil {
			return
		}
		// Sanity check, this should be true as both log slices were read from the same source
		if len(oldLogs) != len(logs) {
			return errors.New("Log count does not match")
		}

		for i, entry := range logs {
			oldEntry := oldLogs[i]

			if len(oldEntry.Response) == 0 {
				return errors.New("Log entry had no Response field")
			}

			switch entry.Type {
			case actionRemoval: // nop
			case irma.ActionSigning:
				fallthrough
			case irma.ActionDisclosing:
				proofs := []*gabi.ProofD{}
				if err = json.Unmarshal(oldEntry.Response, &proofs); err != nil {
					return
				}
				for _, proof := range proofs {
					entry.ProofList = append(entry.ProofList, proof)
				}
			case irma.ActionIssuing:
				entry.IssueCommitment = &gabi.IssueCommitmentMessage{}
				if err = json.Unmarshal(oldEntry.Response, entry.IssueCommitment); err != nil {
					return err
				}
			default:
				return errors.New("Invalid log type")
			}

			if entry.Type != irma.ActionIssuing {
				continue
			}
			// Ugly hack alert: unfortunately the protocol version that was used in the session is nowhere recorded.
			// This means that we cannot be sure whether or not we should byteshift the presence bit out of the attributes
			// that was introduced in version 2.3 of the protocol. The only thing that I can think of to determine this
			// is to check if the attributes are human-readable, i.e., alphanumeric: if the presence bit is present and
			// we do not shift it away, then they almost certainly will not be.
			var jwt irma.RequestorJwt
			jwt, err = entry.Jwt()
			if err != nil {
				return
			}
			for _, attr := range jwt.IrmaSession().(*irma.IssuanceRequest).Credentials[0].Attributes {
				if regexp.MustCompile("^\\w").Match([]byte(attr)) {
					entry.Version = irma.NewVersion(2, 2)
				} else {
					entry.Version = irma.NewVersion(2, 3)
				}
				break
			}
		}
		return client.storage.StoreLogs(logs)
	},
}

// update performs any function from clientUpdates that has not
// already been executed in the past, keeping track of previously executed updates
// in the file at updatesFile.
func (client *Client) update() error {
	// Load and parse file containing info about already performed updates
	var err error
	if client.updates, err = client.storage.LoadUpdates(); err != nil {
		return err
	}

	// Perform all new updates
	for i := len(client.updates); i < len(clientUpdates); i++ {
		err = nil
		if clientUpdates[i] != nil {
			err = clientUpdates[i](client)
		}
		u := update{
			When:    irma.Timestamp(time.Now()),
			Number:  i,
			Success: err == nil,
		}
		if err != nil {
			str := err.Error()
			u.Error = &str
		}
		client.updates = append(client.updates, u)
		if err != nil {
			break
		}
	}

	storeErr := client.storage.StoreUpdates(client.updates)
	if storeErr != nil {
		return storeErr
	}
	return err
}

// ParseAndroidStorage parses an Android cardemu.xml shared preferences file
// from the old Android IRMA app, parsing its credentials into the current instance,
// and saving them to storage.
// CAREFUL: this method overwrites any existing secret keys and attributes on storage.
func (client *Client) ParseAndroidStorage() (present bool, err error) {
	if client.androidStoragePath == "" {
		return false, nil
	}

	cardemuXML := client.androidStoragePath + "/shared_prefs/cardemu.xml"
	present, err = fs.PathExists(cardemuXML)
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
	if err = xml.Unmarshal(bytes, &parsedxml); err != nil {
		return
	}

	parsedjson := make(map[string][]*struct {
		Signature    *gabi.CLSignature `json:"signature"`
		Pk           *gabi.PublicKey   `json:"-"`
		Attributes   []*big.Int        `json:"attributes"`
		SharedPoints []*big.Int        `json:"public_sks"`
	})
	client.keyshareServers = make(map[irma.SchemeManagerIdentifier]*keyshareServer)
	for _, xmltag := range parsedxml.Strings {
		if xmltag.Name == "credentials" {
			jsontag := html.UnescapeString(xmltag.Content)
			if err = json.Unmarshal([]byte(jsontag), &parsedjson); err != nil {
				return
			}
		}
		if xmltag.Name == "keyshare" {
			jsontag := html.UnescapeString(xmltag.Content)
			if err = json.Unmarshal([]byte(jsontag), &client.keyshareServers); err != nil {
				return
			}
		}
		if xmltag.Name == "KeyshareKeypairs" {
			jsontag := html.UnescapeString(xmltag.Content)
			keys := make([]*paillierPrivateKey, 0, 3)
			if err = json.Unmarshal([]byte(jsontag), &keys); err != nil {
				return
			}
			client.paillierKeyCache = keys[0]
		}
	}

	for _, list := range parsedjson {
		client.secretkey = &secretKey{Key: list[0].Attributes[0]}
		for _, oldcred := range list {
			gabicred := &gabi.Credential{
				Attributes: oldcred.Attributes,
				Signature:  oldcred.Signature,
			}
			if oldcred.SharedPoints != nil && len(oldcred.SharedPoints) > 0 {
				gabicred.Signature.KeyshareP = oldcred.SharedPoints[0]
			}
			var cred *credential
			if cred, err = newCredential(gabicred, client.Configuration); err != nil {
				return
			}
			if cred.CredentialType() == nil {
				err = errors.New("cannot add unknown credential type")
				return
			}

			if err = client.addCredential(cred, false); err != nil {
				return
			}
		}
	}

	if len(client.credentialsCache) > 0 {
		if err = client.storage.StoreAttributes(client.attributes); err != nil {
			return
		}
		if err = client.storage.StoreSecretKey(client.secretkey); err != nil {
			return
		}
	}

	if len(client.keyshareServers) > 0 {
		if err = client.storage.StoreKeyshareServers(client.keyshareServers); err != nil {
			return
		}
	}

	if err = client.storage.StorePaillierKeys(client.paillierKeyCache); err != nil {
		return
	}
	if client.paillierKeyCache == nil {
		client.paillierKey(false) // trigger calculating a new one
	}
	return
}
