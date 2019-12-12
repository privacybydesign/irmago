package irmaclient

import (
	"encoding/json"
	"github.com/privacybydesign/gabi"
	"time"

	"github.com/privacybydesign/irmago"
	"go.etcd.io/bbolt"
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
	nil, // No longer necessary as the Android app was deprecated long ago

	// 1: Adding scheme manager index, signature and public key
	// Check the signatures of all scheme managers, if any is not ok,
	// copy the entire irma_configuration folder from assets
	nil, // made irrelevant by irma_configuration-autocopying

	// 2: Rename config -> preferences
	nil, // No longer necessary

	// 3: Copy new irma_configuration out of assets
	nil, // made irrelevant by irma_configuration-autocopying

	// 4: For each keyshare server, include in its struct the identifier of its scheme manager
	nil, // No longer necessary

	// 5: Remove the test scheme manager which was erroneously included in a production build
	nil, // No longer necessary, also broke many unit tests

	// 6: Remove earlier log items of wrong format
	nil, // No longer necessary

	// 7: Convert log entries to bbolt database
	func(client *Client) error {
		var logs []*LogEntry
		var err error
		if err = client.storage.loadFromFile(&logs, logsFile); err != nil {
			return nil
		}
		// Open one bolt transaction to process all our log entries in
		err = client.storage.db.Update(func(tx *bbolt.Tx) error {
			for _, log := range logs {
				// As log.Request is a json.RawMessage it would not get updated to the new session request
				// format by re-marshaling the containing struct, as normal struct members would,
				// so update it manually now by marshaling the session request into it.
				req, err := log.SessionRequest()
				if err != nil {
					return err
				}
				log.Request, err = json.Marshal(req)
				if err != nil {
					return err
				}
				if err = client.storage.TxAddLogEntry(tx, log); err != nil {
					return err
				}
			}
			return nil
		})
		return err
	},

	// 8: Move other user storage to bbolt database
	func(client *Client) error {
		sk, err := client.storage.LoadSecretKeyFile()
		if err != nil {
			return err
		}

		// When no secret key is found, it means the storage is fresh. No update is needed.
		if sk == nil {
			return nil
		}

		attrs, err := client.storage.LoadAttributesFile()
		if err != nil {
			return err
		}

		sigs := make(map[string]*gabi.CLSignature)
		for _, attrlistlist := range attrs {
			for _, attrlist := range attrlistlist {
				sig, err := client.storage.LoadSignatureFile(attrlist)
				if err != nil {
					return err
				}
				sigs[attrlist.Hash()] = sig
			}
		}

		ksses, err := client.storage.LoadKeyshareServersFile()
		if err != nil {
			return err
		}

		prefs, err := client.storage.LoadPreferencesFile()
		if err != nil {
			return err
		}

		// Preferences are already loaded in client, refresh
		client.Preferences = prefs
		client.applyPreferences()

		updates, err := client.storage.LoadUpdatesFile()
		if err != nil {
			return err
		}

		return client.storage.db.Update(func(tx *bbolt.Tx) error {
			err = client.storage.TxStoreSecretKey(tx, sk)
			if err != nil {
				return err
			}
			err := client.storage.TxStoreAttributes(tx, attrs)
			if err != nil {
				return err
			}
			for hash, sig := range sigs {
				err = client.storage.TxStoreSignature(tx, hash, sig)
				if err != nil {
					return err
				}
			}
			err = client.storage.TxStoreKeyshareServers(tx, ksses)
			if err != nil {
				return err
			}
			err = client.storage.TxStorePreferences(tx, prefs)
			if err != nil {
				return err
			}
			return client.storage.TxStoreUpdates(tx, updates)
		})
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
	// When no updates are found, it can either be a fresh storage or the storage has not been updated
	// to bbolt yet. Therefore also check the updates file.
	if len(client.updates) == 0 {
		if client.updates, err = client.storage.LoadUpdatesFile(); err != nil {
			return err
		}
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
