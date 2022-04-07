package irmaclient

import (
	"encoding/json"
	"github.com/privacybydesign/gabi"
	"time"

	irma "github.com/privacybydesign/irmago"
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
		logs, err := client.fileStorage.LoadLogs()
		if err != nil {
			return nil
		}

		// Open one bolt transaction to process all our log entries in
		err = client.storageOld.Transaction(func(tx *transaction) error {
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
				if err = client.storageOld.TxAddLogEntry(tx, log); err != nil {
					return err
				}
			}
			return nil
		})
		return err
	},

	// 8: Move other user storage to bbolt database
	func(client *Client) error {
		sk, err := client.fileStorage.LoadSecretKey()
		if err != nil {
			return err
		}

		// When no secret key is found, it means the storage is fresh. No update is needed.
		if sk == nil {
			return nil
		}

		attrs, err := client.fileStorage.LoadAttributes()
		if err != nil {
			return err
		}

		sigs := make(map[string]*clSignatureWitness)
		for _, attrlistlist := range attrs {
			for _, attrlist := range attrlistlist {
				sig, witness, err := client.fileStorage.LoadSignature(attrlist)
				if err != nil {
					return err
				}
				sigs[attrlist.Hash()] = &clSignatureWitness{
					CLSignature: sig,
					Witness:     witness,
				}
			}
		}

		ksses, err := client.fileStorage.LoadKeyshareServers()
		if err != nil {
			return err
		}

		prefs, err := client.fileStorage.LoadPreferences()
		if err != nil {
			return err
		}

		// Preferences are already loaded in client, refresh
		client.Preferences = prefs
		client.applyPreferences()

		updates, err := client.fileStorage.LoadUpdates()
		if err != nil {
			return err
		}

		return client.storageOld.Transaction(func(tx *transaction) error {
			if err = client.storageOld.TxStoreSecretKey(tx, sk); err != nil {
				return err
			}
			for credTypeID, attrslistlist := range attrs {
				if err = client.storageOld.TxStoreAttributes(tx, credTypeID, attrslistlist); err != nil {
					return err
				}
			}
			for hash, sig := range sigs {
				err = client.storageOld.TxStoreCLSignature(tx, hash, sig)
				if err != nil {
					return err
				}
			}
			if err = client.storageOld.TxStoreKeyshareServers(tx, ksses); err != nil {
				return err
			}
			if err = client.storageOld.TxStorePreferences(tx, prefs); err != nil {
				return err
			}
			return client.storageOld.TxStoreUpdates(tx, updates)
		})
	},

	// 9: Encrypt storage
	func(client *Client) error {
		sk, err := client.storageOld.LoadSecretKey()
		if err != nil {
			return err
		}

		// When no secret key is found, it means the storage is fresh. No update is needed.
		if sk == nil {
			return nil
		}

		updates, err := client.storageOld.LoadUpdates()
		if err != nil {
			return err
		}
		preferences, err := client.storageOld.LoadPreferences()
		if err != nil {
			return err
		}
		kss, err := client.storageOld.LoadKeyshareServers()
		if err != nil {
			return err
		}
		attrList, err := client.storageOld.LoadAttributes()
		if err != nil {
			return err
		}

		err = client.storage.Transaction(func(tx *transaction) error {
			err = client.storage.TxStoreSecretKey(tx, sk)
			if err != nil {
				return err
			}
			err = client.storage.TxStoreUpdates(tx, updates)
			if err != nil {
				return err
			}
			err = client.storage.TxStorePreferences(tx, preferences)
			if err != nil {
				return err
			}
			err = client.storage.TxStoreKeyshareServers(tx, kss)
			if err != nil {
				return err
			}

			for i := range attrList {
				err = client.storage.TxStoreAttributes(tx, i, attrList[i])
				if err != nil {
					return err
				}

				for attr := range attrList[i] {
					e, h, err := client.storageOld.LoadSignature(attrList[i][attr])
					if err != nil {
						return err
					}

					cred := &credential{attrs: attrList[i][attr], Credential: &gabi.Credential{Signature: e, NonRevocationWitness: h}}
					err = client.storage.TxStoreSignature(tx, cred)
					if err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}

		return client.storageOld.DeleteAll()
	},

	// TODO: Maybe delete preferences file to start afresh
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
		if client.updates, err = client.storageOld.LoadUpdates(); err != nil {
			return err
		}
		if len(client.updates) == 0 {
			if client.updates, err = client.fileStorage.LoadUpdates(); err != nil {
				return err
			}
		}
	}

	// Early exit if all updates are already performed to prevent superfluously storing the updates array
	if len(client.updates) == len(clientUpdates) {
		return nil
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
