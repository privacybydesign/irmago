package irmaclient

import (
	"encoding/json"
	"github.com/privacybydesign/gabi"
	"go.etcd.io/bbolt"
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
		fileStorage := fileStorage{storagePath: client.storage.storagePath, Configuration: client.Configuration}
		logs, err := fileStorage.LoadLogs()
		if err != nil {
			return nil
		}

		storageOld := storageOld{storageOldPath: client.storage.storagePath, Configuration: client.Configuration}
		if err = storageOld.Open(); err != nil {
			return err
		}
		defer func() { _ = storageOld.Close() }()

		// Open one bolt transaction to process all our log entries in
		return storageOld.Transaction(func(tx *transaction) error {
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
				if err = storageOld.TxAddLogEntry(tx, log); err != nil {
					return err
				}
			}
			return nil
		})
	},

	// 8: Move other user storage to bbolt database
	func(client *Client) error {
		fileStorage := fileStorage{storagePath: client.storage.storagePath, Configuration: client.Configuration}

		sk, err := fileStorage.LoadSecretKey()
		if err != nil {
			return err
		}

		// When no secret key is found, it means the storage is fresh. No update is needed.
		if sk == nil {
			return nil
		}

		attrs, err := fileStorage.LoadAttributes()
		if err != nil {
			return err
		}

		sigs := make(map[string]*clSignatureWitness)
		for _, attrlistlist := range attrs {
			for _, attrlist := range attrlistlist {
				sig, witness, err := fileStorage.LoadSignature(attrlist)
				if err != nil {
					return err
				}
				sigs[attrlist.Hash()] = &clSignatureWitness{
					CLSignature: sig,
					Witness:     witness,
				}
			}
		}

		ksses, err := fileStorage.LoadKeyshareServers()
		if err != nil {
			return err
		}

		prefs, err := fileStorage.LoadPreferences()
		if err != nil {
			return err
		}

		// Preferences are already loaded in client, refresh
		client.Preferences = prefs
		client.applyPreferences()

		updates, err := fileStorage.LoadUpdates()
		if err != nil {
			return err
		}

		storageOld := storageOld{storageOldPath: client.storage.storagePath, Configuration: client.Configuration}
		if err = storageOld.Open(); err != nil {
			return err
		}
		defer func() { _ = storageOld.Close() }()

		return storageOld.Transaction(func(tx *transaction) error {
			if err = storageOld.TxStoreSecretKey(tx, sk); err != nil {
				return err
			}
			for credTypeID, attrslistlist := range attrs {
				if err = storageOld.TxStoreAttributes(tx, credTypeID, attrslistlist); err != nil {
					return err
				}
			}
			for hash, sig := range sigs {
				err = storageOld.TxStoreCLSignature(tx, hash, sig)
				if err != nil {
					return err
				}
			}
			if err = storageOld.TxStoreKeyshareServers(tx, ksses); err != nil {
				return err
			}
			if err = storageOld.TxStorePreferences(tx, prefs); err != nil {
				return err
			}
			return storageOld.TxStoreUpdates(tx, updates)
		})
	},

	// 9: Migrate old log entries to current format and delete malformatted log entries
	func(client *Client) error {
		storageOld := storageOld{storageOldPath: client.storage.storagePath, Configuration: client.Configuration}
		if err := storageOld.Open(); err != nil {
			return err
		}
		defer func() { _ = storageOld.Close() }()

		var toBeMigratedLogs []*LogEntry
		var toBeDeletedLogs [][]byte

		return storageOld.db.Update(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket([]byte(logsBucket))
			if bucket == nil {
				return nil
			}

			// The inner function only returns nil. Thus, the error can be ignored.
			_ = bucket.ForEach(func(k []byte, v []byte) error {
				type rawLogEntry LogEntry
				var temp struct {
					ServerName json.RawMessage `json:",omitempty"`
					rawLogEntry
				}

				if err := json.Unmarshal(v, &temp); err != nil {
					toBeDeletedLogs = append(toBeDeletedLogs, k)
					return nil
				}

				// Copy standard fields
				log := LogEntry(temp.rawLogEntry)

				// If there's no servername in the old log entry, delete the log entry.
				if len(temp.ServerName) == 0 {
					toBeDeletedLogs = append(toBeDeletedLogs, k)
					return nil
				}

				// Try to decode servername as RequestorInfo. If unmarshaling returns an error, the
				// log entry cannot be used and should be deleted.
				if err := json.Unmarshal(temp.ServerName, &(log.ServerName)); err != nil {
					toBeDeletedLogs = append(toBeDeletedLogs, k)
					return nil
				}

				// If successful, we should have at least one translation for a name, so check that.
				// Then log entry is up-to-date and no action is needed
				if len(log.ServerName.Name) != 0 {
					return nil
				}

				// The Rawmessage is not of type RequestorInfo and may still be of the old format.
				// Try to parse the Rawmessage as TranslatedString into the log entry's ServerName.Name.
				// Again, if unmarshaling returns an error, the log entry cannot be used and should be deleted.
				log.ServerName = &irma.RequestorInfo{}
				if err := json.Unmarshal(temp.ServerName, &(log.ServerName.Name)); err != nil {
					toBeDeletedLogs = append(toBeDeletedLogs, k)
					return nil
				}

				// If the log entry's name was filled correctly, log entry migration is feasible.
				// Otherwise, delete the old log.
				if len(log.ServerName.Name) != 0 {
					toBeMigratedLogs = append(toBeMigratedLogs, &log)
				} else {
					toBeDeletedLogs = append(toBeDeletedLogs, k)
				}
				return nil
			})

			for _, id := range toBeDeletedLogs {
				err := bucket.Delete(id)
				if err != nil {
					return err
				}
			}

			// Overwrite old with newly formatted log entry.
			for _, log := range toBeMigratedLogs {
				if err := storageOld.WriteLogEntry(bucket, log); err != nil {
					return err
				}
			}

			return nil
		})
	},

	// 10: Encrypt storage
	func(client *Client) error {
		storageOld := storageOld{storageOldPath: client.storage.storagePath, Configuration: client.Configuration}
		if err := storageOld.Open(); err != nil {
			return err
		}
		defer func() { _ = storageOld.Close() }()

		sk, err := storageOld.LoadSecretKey()
		if err != nil {
			return err
		}

		// When no secret key is found, it means the storage is fresh. No update is needed.
		if sk == nil {
			return nil
		}

		updates, err := storageOld.LoadUpdates()
		if err != nil {
			return err
		}
		preferences, err := storageOld.LoadPreferences()
		if err != nil {
			return err
		}
		kss, err := storageOld.LoadKeyshareServers()
		if err != nil {
			return err
		}
		attrs, err := storageOld.LoadAttributes()
		if err != nil {
			return err
		}
		logs, err := storageOld.loadLogs()
		if err != nil {
			return err
		}

		return client.storage.Transaction(func(tx *transaction) error {
			for _, log := range logs {
				if err = client.storage.TxAddLogEntry(tx, log); err != nil {
					return err
				}
			}

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

			for credid, attrlistlist := range attrs {
				err = client.storage.TxStoreAttributes(tx, credid, attrlistlist)
				if err != nil {
					return err
				}

				for _, attrlist := range attrlistlist {
					e, h, err := storageOld.LoadSignature(attrlist)
					if err != nil {
						return err
					}

					cred := &credential{attrs: attrlist, Credential: &gabi.Credential{Signature: e, NonRevocationWitness: h}}
					err = client.storage.TxStoreSignature(tx, cred)
					if err != nil {
						return err
					}
				}
			}
			return nil
		})
	},

	// 11: Delete fileStorage
	func(client *Client) error {
		fileStorage := fileStorage{storagePath: client.storage.storagePath, Configuration: client.Configuration}
		return fileStorage.DeleteAll()
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
	// to encrypted bbolt storage yet. Therefore also check the plaintext storage `storageOld` and the
	// updates file.
	if len(client.updates) == 0 {
		storageOld := storageOld{storageOldPath: client.storage.storagePath, Configuration: client.Configuration}
		if err = storageOld.Open(); err != nil {
			return err
		}

		if client.updates, err = storageOld.LoadUpdates(); err != nil {
			return err
		}

		if err = storageOld.Close(); err != nil {
			return err
		}

		if len(client.updates) == 0 {
			fileStorage := fileStorage{storagePath: client.storage.storagePath, Configuration: client.Configuration}
			if client.updates, err = fileStorage.LoadUpdates(); err != nil {
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
