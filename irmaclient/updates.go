package irmaclient

import (
	"os"
	"time"

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
	nil, // No longer necessary as the Android app was deprecated long ago

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
		// TODO: this has been temporarily removed and should be restored
		os.Remove(client.storage.path(logsFile))
		return nil
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
