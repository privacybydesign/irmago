package irmaclient

import (
	"encoding/json"
	"regexp"
	"time"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/mhe/gabi/big"
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
		logs, err := client.Logs()
		if err != nil {
			return
		}
		// The logs read above do not contain the Response field as it has been removed from the LogEntry struct.
		// So read the logs again into a slice of a temp struct that does contain this field.
		type oldLogEntry struct {
			Response    json.RawMessage
			ProofList   gabi.ProofList
			SessionInfo struct {
				Nonce   *big.Int                      `json:"nonce"`
				Context *big.Int                      `json:"context"`
				Jwt     string                        `json:"jwt"`
				Keys    map[irma.IssuerIdentifier]int `json:"keys"`
			}
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

			var jwt irma.RequestorJwt
			jwt, err = irma.ParseRequestorJwt(string(entry.Type), oldEntry.SessionInfo.Jwt)
			if err != nil {
				return err
			}

			entry.request = jwt.SessionRequest()
			// Ugly hack alert: unfortunately the protocol version that was used in the session is nowhere recorded.
			// This means that we cannot be sure whether or not we should byteshift the presence bit out of the attributes
			// that was introduced in version 2.3 of the protocol. The only thing that I can think of to determine this
			// is to check if the attributes are human-readable, i.e., alphanumeric: if the presence bit is present and
			// we do not shift it away, then they almost certainly will not be.
			if entry.Type == irma.ActionIssuing && entry.Version == nil {
				for _, attr := range entry.request.(*irma.IssuanceRequest).Credentials[0].Attributes {
					if regexp.MustCompile("^\\w").Match([]byte(attr)) {
						entry.Version = irma.NewVersion(2, 2)
					} else {
						entry.Version = irma.NewVersion(2, 3)
					}
					break
				}
			}
			if entry.Version == nil {
				entry.Version = irma.NewVersion(2, 3)
			}
			entry.request.SetNonce(oldEntry.SessionInfo.Nonce)
			entry.request.SetContext(oldEntry.SessionInfo.Context)
			entry.request.SetVersion(entry.Version)
			if err := entry.setSessionRequest(); err != nil {
				return err
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
				entry.Disclosure = &irma.Disclosure{}
				for _, proof := range proofs {
					entry.Disclosure.Proofs = append(entry.Disclosure.Proofs, proof)
				}
			case irma.ActionIssuing:
				entry.IssueCommitment = &irma.IssueCommitmentMessage{}
				if err = json.Unmarshal(oldEntry.Response, entry.IssueCommitment); err != nil {
					return err
				}
				isreq := entry.request.(*irma.IssuanceRequest)
				for _, cred := range isreq.Credentials {
					cred.KeyCounter = oldEntry.SessionInfo.Keys[cred.CredentialTypeID.IssuerIdentifier()]
				}
			default:
				return errors.New("Invalid log type")
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
