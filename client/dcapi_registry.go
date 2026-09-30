package client

import (
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credman"
	"github.com/privacybydesign/irmago/eudi/storage/db"
)

// CredentialManagerProtocols is the set of Digital Credentials API protocols the
// wallet is registered for on the platform.
//
// Deliberately narrower than what the wallet can answer. irmago also handles
// openid4vp-v1-signed and openid4vp-v1-unsigned over the DC API, but registering
// for those makes the wallet appear in the picker for OpenID4VP requests from a
// browser, which is a path no browser has ever driven against it. Widening this
// list is a one-line change and a separately testable one; doing it here would
// make the first browser request a test of two things at once.
var CredentialManagerProtocols = []string{credman.ProtocolIsoMdoc}

// CredentialManagerDatabase encodes everything the wallet holds in the form
// Android's Credential Manager hands to the matcher, for the app to register
// with the platform.
//
// This is a snapshot, not a subscription: the platform keeps whatever it was
// last given and consults it with the wallet not running, so the app must call
// this again and re-register whenever the wallet's contents or its locale
// change. A credential issued after the last registration is invisible to the
// picker until then — the user sees a wallet that does not offer a credential it
// plainly holds, with nothing anywhere reporting an error.
//
// Only mso_mdoc credentials are exported, because org-iso-mdoc is the only
// protocol registered for; see CredentialManagerProtocols.
func (client *Client) CredentialManagerDatabase() ([]byte, error) {
	batches, err := db.NewMdocStore(client.eudiStorage.Db()).ListBatches()
	if err != nil {
		return nil, fmt.Errorf("failed to list mdoc credentials for the credential manager database: %w", err)
	}

	return credman.Build(batches, client.currentLocale.Get(), CredentialManagerProtocols)
}
