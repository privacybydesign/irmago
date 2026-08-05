package client

import "github.com/privacybydesign/irmago/eudi/storage"

// EudiStorageForTesting exposes the client's EUDI storage so tests in other
// packages can seed credentials the wallet then discloses through the real
// session flow.
//
// This exists for the mso_mdoc integration tests: no container in the
// docker-compose stack issues mdoc credentials (the EUDI Python PID issuer
// enables only the SD-JWT variant), so the alternative to seeding storage
// directly is not testing mdoc disclosure at all. Everything downstream of the
// seed — DCQL matching, the disclosure plan, device signing, the response to the
// verifier — still runs as it does in production.
//
// Kept in a non-test file because Go only exports test helpers to other
// packages that way; it is deliberately not part of the app-facing API.
func (client *Client) EudiStorageForTesting() storage.Storage {
	return client.eudiStorage
}
