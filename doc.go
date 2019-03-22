// Package irma contains generic IRMA strucs and logic of use to all IRMA participants.
// It parses irma_configuration folders to scheme managers, issuers, credential types and public keys,
// it contains various messages from the IRMA protocol, and parses IRMA metadata attributes.
package irma

import "github.com/timshannon/bolthold"

var _ = bolthold.Key
