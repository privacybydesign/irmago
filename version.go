// Package irma contains generic IRMA strucs and logic of use to all IRMA participants.
// It parses irma_configuration folders to scheme managers, issuers, credential types and public keys;
// it contains various messages from the IRMA protocol; it parses IRMA metadata attributes; and it
// contains attribute and credential verification logic.
package irma

import "github.com/timshannon/bolthold"

// Version of the IRMA command line and libraries
const Version = "0.4.1"

// go-atum requires a version of bolthold newer than the latest release v1.1, but go-atum does not
// use dep, so by default dep fetches v1.1 which breaks the build. We make bolthold an explicit
// dependency here, so that we can require its version to be sufficiently new in a [[constraint]] in
// Gopkg.toml: an [[override]] would not propagate to the users of irmago. This is ok, as we will
// have bolthold as actual dependency soon anyway. go-atum uses go mod files which does properly
// lock its bolthold dependency, so:
// TODO: remove this line after we switch to go modules
var _ = bolthold.Key
