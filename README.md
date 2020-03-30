# irmago &nbsp; [![GoDoc](https://godoc.org/github.com/privacybydesign/irmago?status.svg)](https://godoc.org/github.com/privacybydesign/irmago) [![Go Report Card](https://goreportcard.com/badge/github.com/privacybydesign/irmago)](https://goreportcard.com/report/github.com/privacybydesign/irmago)

`irmago` is an IRMA implementation in Go. It contains multiple libraries and applications:

* The commandline tool [`irma`](https://irma.app/docs/irma-cli/), which contains an [IRMA server](https://irma.app/docs/irma-server/); subcommands for manipulating [IRMA schemes](https://irma.app/docs/schemes/), generating IRMA issuer public/private keypairs, performing test IRMA sessions on the command line; and more.
* The Go library [`irmaserver`](https://irma.app/docs/irma-server-lib/) providing a HTTP server that handles IRMA session with the [IRMA mobile app](https://github.com/privacybydesign/irma_mobile), and functions for starting and managing IRMA sessions.
* The root package `irma` contains generic IRMA functionality used by all other components below, such as parsing [IRMA schemes](https://irma.app/docs/schemes/), parsing [IRMA metadata attributes](https://irma.app/docs/overview#the-metadata-attribute), and structs representing messages of the IRMA protocol.
* The Go package `irmaclient` is a library that serves as the client in the IRMA protocol; it can receive and disclose IRMA attributes and store and read them from storage. It also implements the [keyshare protocol](https://github.com/privacybydesign/irma_keyshare_server) and handles registering to keyshare servers. The [IRMA mobile app](https://github.com/privacybydesign/irma_mobile) uses `irmaclient`.

## Documentation

Technical documentation of all components of `irmago` and more can be found at https://irma.app/docs.

## Installing

    git clone https://github.com/privacybydesign/irmago

`irmago` and its subpackages use Go modules for their dependencies. The `go` command will automatically download dependencies when needed.

To install the `irma` command line tool:

    go install ./irma


## Running the unit tests

The tests can be run using:

    go test -v -p 1 --tags=local_tests ./...

* The option `./...` makes sure all tests are run. You can also limit the number of tests by only running the tests from a single directory or even from a single file, for example only running all tests in the directory `./internal/sessiontest`. When you only want to execute one single test, for example the `TestDisclosureSession` test, you can do this by adding the option `-run TestDisclosureSession`.
* The option `-p 1` is necessary to prevent parallel execution of tests. Most tests use file manipulation and therefore tests can interfere.

The command above only runs the local tests. These tests cover all regular use cases. The tests that are dependent on the [irma_keyshare_server](https://github.com/credentials/irma_keyshare_server) are skipped. These tests are only relevant for client implementations, like the IRMA app. 

If you do want to also run the tests using a keyshare server, you have to run your own local instance. How to set up a keyshare server suitable for these tests is described below. After this is done, the tests can be added by removing the `--tags=local_tests` parameter from the command.

### IRMA Keyshare Server
An [irma_keyshare_server](https://github.com/credentials/irma_keyshare_server) suitable for testing `irmago` can be set up in the following way:

- Copy or symlink the `irma_configuration` folder from `testdata/` to the configuration of the Keyshare server.
    - Note that a `gradle appRun` won't automatically use the new `irma_configuration` folder if it was already built with an old one. For this, use `gradle clean`.
- Add the keyshare user used in the unit tests to the keyshare database by a command like this:

        mysql -uirma -pirma irma_keyshare < keyshareuser.sql

- Make sure `check_user_enabled` is set to false in the Keyshare server configuration. Other options are already setup correctly in the example configuration.

<!-- vim: set ts=4 sw=4: -->
