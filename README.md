# irmago &nbsp; [![GoDoc](https://godoc.org/github.com/privacybydesign/irmago?status.svg)](https://godoc.org/github.com/privacybydesign/irmago) [![Go Report Card](https://goreportcard.com/badge/github.com/privacybydesign/irmago)](https://goreportcard.com/report/github.com/privacybydesign/irmago)

`irmago` is an IRMA implementation in Go. It contains multiple libraries and applications:

* The commandline tool [`irma`](https://irma.app/docs/irma-cli/), which contains an [IRMA server](https://irma.app/docs/irma-server/); subcommands for manipulating [IRMA schemes](https://irma.app/docs/schemes/), generating IRMA issuer public/private keypairs, performing test IRMA sessions on the command line; and more.
* The Go library [`irmaserver`](https://irma.app/docs/irma-server-lib/) providing a HTTP server that handles IRMA session with the [IRMA mobile app](https://github.com/privacybydesign/irma_mobile), and functions for starting and managing IRMA sessions.
* The root package `irma` contains generic IRMA functionality used by all other components below, such as parsing [IRMA schemes](https://irma.app/docs/schemes/), parsing [IRMA metadata attributes](https://irma.app/docs/overview#the-metadata-attribute), and structs representing messages of the IRMA protocol.
* The Go package `irmaclient` is a library that serves as the client in the IRMA protocol; it can receive and disclose IRMA attributes and store and read them from storage. It also implements the [keyshare protocol](https://github.com/privacybydesign/irma_keyshare_server) and handles registering to keyshare servers. The [IRMA mobile app](https://github.com/privacybydesign/irma_mobile) uses `irmaclient`.

## Documentation

Technical documentation of all components of `irmago` and more can be found at https://irma.app/docs.

## Installing

    go get -d -u github.com/privacybydesign/irmago


`irmago` and its subpackages uses [`dep`](https://github.com/golang/dep) for its dependencies. After [Installing `dep`](https://golang.github.io/dep/docs/installation.html) if necesssary, run

    cd $GOPATH/src/github.com/privacybydesign/irmago
    dep ensure

to download and [`vendor`](https://golang.org/cmd/go/#hdr-Vendor_Directories) the correct version of
each dependency. To install the `irma` command line tool:

    go install ./irma


## Running the unit tests

For running the unit tests, you need to run [irma_keyshare_server](https://github.com/credentials/irma_keyshare_server) and [irma_api_server](https://github.com/credentials/irma_api_server) locally.

### IRMA Keyshare Server

- Copy or symlink the `irma_configuration` folder from `testdata/` to the configuration of the Keyshare server.
    - Note that a `gradle appRun` won't automatically use the new `irma_configuration` folder if it was already built with an old one. For this, use `gradle clean`.
- Add the keyshare user used in the unit tests to the keyshare database by a command like this:

        mysql -uirma -pirma irma_keyshare < keyshareuser.sql

- Make sure `check_user_enabled` is set to false in the Keyshare server configuration. Other options are already setup correctly in the example configuration.


### IRMA API Server
- Copy or symlink the `irma_configuration` folder from `testdata/` to the configuration of the IRMA api server.
    - Note that a `gradle appRun` won't automatically use the new `irma_configuration` folder if it was already built with an old one. For this, use `gradle clean`.


### Running the tests
The tests can be run by using:

    go test -v ./...

<!-- vim: set ts=4 sw=4: -->
