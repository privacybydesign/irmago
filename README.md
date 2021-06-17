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

Some of the unit tests connect to locally running external services, namely PostgreSQL and an SMTP server running at port 1025. These need to be up and running before these tests can be executed. They can be installed as follows.

#### PostgreSQL

 * Install using e.g. `brew install postgresql`, or `apt-get install postgresql`, or via another package manager of your OS.
 * Prepare the database and user:

       create database test;
       create user testuser with encrypted password 'testpassword';
       grant all privileges on database test to testuser;

   This only needs to be done once. No table or rows need to be created; the unit tests do this themselves.

#### SMTP server
For the SMTP server you can use [MailHog](https://github.com/mailhog/MailHog) (see also their [installation instructions](https://github.com/mailhog/MailHog#installation)):
 * Install using `brew install mailhog` or `go get github.com/mailhog/MailHog`.
 * Run using `MailHog`, or `~/go/bin/MailHog`, depending on your setup.

For the unit tests it only matters that the SMTP server itself is running and accepts emails, but MailHog additionally comes with a webinterface showing incoming emails. By default this runs at <http://localhost:8025>.

### Running the tests

After installing PostgreSQL and MailHog, the tests can be run using:

    go test -p 1 ./...

* The option `./...` makes sure all tests are run. You can also limit the number of tests by only running the tests from a single directory or even from a single file, for example only running all tests in the directory `./internal/sessiontest`. When you only want to execute one single test, for example the `TestDisclosureSession` test, you can do this by adding the option `-run TestDisclosureSession`.
* The option `-p 1` is necessary to prevent parallel execution of tests. Most tests use file manipulation and therefore tests can interfere.

### Running without PostgreSQL or MailHog

If installing PostgreSQL or MailHog is not an option for you, then you can exclude all tests that use those by additionally passing `--tags=local_tests`:

    go test -p 1 --tags=local_tests ./...

<!-- vim: set ts=4 sw=4: -->
