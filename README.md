# irmago &nbsp; [![GoDoc](https://godoc.org/github.com/privacybydesign/irmago?status.svg)](https://godoc.org/github.com/privacybydesign/irmago) [![Go Report Card](https://goreportcard.com/badge/github.com/privacybydesign/irmago)](https://goreportcard.com/report/github.com/privacybydesign/irmago)

`irmago` is an IRMA implementation in Go. It contains multiple libraries and applications:

* The commandline tool [`yivi`](https://docs.yivi.app/irma-cli/), which contains an [IRMA server](https://docs.yivi.app/irma-server/); subcommands for manipulating [IRMA schemes](https://docs.yivi.app/schemes/), generating IRMA issuer public/private keypairs, performing test IRMA sessions on the command line; and more.
* The Go library [`irmaserver`](https://docs.yivi.app/irma-server-lib/) providing a HTTP server that handles IRMA session with the [IRMA mobile app](https://github.com/privacybydesign/irma_mobile), and functions for starting and managing IRMA sessions.
* The root package `irma` contains generic IRMA functionality used by all other components below, such as parsing [IRMA schemes](https://docs.yivi.app/schemes/), parsing [IRMA metadata attributes](https://docs.yivi.app/technical-overview#the-metadata-attribute), and structs representing messages of the IRMA protocol.
* The Go package `irmaclient` is a library that serves as the client in the IRMA protocol; it can receive and disclose IRMA attributes and store and read them from storage. It also implements the [keyshare protocol](https://github.com/privacybydesign/irma_keyshare_server) and handles registering to keyshare servers. The [IRMA mobile app](https://github.com/privacybydesign/irma_mobile) uses `irmaclient`.
* The Go package `client` is a unified wallet client that combines the classic `irmaclient` with support for the European Digital Identity (EUDI) standards. It is built around the `eudi` packages described below and is used by the Yivi app to issue, store and present credentials over both the IRMA and the OpenID4VC protocol families.

## Standards and credential formats

`irmago` has evolved from an IRMA-only implementation into a crypto-agile wallet stack that speaks both the original IRMA protocol and the OpenID for Verifiable Credentials (OpenID4VC) family of standards used by the European Digital Identity (EUDI) ecosystem.

### Supported protocols

* **IRMA** — the original issuance and disclosure protocol based on Idemix attribute-based credentials.
* **OpenID4VCI** ([OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)) — credential issuance supporting both the Pre-Authorized Code flow (with optional transaction code) and the Authorization Code flow with Pushed Authorization Requests (PAR), in-app browser authorization and PKCE. Implemented in `eudi/openid4vci`.
* **OpenID4VP** ([OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)) — credential presentation supporting the `direct_post` and `direct_post.jwt` response modes and credential selection via [DCQL](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l) (Digital Credentials Query Language), including credential sets and optional cryptographic holder binding. Implemented in `eudi/openid4vp`.

### Supported credential formats

* **IRMA / Idemix** (`idemix`) — the classic IRMA credential format.
* **SD-JWT VC** (`dc+sd-jwt`) — [Selective Disclosure JWT Verifiable Credentials](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/), with selectively disclosable nested and array claims, batch issuance over OpenID4VCI and presentation over OpenID4VP. Implemented in `eudi/credentials/sdjwtvc`.

### Cryptographic agility

The EUDI client's architecture is designed to accommodate multiple signature schemes, holder binding methods and DID methods side by side, so that algorithms and key representations can evolve without changing the surrounding protocol code:

* **Signature algorithms**: holder signing currently uses ES256 (ECDSA over P-256). Issuer-signature verification is algorithm-agile via [`lestrrat-go/jwx`](https://github.com/lestrrat-go/jwx).
* **Holder binding**: `jwk`, `did:key`, `did:jwk` and COSE key binding.
* **DID methods**: `did:web`, `did:jwk` and `did:key` resolution for verifying issuers and verifiers.

Sensitive material such as holder binding keys, key metadata and issued credentials is stored encrypted at rest using [SQLCipher](https://www.zetetic.net/sqlcipher/) (see [Prerequisites](#prerequisites)).

## Documentation

Technical documentation of all components of `irmago` and more can be found at https://docs.yivi.app.

## Running (development)

The easiest way to run the `yivi` command line tool for development purposes is using Docker.

    docker-compose run yivi

For example, to start a simple IRMA session:

    IP=192.168.1.2 # Replace with your local IP address.
    docker-compose run -p 48680:48680 yivi irma session --disclose pbdf.sidn-pbdf.email.email --url "http://$IP:48680"

You can run the `yivi irma keyshare` services locally using the test configuration in `testdata/configurations`.

    # To run the IRMA keyshare server
    docker-compose run -p 8080:8080 yivi irma keyshare server -c ./testdata/configurations/keyshareserver.yml
    # To run the MyIRMA backend server
    docker-compose run -p 8081:8081 yivi irma keyshare myirmaserver -c ./testdata/configurations/myirmaserver.yml

## Prerequisites

### SQLCipher

The EUDI (European Digital Identity) client code uses [SQLCipher](https://www.zetetic.net/sqlcipher/) to provide encrypted-at-rest SQLite storage for sensitive data such as holder binding keys and key metadata. SQLCipher encrypts the entire database file, ensuring credentials and cryptographic material are protected when not in use.

This prerequisite is only relevant if you are building or developing the EUDI client library (`client`). If you are only running the `yivi` server or command line tool, you can skip this section.

Because SQLCipher relies on CGO bindings, you need to have the SQLCipher library and its development headers installed on your system before building.

**macOS** (using Homebrew):

    brew install sqlcipher

**Debian/Ubuntu**:

    sudo apt-get install libsqlcipher-dev

**Fedora/RHEL**:

    sudo dnf install sqlcipher-devel

You can verify the installation by running:

    pkg-config --libs sqlcipher

## SQLCipher on Windows

    Installing SQLCipher for Windows can be done in 2 steps:
    - Install MSYS2 via https://github.com/msys2/msys2-installer/, make sure the install path is `C:\msys64\`
    - Add the path `C:\msys64\user\bin` to your PATH environment variable
    - Install SQLCipher using `pacman`:  `pacman -S mingw-w64-x86_64-sqlcipher`
    - Verify installation by running `sqlcipher` in a new CMD/PowerShell windows


> **Note:** Pre-compiled release binaries are built with `CGO_ENABLED=0` and do not include SQLCipher. This prerequisite only applies when building from source.

## Installing
### Using Go
To install the latest released version of the `yivi` command line tool using Go, you do the following.

    go install github.com/privacybydesign/irmago/yivi@latest

You can also specify an exact version, from version v1.0.0 or newer. You should replace `v0.0.0` with the desired version number.
  
    go install github.com/privacybydesign/irmago/yivi@v0.0.0

The `yivi` command is only available from v1.0.0 and newer. If you want to use an older version of IRMA, use the command below.

    go install github.com/privacybydesign/irmago/irma@v0.0.0

### Using a container
If you want a container image of the `yivi` command line tool, then you can use our `ghcr.io/privacybydesign/yivi` image.

    docker run ghcr.io/privacybydesign/yivi:latest

The images are tagged in the following way:
- `latest`: latest released version of `yivi`
- `edge`: HEAD of the main development branch (`master`)
- `v0.0.0`: `yivi` version (replace `v0.0.0` with the desired version number)

When you build for production, we recommend you to use the [latest release](https://github.com/privacybydesign/irmago/releases/latest).

In case you want to use `v0.12.6` or lower, then you should build it yourself.

    VERSION=v0.8.0
    git checkout $VERSION
    git checkout master -- Dockerfile
    docker build -t privacybydesign/irma:$VERSION .

### Using pre-compiled binaries
You can find pre-compiled binaries of the `yivi` command line tool on the [GitHub release page](https://github.com/privacybydesign/irmago/releases).
We recommend you to use the [latest release](https://github.com/privacybydesign/irmago/releases/latest).

## Running the unit tests

Some of the unit tests connect to locally running external services, namely PostgreSQL, MySQL, Microsoft SQL Server and an SMTP server running at port 1025. These need to be up and running before these tests can be executed. This can be done using `docker-compose`.

### Running the tests

In case you chose to start PostgreSQL and MailHog using `docker-compose`, you first need to start these services:

    docker-compose up

When the databases and MailHog are running, the tests can be run using:

    go test -p 1 ./...

* The option `./...` makes sure all tests are run. You can also limit the number of tests by only running the tests from a single directory or even from a single file, for example only running all tests in the directory `./internal/sessiontest`. When you only want to execute one single test, for example the `TestDisclosureSession` test, you can do this by adding the option `-run TestDisclosureSession`.
* The option `-p 1` is necessary to prevent parallel execution of tests. Most tests use file manipulation and therefore tests can interfere.

### Running without Docker

If installing Docker or Docker alternatives is not an option for you, then you can exclude all tests that use those by additionally passing `--tags=local_tests`:

    go test -p 1 --tags=local_tests ./...

### Running without Go

You can also run the tests fully in Docker using the command below. This is useful when you don't want to install the Go compiler locally. By default, all tests are run one-by-one without parallel execution.

    docker-compose run test

You can override the default command by specifying command line options for `go test` manually, for example:

    docker-compose run test ./internal/sessiontest -run TestDisclosureSession

We always enforce the `-p 1` option to be used (as explained [above](#running-the-tests)).

## Using a local Redis datastore
`irmago` can either store session states in memory (default) or in a Redis datastore. For local testing purposes you can use the standard [Redis docker container](https://hub.docker.com/_/redis):

```
docker pull redis
docker run --name redis-test-instance -p 6379:6379 -d redis
```

You can then start `yivi irma` with the store-type flag set to Redis and the [default configuration file](testdata/configurations/redis.yml).

```
yivi irma server -vv --store-type redis --redis-addr "localhost:6379" --redis-allow-empty-password --redis-no-tls
```

If you use Redis in Sentinel mode for high availability, you need to consider whether you accept the risk of losing session state in case of a failover. Redis does not guarantee [strong consistency](https://redis.io/docs/management/scaling/#redis-cluster-consistency-guarantees) in these setups. We mitigated this by waiting for a write to have reached the master node and at least one replica. This means that at least two replicas should be configured for every master node to achieve high availability. Even then, there is a small chance of losing session state when a replica fails at the same time as the master node. For example, this might be problematic if you want to guarantee that a credential is not issued twice or if you need a session QR to have a long lifetime but you do want the session to be finished soon after the QR is scanned. If you require IRMA sessions to be highly consistent, you should use the default in-memory store or Redis in standalone mode. If you accept this risk, then you can enable Sentinel mode support by setting the `--redis-accept-inconsistency-risk` flag.

Besides the `yivi irma server`, Redis can also be configured for the `yivi irma keyshare server` and the `yivi irma keyshare myirmaserver` in the same way as described above. Note that the `yivi irma keyshare server` does not become stateless when using Redis, because it stores the keyshare commitments and authentication challenges in memory. These cannot be stored in Redis, because we require this data to be strongly consistent. Instead, you can use sticky sessions to make sure that the same user is always routed to the same keyshare server instance. The stored commitments and challenges are only relevant for a few seconds, so the risk of losing this data is low. The `yivi irma keyshare myirmaserver` does become stateless when using Redis.

## Performance tests
This project only includes performance tests for the `yivi irma keyshare server`. These tests can be run using the [k6 load testing tool](https://k6.io/docs/) and need a running keyshare server instance to test against. Instructions on how to run a keyshare server locally can be found [above](#running).

The performance tests can be started in the following way:

```
go install go.k6.io/k6@latest
k6 run ./testdata/performance/keyshare-server.js --env URL=http://localhost:8080 --env ISSUER_ID=test.test
```

By default, k6 runs a single test iteration using 1 virtual user. These defaults can be adjusted by specifying test stages using the [`-s` CLI parameter](https://k6.io/docs/using-k6/options/#stages).

## Contact
Request access to our IRMA slack channel by mailing to [our support](mailto:support@yivi.app) if you want to become part of the community. In our slack channels, the latest news on IRMA are shared and technical details get discussed.

For responsible disclosure mail to [our responsible disclosure mailbox](mailto:support@yivi.app)

<!-- vim: set ts=4 sw=4: -->
