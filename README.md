# irmago &nbsp; [![GoDoc](https://godoc.org/github.com/privacybydesign/irmago?status.svg)](https://godoc.org/github.com/privacybydesign/irmago) [![Go Report Card](https://goreportcard.com/badge/github.com/privacybydesign/irmago)](https://goreportcard.com/report/github.com/privacybydesign/irmago)

`irmago` is an IRMA implementation in Go. It contains multiple libraries and applications:

* The commandline tool [`irma`](https://irma.app/docs/irma-cli/), which contains an [IRMA server](https://irma.app/docs/irma-server/); subcommands for manipulating [IRMA schemes](https://irma.app/docs/schemes/), generating IRMA issuer public/private keypairs, performing test IRMA sessions on the command line; and more.
* The Go library [`irmaserver`](https://irma.app/docs/irma-server-lib/) providing a HTTP server that handles IRMA session with the [IRMA mobile app](https://github.com/privacybydesign/irma_mobile), and functions for starting and managing IRMA sessions.
* The root package `irma` contains generic IRMA functionality used by all other components below, such as parsing [IRMA schemes](https://irma.app/docs/schemes/), parsing [IRMA metadata attributes](https://irma.app/docs/overview#the-metadata-attribute), and structs representing messages of the IRMA protocol.
* The Go package `irmaclient` is a library that serves as the client in the IRMA protocol; it can receive and disclose IRMA attributes and store and read them from storage. It also implements the [keyshare protocol](https://github.com/privacybydesign/irma_keyshare_server) and handles registering to keyshare servers. The [IRMA mobile app](https://github.com/privacybydesign/irma_mobile) uses `irmaclient`.

## Documentation

Technical documentation of all components of `irmago` and more can be found at https://irma.app/docs.

## Running (development)

The easiest way to run the `irma` command line tool for development purposes is using Docker.

    docker-compose run irma

For example, to start a simple IRMA session:

    IP=192.168.1.2 # Replace with your local IP address.
    docker-compose run -p 48680:48680 irma session --disclose pbdf.sidn-pbdf.email.email --url "http://$IP:48680"

You can run the `irma keyshare` services locally using the test configuration in `testdata/configurations`.

    # To run the IRMA keyshare server
    docker-compose run -p 8080:8080 irma keyshare server -c ./testdata/configurations/keyshareserver.yml
    # To run the MyIRMA backend server
    docker-compose run -p 8081:8081 irma keyshare myirmaserver -c ./testdata/configurations/myirmaserver.yml

## Installing
### Using Go
To install the latest released version of the `irma` command line tool using Go, you do the following.

    go install github.com/privacybydesign/irmago/irma@latest

You can also specify an exact version. You should replace `v0.0.0` with the desired version number.
  
    go install github.com/privacybydesign/irmago/irma@v0.0.0

### Using a container
If you want a container image of the `irma` command line tool, then you can use our `ghcr.io/privacybydesign/irma` image.

    docker run ghcr.io/privacybydesign/irma:latest

The images are tagged in the following way:
- `latest`: latest released version of `irma`
- `edge`: HEAD of the main development branch (`master`)
- `v0.0.0`: `irma` version (replace `v0.0.0` with the desired version number)

When you build for production, we recommend you to use the [latest release](https://github.com/privacybydesign/irmago/releases/latest).

In case you want to use `v0.12.6` or lower, then you should build it yourself.

    VERSION=v0.8.0
    git checkout $VERSION
    git checkout master -- Dockerfile
    docker build -t privacybydesign/irma:$VERSION .

### Using pre-compiled binaries
You can find pre-compiled binaries of the `irma` command line tool on the [GitHub release page](https://github.com/privacybydesign/irmago/releases).
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

You can then start `irma` with the store-type flag set to Redis and the [default configuration file](testdata/configurations/redis.yml).

```
irma server -vv --store-type redis --redis-addr "localhost:6379" --redis-allow-empty-password --redis-no-tls
```

If you use Redis in Sentinel mode for high availability, you need to consider whether you accept the risk of losing session state in case of a failover. Redis does not guarantee [strong consistency](https://redis.io/docs/management/scaling/#redis-cluster-consistency-guarantees) in these setups. This might be problematic if you want to guarantee that a credential is not issued twice or if you need a session QR to have a long lifetime but you do want the session to be finished soon after the QR is scanned. If you require IRMA sessions to be highly consistent, you should use the default in-memory store or Redis in standalone mode. If you accept this risk, then you can enable Sentinel mode support by setting the `--redis-accept-inconsistency-risk` flag.

If you use a managed Redis service from a cloud provider, please be aware that if you enable high availability or cluster mode, they use Redis Cluster or Redis Sentinel under water. The `irma server` does not automatically detect this, so it does not require you to set the `--redis-accept-inconsistency-risk` flag. However, the same inconsistency risks hold here too.

Besides the `irma server`, Redis can also be configured for the `irma keyshare server` and the `irma keyshare myirmaserver` in the same way as described above. Note that the `irma keyshare server` does not become stateless when using Redis, because it stores the keyshare commitments and authentication challenges in memory. These cannot be stored in Redis, because we require this data to be strongly consistent. Instead, you can use sticky sessions to make sure that the same user is always routed to the same keyshare server instance. The stored commitments and challenges are only relevant for a few seconds, so the risk of losing this data is low. The `irma keyshare myirmaserver` does become stateless when using Redis.

## Performance tests
This project only includes performance tests for the `irma keyshare server`. These tests can be run using the [k6 load testing tool](https://k6.io/docs/) and need a running keyshare server instance to test against. Instructions on how to run a keyshare server locally can be found [above](#running).

The performance tests can be started in the following way:

```
go install go.k6.io/k6@latest
k6 run ./testdata/performance/keyshare-server.js --env URL=http://localhost:8080 --env ISSUER_ID=test.test
```

By default, k6 runs a single test iteration using 1 virtual user. These defaults can be adjusted by specifying test stages using the [`-s` CLI parameter](https://k6.io/docs/using-k6/options/#stages).

## Contact
Request access to our IRMA slack channel by mailing to [our support](mailto:support@yivi.app) if you want to become part of the community. In our slack channels, the latest news on IRMA are shared and technical details get discussed.

For responsible disclosure mail to [our responsible disclosure mailbox](mailto:responsible.disclosure@sidn.nl)

<!-- vim: set ts=4 sw=4: -->
