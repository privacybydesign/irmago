# CLAUDE.md

Repo-specific notes for working in `irmago`. `README.md` covers installing the
`yivi` CLI, running it and running the keyshare services; read that first. This
file records only what is not obvious from it.

Unless marked otherwise, every command below was run successfully in a checkout
of this repo.

## Layout

- `irma/` is package `irma`: schemes, metadata attributes, protocol messages and
  verification logic. `irma/server/` holds the IRMA server, the requestor server
  and the keyshare and myirma servers. `irma/irmaclient/` is the wallet client
  library the Yivi app uses.
- `client/` is the EUDI wallet client. It wraps `irmaclient.IrmaClient` and wires
  the OpenID4VCI and OpenID4VP adapters onto it.
- `eudi/` holds the EUDI building blocks: DID methods (`didweb`, `didjwk`,
  `didkey`), credentials, OpenID4VCI, OpenID4VP, the trust model and holder
  storage under `eudi/storage/`.
- `internal/` is support and test code. `internal/sessiontest/` is the
  session-level suite that starts real servers; `internal/test/` and
  `internal/testhelpers/` hold shared fixtures.
- `common/clientmodels/` holds the models shared between the clients.
- `yivi/` is `main` for the `yivi` CLI, with the subcommands in `yivi/cli/`.
- The repo root is package `irmago` and contains only `Version` in `version.go`.

## Build

    go build ./...
    go build -o /tmp/yivi ./yivi

`go.mod` declares `go 1.26.0` and `toolchain go1.26.4`, so a system Go older than
that downloads the pinned toolchain on first use.

Release binaries are built with `CGO_ENABLED=0` (see `.github/actions/build` and
the `Dockerfile`), which also works locally:

    CGO_ENABLED=0 go build -o /tmp/yivi ./yivi

### SQLCipher is needed for `./client`

`eudi/storage/db/sqlcipher/driver.go` has `#cgo !android,!windows
pkg-config: sqlcipher`, so three packages need the SQLCipher development headers
at build time:

- `eudi/storage/db/sqlcipher`
- `eudi/storage/sqlcipherstorage`
- `client`

Without them, `go build ./client` fails on the driver package with `Package
sqlcipher was not found in the pkg-config search path`. Per-platform install
instructions are in the Prerequisites section of `README.md`; CI installs
`libsqlcipher-dev`. Verify with:

    pkg-config --libs sqlcipher

Nothing outside those three packages needs it, so `go build ./yivi` succeeds on a
machine without SQLCipher.

## Tests

`-p 1` is required everywhere: many tests manipulate files on disk and interfere
when run in parallel.

### Without any services

Everything except `internal/sessiontest` passes with nothing else running:

    go test -p 1 --tags=local_tests $(go list ./... | grep -v /internal/sessiontest)

The `local_tests` tag excludes the files that need Postgres, MySQL, SQL Server or
SMTP. Grep for `//go:build !local_tests` to see which ones.

Two things to know about this:

- The plain `go test -p 1 --tags=local_tests ./...` from `README.md` does not
  build at the moment. `internal/sessiontest/irma_issuance_test.go` (untagged)
  calls `startRevocationServer`, which is defined in `revocation_test.go` behind
  `//go:build !local_tests`, so the package fails with `undefined:
  startRevocationServer`. Excluding the package as above is the workaround.
- Redis is not a test dependency. `internal/sessiontest/redis_test.go` and
  `irma/server/keyshare/myirmaserver/session_test.go` run against in-process
  `miniredis`, and `docker-compose.yml` has no Redis service. The `docker run
  redis` snippet in `README.md` is for running a server by hand, not for tests.

### With the service dependencies

`internal/sessiontest` and the `!local_tests` files need the services in
`docker-compose.yml`. The tests reach them over `localhost`:

- `postgres` on 5432. The tests create the `irma` schema themselves: the
  keyshare, myirma and tasks packages each define `SetupDatabase(t)` (e.g.
  `irma/server/keyshare/keyshareserver/postgresdb_test.go:171`), which runs
  `cleanup.sql` and then `schema.sql`, and every Postgres test calls it first.
  So the database only has to be up. `docker-compose.yml` also has a one-shot
  `postgres-init` container running those same two scripts, but it sits in the
  `yivi` service's `depends_on`, not the `test` service's, so `docker compose
  run test` never starts it. It is there for running a keyshare or myirma
  server by hand. The connection string the tests use is `PostgresTestUrl` in
  `internal/test/postgres.go`.
- `mysql` on 3306 and `sqlserver` on 1433, used only by
  `internal/sessiontest/revocation_test.go`.
- `mailhog` on 1025 for the keyshare e-mail tests.
- `veramo_*`, `statuslist_agent`, `eudi_*` and `tls_proxy` for the EUDI
  OpenID4VCI and OpenID4VP session tests. `tls_proxy` terminates TLS for them on
  8443, 8444 and 8445 with the certificate in
  `testdata/configurations/certs/`.

`postgres` and `mailhog` get a `postgres.localhost` and `mailhog.localhost`
alias on the compose network. That is what lets one hostname in
`testdata/configurations/*.yml` resolve both from inside the network (the `yivi`
compose service) and from a host where the ports are published.

`internal/sessiontest` hard-codes listeners on 127.0.0.1:48680-48699 (see
`helper_servers_test.go`). Those ports sit inside Linux's default ephemeral
range, so a TIME_WAIT socket left by an earlier subtest can make a later
`ListenAndServe` fail with EADDRINUSE. CI narrows the range first with `sysctl -w
net.ipv4.ip_local_port_range="48700 60999"`.

CI runs the whole suite as `docker compose run test -v ./...`. The `test` service
builds `Dockerfile.test`, uses host networking and sets `CGO_ENABLED=1`. That
command and the `docker compose up` for the services above are the one part of
this file that was not verified by running it: the container these notes were
written in has the Docker client but no Docker daemon. Everything stated about
those services is read off `docker-compose.yml`, `Dockerfile.test` and
`.github/workflows/status-checks.yml`.

### testdata/configurations

`testdata/configurations/` holds ready-made server configs pointed at those
services: `keyshareserver.yml` and `myirmaserver.yml` (both using the
`postgres.localhost` and `mailhog.localhost` hostnames above),
`irmaserver-sdjwt.yml`, `issuer.yml`, `redis.yml`, `revocation.yml`,
`static.yml`, `requestorserver_nextsession.yml`, and in `certs/` the self-signed
certificate that the tests and `tls_proxy` share. The tests load these files
directly. For running a keyshare or myirma server by hand against them, use the
`docker-compose run yivi ... -c ./testdata/configurations/...` commands in
`README.md`.

## Lint

The `lint` job in `.github/workflows/status-checks.yml` runs, in order:

    gofmt -d -e . | (! grep ^)
    go vet ./...
    go fix -diff ./...
    ineffassign ./...
    find . -type f -not -path './testdata/*.json' | xargs misspell -error -i "adres,instelling,relatie"
    staticcheck -checks "all,-ST1000,-ST1003,-SA1019,-SA1029" ./...

All of them run without Docker. Two of them have sharp edges.

misspell covers every file in the tree, `.md` and `CHANGELOG.md` included, and
`-error` turns a single hit into a failing check. A typo in a changelog line is a
red build, not a review nit. The `-i` list holds Dutch words that misspell reads
as English typos.

staticcheck is pinned to 2025.1.1:

    go install honnef.co/go/tools/cmd/staticcheck@2025.1.1

Build it with a Go toolchain at least as new as the one in `go.mod`, otherwise it
refuses the module with `module requires at least go1.26.0, but Staticcheck was
built with go1.24.2` and reports nothing useful. If your default `go` is older,
pin the toolchain for the install:

    GOTOOLCHAIN=go1.26.4 go install honnef.co/go/tools/cmd/staticcheck@2025.1.1

A bare `staticcheck ./...` reads `staticcheck.conf`, which keeps SA1019 enabled,
and reports the pre-existing deprecation warnings CI hides (34 of them as of this
writing, all SA1019). CI adds `-SA1019` on the command line instead, as the
comment in `staticcheck.conf` notes. Use the CI invocation to see what actually
gates the PR.

`go fix -diff` is tied to the toolchain pinned in `go.mod`, so bumping that can
make the step fail on files your change never touched. Run `go fix ./...` and
commit the result when it does.

## Changelog

`.github/workflows/changelog.yml` fails a PR unless the diff between the base and
the head touches `CHANGELOG.md`, or the PR carries the `skip-changelog` label.
Add entries under `## Unreleased`, in the `### Added`, `### Fixed`, `### Security`
or `### Internal` subsection already used there.
