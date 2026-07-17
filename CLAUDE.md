# irmago — repo notes for coding agents

- Building requires SQLCipher via cgo: `eudi/storage/db/sqlcipher` uses `pkg-config: sqlcipher` (CI installs `libsqlcipher-dev`). Without it, `go build ./...` fails on that package only; a local build of SQLCipher with a hand-written `sqlcipher.pc` (Libs: `-lsqlite3 -lcrypto`) works too.
- Every PR must either update `CHANGELOG.md` under `## Unreleased` or carry the `skip-changelog` label (enforced by `.github/workflows/changelog.yml`).
- CI unit tests run `docker compose run test -v ./...`; locally a plain `go test ./...` works when SQLCipher is available. The `internal/sessiontest` package hard-codes listeners on ports 48680-48699.
- Lint gates: `gofmt`, `go vet`, `go fix -diff`, `ineffassign`, `misspell`, and `staticcheck -checks "all,-ST1000,-ST1003,-SA1019,-SA1029"`.
