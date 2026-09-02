# Golden wallet config

A committed, signed wallet config for `eudi/walletconfig`'s golden tests: the one
document in the suite the package did not marshal itself, so the only one that
notices a JSON tag or header changing.

- `config.jws` — the signed config (compact JWS, `typ: yivi-wallet-config+jwt`, ES256).
- `config.json` — the same payload in readable form; a test keeps the two honest.
- `root.crt` — the config root the tests pin as the `golden` environment's signing root.
- `intermediate.crt`, `signer.crt` — the rest of the chain, as carried in `x5c`.

Dates are fixed (issued 2026-09-02, certificates valid from 2026-09-01 for decades)
and the tests pin their clock, so the fixture does not rot.

Regenerate with:

    go run ./testdata/walletconfig/mkgolden
