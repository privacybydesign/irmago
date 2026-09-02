# Example curation directory

The curation format `yivi eudi config build` compiles into a wallet configuration:
`config.json` with the config's own information, and one directory per trusted
entity holding `entity.json` and the certificates it names by bare filename. The
directory name is the entity id.

Building it with `--issued-at 2026-09-02T12:00:00Z` reproduces the payload in
`../golden/config.json`; the CLI tests check that, so the example cannot rot into
something `build` would refuse. Regenerate both with:

    go run ./testdata/walletconfig/mkgolden
