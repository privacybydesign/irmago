package eudicli

import "github.com/spf13/cobra"

// loteCmd groups the publishing tools for a List of Trusted Entities. Production
// hosting is not among them: the wallet asks for a plain unconditional GET of a
// signed blob, so publishing is `build`, `sign`, and copying the file onto static
// hosting. `serve` is for development and staging.
var loteCmd = &cobra.Command{
	Use:   "lote",
	Short: "Build, sign and inspect a List of Trusted Entities",
	Long: `Build, sign and inspect an ETSI TS 119 602 List of Trusted Entities (LoTE).

The document produced is a scheme-explicit LoTE in the Annex A JSON binding,
signed as a compact JAdES Baseline B signature. See
docs/plans/yivi-lote-publishing.md for the contract the wallet enforces.

A typical release:

    yivi eudi lote build ./trustlist -o list.json
    yivi eudi lote sign list.json --key signer.key --cert signer.crt \
        --anchor root.crt -o list.jws
    yivi eudi lote verify list.jws --anchor root.crt \
        --against https://trustlist.yivi.app/lote
    # then copy list.jws onto static hosting`,
}

func init() {
	EudiRootCmd.AddCommand(loteCmd)
}
