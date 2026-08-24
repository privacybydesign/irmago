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
signed as a compact JAdES Baseline B signature.

A release, as the publishing job runs it. The sequence number is the publisher's:
clause 6.3.2 defines it relative to the list already in force, so it comes from
what is published rather than from the curation directory.

    yivi eudi lote build ./trustlist --sequence-number $((live + 1)) -o list.json
    yivi eudi lote sign list.json --key signer.key --cert signer.crt \
        --anchor root.crt -o list.jws
    yivi eudi lote verify list.jws --anchor root.crt \
        --against https://trustlist.yivi.app/lote
    # then copy list.jws onto static hosting

A pull-request check, which holds no key and publishes nothing:

    yivi eudi lote keygen --out-dir throwaway --organization Yivi
    yivi eudi lote build ./trustlist --sequence-number 1 -o built.json
    yivi eudi lote sign built.json --key throwaway/signer.key \
        --cert throwaway/signer.crt --anchor throwaway/ca.crt -o built.jws
    yivi eudi lote show published.jws --json > published.json
    diff published.json built.json`,
}

func init() {
	EudiRootCmd.AddCommand(loteCmd)
}
