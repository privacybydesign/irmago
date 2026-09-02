package eudicli

import "github.com/spf13/cobra"

// configCmd groups the publishing tools for the wallet configuration. Production
// hosting is not among them: the wallet asks for a plain unconditional GET of a
// signed blob, so publishing is `build`, `sign`, and copying the file onto static
// hosting. `serve` is for development and staging.
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Build, sign and inspect a wallet configuration",
	Long: `Build, sign and inspect a Yivi wallet configuration.

The wallet configuration is the one signed document per environment that says
who Yivi vouches for on the OpenID4VC side of the wallet, how much, and under
what policy. It is compiled from a curation directory — one file for the
config's own information, one directory per trusted entity — into the JSON
payload the wallet reads, and signed as a compact JWS under the environment's
config CA.

A release, as the publishing job runs it:

    yivi eudi config build ./curation --version $((live + 1)) -o config.json
    yivi eudi config sign config.json --key signer.key --cert chain.pem \
        --root root.crt -o config.jws
    yivi eudi config verify config.jws --root root.crt \
        --against https://config.yivi.app/wallet-config/v1/
    # then copy config.jws onto static hosting

A pull-request check, which holds no key and publishes nothing:

    yivi eudi config keygen --out-dir throwaway
    yivi eudi config build ./curation -o built.json
    yivi eudi config sign built.json --key throwaway/signer.key \
        --cert throwaway/chain.pem --root throwaway/root.crt -o built.jws
    yivi eudi config show published.jws --json > published.json
    diff published.json built.json`,
}

func init() {
	EudiRootCmd.AddCommand(configCmd)
}
