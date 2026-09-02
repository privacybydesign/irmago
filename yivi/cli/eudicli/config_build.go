package eudicli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var configBuildCmd = &cobra.Command{
	Use:   "build <dir>",
	Short: "Build an unsigned wallet configuration from a curation directory",
	Long: `Build an unsigned wallet configuration from a curation directory.

The directory holds the config's own information and one directory per trusted
entity, each holding that entity and the certificates it is recognized by:

    curation/
      config.json                    id, environment, policy, freshness window
      entities/
        yivi-issuers/
          entity.json                the trusted entity; the directory name is its id
          root.crt                   referenced by bare filename from entity.json
          issuing-ca.crt

Entities are read in directory-name order, so a rebuild of unchanged input is
byte-identical. Certificates are read rather than transcribed, and resolved
inside their own entity's directory, so an entity can name only its own.
Curation files are read strictly: a member this tool does not know is a typo
and is refused, where the wallet would silently ignore it on the wire.

The output is the payload the wallet reads, validated as the wallet validates
it, with the signature still to come. The issue time is stamped now and
next_update derived from it, so build and sign belong in the same release step.

The version normally comes from --version rather than from config.json: the
wallet refuses a config whose version is below the one it holds, so the number
must never go down relative to what is published, which is bookkeeping against
the live config and belongs to whatever publishes rather than to whoever
curates. A re-signing of the same version with a later issue time is adopted by
the wallet, so a missed bump delays nothing.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		out, _ := cmd.Flags().GetString("output")
		issuedAtFlag, _ := cmd.Flags().GetString("issued-at")
		version, _ := cmd.Flags().GetUint64("version")

		issuedAt := time.Now()
		if issuedAtFlag != "" {
			var err error
			if issuedAt, err = time.Parse(time.RFC3339, issuedAtFlag); err != nil {
				return fmt.Errorf("invalid --issued-at: %w", err)
			}
		}

		config, err := loadSource(args[0], buildOptions{IssuedAt: issuedAt, Version: version})
		if err != nil {
			return err
		}
		raw, err := configJSON(config)
		if err != nil {
			return err
		}

		if out == "" || out == "-" {
			_, err = cmd.OutOrStdout().Write(raw)
			return err
		}
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			return err
		}
		Logger.Infof("built %s: %s for %s, version %d, %d entities, next update %s",
			out, config.ID, config.Environment, config.Version, len(config.TrustedEntities),
			config.NextUpdate.Format(time.RFC3339))
		return nil
	},
}

func init() {
	configCmd.AddCommand(configBuildCmd)

	configBuildCmd.Flags().StringP("output", "o", "", "write the config here (default stdout)")
	configBuildCmd.Flags().Uint64("version", 0,
		"version to stamp; overrides config.json. Must never go down relative to the published config")
	configBuildCmd.Flags().String("issued-at", "",
		"RFC 3339 issue time (default now); set it to make a rebuild byte-identical")
}
