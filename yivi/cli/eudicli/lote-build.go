package eudicli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/privacybydesign/irmago/eudi/trust/lote"
	"github.com/spf13/cobra"
)

var loteBuildCmd = &cobra.Command{
	Use:   "build <dir>",
	Short: "Build an unsigned LoTE from a curation directory",
	Long: `Build an unsigned List of Trusted Entities from a curation directory.

The directory holds the scheme's own information, one file per listed entity, and
the certificates those entities are recognized by:

    trustlist/
      scheme.json                  the scheme information and sequence number
      entities/
        example-municipality.json  one trusted entity per file
      certs/
        example-verifier.crt       referenced by filename from an entity

Entity files are read in filename order, and certificates are read rather than
transcribed — a service keyed on "certificate_skis" gets the subject key
identifier out of the named certificate, so an entry cannot be keyed on a value
the wallet's lookup would never match.

The output is a conformant Annex A document with the signature still to come. The
issue time is stamped now and NextUpdate derived from it, so build and sign belong
in the same release step.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := cmd.Flags().GetString("output")
		if err != nil {
			return err
		}
		issuedAtFlag, err := cmd.Flags().GetString("issued-at")
		if err != nil {
			return err
		}

		// Now by default, overridable so a build of unchanged input can be made
		// byte-identical — which is what lets a reviewer diff two issues.
		issuedAt := time.Now().UTC().Truncate(time.Second)
		if issuedAtFlag != "" {
			issuedAt, err = time.Parse(time.RFC3339, issuedAtFlag)
			if err != nil {
				return fmt.Errorf("invalid --issued-at: %w", err)
			}
			issuedAt = issuedAt.UTC()
		}

		list, err := loadSource(args[0], issuedAt)
		if err != nil {
			return err
		}

		raw, err := json.MarshalIndent(lote.Document{LoTE: list}, "", "  ")
		if err != nil {
			return err
		}
		raw = append(raw, '\n')

		if out == "" || out == "-" {
			_, err = os.Stdout.Write(raw)
			return err
		}
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			return err
		}

		Logger.Infof("built %s: %d entities, sequence number %d, next update %s",
			out, len(list.Entities), list.SchemeInformation.SequenceNumber,
			list.SchemeInformation.NextUpdate.Format(time.RFC3339))
		return nil
	},
}

func init() {
	loteCmd.AddCommand(loteBuildCmd)

	loteBuildCmd.Flags().StringP("output", "o", "", "write the document here (default stdout)")
	loteBuildCmd.Flags().String("issued-at", "",
		"RFC 3339 issue time (default now); set it to make a rebuild byte-identical")
}
