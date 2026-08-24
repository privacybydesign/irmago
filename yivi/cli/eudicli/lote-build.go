package eudicli

import (
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

The directory holds the scheme's own information and one directory per listed
entity, each holding that entity and the certificates it is recognized by:

    trustlist/
      scheme.json                    the scheme information
      entities/
        example-municipality/
          entity.json                the trusted entity
          example-verifier.crt       referenced by bare filename from entity.json

Entities are read in directory-name order, and certificates are read rather than
transcribed — a service keyed on "certificate_skis" gets the subject key
identifier out of the named certificate, so an entry cannot be keyed on a value
the wallet's lookup would never match. A certificate is named by bare filename and
resolved inside its own entity's directory, so an entity can name only its own.

The output is a conformant Annex A document with the signature still to come. The
issue time is stamped now and NextUpdate derived from it, so build and sign belong
in the same release step.

The sequence number normally comes from --sequence-number rather than from
scheme.json. Clause 6.3.2 requires it to be 1 at the first release, to be
incremented at every subsequent release, and never to be re-cycled or lowered —
which is bookkeeping against the list already in force, so it belongs to whatever
publishes rather than to whoever curates.`,
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
		sequenceNumber, err := cmd.Flags().GetUint64("sequence-number")
		if err != nil {
			return err
		}

		// Now by default, overridable so a build of unchanged input can be made
		// byte-identical for a reviewer to diff.
		issuedAt := time.Now().UTC().Truncate(time.Second)
		if issuedAtFlag != "" {
			issuedAt, err = time.Parse(time.RFC3339, issuedAtFlag)
			if err != nil {
				return fmt.Errorf("invalid --issued-at: %w", err)
			}
			issuedAt = issuedAt.UTC()
		}

		list, stats, err := loadSource(args[0], issuedAt, sequenceNumber)
		if err != nil {
			return err
		}

		// Withdrawals are absences in the output, so they are reported.
		if stats.WithdrawnServices > 0 {
			Logger.Infof("excluded %d withdrawn service(s): on a list carrying no statuses, a withdrawal is an absence",
				stats.WithdrawnServices)
		}
		for _, file := range stats.DroppedEntities {
			Logger.Infof("excluded %s entirely: all of its services are withdrawn", file)
		}

		raw, err := documentJSON(list)
		if err != nil {
			return err
		}

		// Validated against the normative Annex A schema before anything is
		// written: the checks above catch what a curator gets wrong, this catches
		// what the serialiser does.
		if err := lote.ValidateDocument(raw); err != nil {
			return err
		}

		if out == "" || out == "-" {
			_, err = os.Stdout.Write(raw)
			return err
		}
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			return err
		}

		Logger.Infof("built %s: %d entities, sequence number %d, next update %s (conforms to Annex A %s)",
			out, len(list.Entities), list.SchemeInformation.SequenceNumber,
			list.SchemeInformation.NextUpdate.Format(time.RFC3339), lote.SchemaVersion)
		return nil
	},
}

func init() {
	loteCmd.AddCommand(loteBuildCmd)

	loteBuildCmd.Flags().StringP("output", "o", "", "write the document here (default stdout)")
	loteBuildCmd.Flags().Uint64("sequence-number", 0,
		"LoTESequenceNumber to stamp; overrides scheme.json. Clause 6.3.2: 1 at the first release, incremented at every release, never lowered")
	loteBuildCmd.Flags().String("issued-at", "",
		"RFC 3339 issue time (default now); set it to make a rebuild byte-identical")
}
