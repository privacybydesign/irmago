package cmd

import (
	"path/filepath"

	"fmt"

	"github.com/credentials/irmago"
	"github.com/go-errors/errors"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify irma_configuration_path",
	Short: "Verify irma_configuration folder correctness and authenticity",
	Long:  `The verify command parses the specified irma_configuration folder and checks the signatures of the contained scheme managers.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		if filepath.Base(path) != "irma_configuration" {
			return errors.New("Path is not irma_configuration")
		}

		conf, err := irma.NewConfiguration(path, "")
		if err != nil {
			return err
		}
		if err := conf.ParseFolder(); err != nil {
			return err
		}

		for _, manager := range conf.SchemeManagers {
			for file := range manager.Index {
				// Don't care about the actual bytes
				if _, err := conf.ReadAuthenticatedFile(manager, file); err != nil {
					return err
				}
			}
		}

		fmt.Println()
		fmt.Println("irma_configuration parsed and authenticated successfully.")
		return nil
	},
}

func init() {
	RootCmd.AddCommand(verifyCmd)
}
