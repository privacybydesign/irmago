package cmd

import (
	"path/filepath"

	"fmt"

	"github.com/privacybydesign/irmago"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify irma_configuration_path",
	Short: "Verify irma_configuration folder correctness and authenticity",
	Long:  `The verify command parses the specified irma_configuration folder and checks the signatures of the contained scheme managers.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		err := RunVerify(args[0])
		if err == nil {
			fmt.Println()
			fmt.Println("irma_configuration parsed and authenticated successfully.")
		}
		return err
	},
}

func RunVerify(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if filepath.Base(path) != "irma_configuration" {
		fmt.Printf("Notice: specified folder name is '%s'; when using in IRMA applications it should be called 'irma_configuration'\n", filepath.Base(path))
	}

	conf, err := irma.NewConfiguration(path, "")
	if err != nil {
		return err
	}
	if err := conf.ParseFolder(); err != nil {
		return err
	}

	for _, manager := range conf.SchemeManagers {
		if err := conf.VerifySchemeManager(manager); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	RootCmd.AddCommand(verifyCmd)
}
