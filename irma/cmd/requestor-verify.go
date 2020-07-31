package cmd

import (
	"os"
	"path/filepath"

	"fmt"

	irma "github.com/privacybydesign/irmago"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyRequestorCmd = &cobra.Command{
	Use:   "verify [<path>]",
	Short: "Verify requestor scheme folder correctness and authenticity",
	Long:  `The verify command parses the specified directory, or the current directory if not specified, and checks the signature and validity of the contained requestor scheme.`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var path string
		if len(args) > 0 {
			path = args[0]
		} else {
			path, err = os.Getwd()
			if err != nil {
				return err
			}
		}
		if err = VerifyRequestor(path); err == nil {
			fmt.Println()
			fmt.Println("Verification was successful.")
		} else {
			die("Verification failed", err)
		}
		return nil
	},
}

func VerifyRequestor(path string) error {
	conf, err := irma.NewConfiguration(filepath.Dir(path), irma.ConfigurationOptions{ReadOnly: true})
	if err != nil {
		return err
	}

	if err = conf.ParseRequestorScheme(path); err != nil {
		return err
	}

	for _, warning := range conf.Warnings {
		fmt.Println("Warning: " + warning)
	}
	return nil
}

func init() {
	requestorCmd.AddCommand(verifyRequestorCmd)
}
