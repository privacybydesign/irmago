package cmd

import (
	"path/filepath"

	"github.com/privacybydesign/irmago/server"
	"github.com/spf13/cobra"
)

// schemeCmd represents the scheme command
var schemeCmd = &cobra.Command{
	Use:   "scheme",
	Short: "Manage IRMA schemes",
}

func init() {
	RootCmd.AddCommand(schemeCmd)
}

func defaultIrmaconfPath() string {
	cachepath, err := server.CachePath()
	if err != nil {
		return ""
	}
	return filepath.Join(cachepath, "irma_configuration")
}
