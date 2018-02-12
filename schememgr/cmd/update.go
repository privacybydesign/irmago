package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/spf13/cobra"
)

// TODO: add flag to update timestamp of irma_configuration folder
var updateCmd = &cobra.Command{
	Use:   "update path...",
	Short: "[Experimental] Update a scheme manager",
	Long: `The update command updates a scheme manager within an irma_configuration folder by comparing its index with the online version, and downloading any new and changed files.

Careful: this command could fail and invalidate or destroy your scheme manager folder! Use this only if you can restore it from git or backups.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return updateSchemeManager(args)
	},
}

func init() {
	RootCmd.AddCommand(updateCmd)
}

func updateSchemeManager(paths []string) error {
	// Before doing anything, first check that all paths are scheme managers
	for _, path := range paths {
		if err := fs.AssertPathExists(filepath.Join(path, "index")); err != nil {
			return errors.Errorf("%s is not a valid scheme manager (%s)", path, err.Error())
		}
	}

	for _, path := range paths {
		if strings.HasSuffix(path, string(os.PathSeparator)) {
			path = path[:len(path)-1]
		}
		irmaconf, manager := filepath.Dir(path), filepath.Base(path)

		// TODO: this parses all managers within the irma_configuration folder, not just the one specified
		// Should make a Configuration constructor that parses just one manager
		conf, err := irma.NewConfiguration(irmaconf, "")
		if err != nil {
			return err
		}
		if err := conf.ParseFolder(); err != nil {
			return err
		}

		if err = conf.UpdateSchemeManager(irma.NewSchemeManagerIdentifier(manager), nil); err != nil {
			return err
		}
	}

	return nil
}
