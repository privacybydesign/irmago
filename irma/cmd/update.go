package cmd

import (
	"io/ioutil"
	"path/filepath"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/server"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update [path...]",
	Short: "Update a scheme",
	Long:  updateHelp(),
	Run: func(cmd *cobra.Command, args []string) {
		var paths []string
		irmaconf := server.DefaultSchemesPath()
		if len(args) != 0 {
			paths = args
		} else {
			if irmaconf == "" {
				die("Failed to find default irma_configuration path", nil)
			}
			files, err := ioutil.ReadDir(irmaconf)
			if err != nil {
				die("Failed to read default irma_configuration path", err)
			}
			paths = make([]string, 0, len(files))
			for _, file := range files {
				if file.IsDir() {
					paths = append(paths, filepath.Join(irmaconf, file.Name()))
				}
			}
		}

		if err := updateSchemeManager(paths); err != nil {
			die("Updating schemes failed", err)
		}
	},
}

func updateSchemeManager(paths []string) error {
	// Before doing anything, first check that all paths are scheme managers
	for _, path := range paths {
		if err := fs.AssertPathExists(filepath.Join(path, "index")); err != nil {
			return errors.Errorf("%s is not a valid scheme manager (%s)", path, err.Error())
		}
	}

	for _, path := range paths {
		path, err := filepath.Abs(path)
		irmaconf, manager := filepath.Dir(path), filepath.Base(path)

		conf, err := irma.NewConfiguration(irmaconf)
		if err != nil {
			return err
		}
		if err := conf.ParseSchemeManagerFolder(path, irma.NewSchemeManager(manager)); err != nil {
			return err
		}

		if err = conf.UpdateSchemeManager(irma.NewSchemeManagerIdentifier(manager), nil); err != nil {
			return err
		}
	}

	return nil
}

func updateHelp() string {
	defaultIrmaconf := server.DefaultSchemesPath()
	str := "The update command updates an IRMA scheme within an irma_configuration folder by comparing its index with the online version, and downloading any new and changed files.\n\n"
	if defaultIrmaconf != "" {
		str += "If no paths are given, the default schemes at " + defaultIrmaconf + " are updated.\n\n"
	}
	str += "Careful: this command could fail and invalidate or destroy your scheme manager folder! Use this only if you can restore it from git or backups."
	return str
}

func init() {
	schemeCmd.AddCommand(updateCmd)
}
