package cmd

import (
	"io/ioutil"
	"path/filepath"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sietseringers/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update [<path>...]",
	Short: "Update a scheme",
	Long:  updateHelp(),
	Run: func(cmd *cobra.Command, args []string) {
		var paths []string
		irmaconf := irma.DefaultSchemesPath()
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
		isscheme, err := common.IsScheme(path, true)
		if err != nil {
			return err
		}
		if !isscheme {
			return errors.Errorf("%s is not a scheme", path)
		}
	}

	for _, path := range paths {
		path, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		conf, err := irma.NewConfiguration(filepath.Dir(path), irma.ConfigurationOptions{})
		if err != nil {
			return err
		}
		scheme, err := conf.ParseSchemeFolder(path)
		if err != nil {
			return err
		}
		if err = conf.UpdateScheme(scheme, nil); err != nil {
			return err
		}
	}

	return nil
}

func updateHelp() string {
	defaultIrmaconf := irma.DefaultSchemesPath()
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
