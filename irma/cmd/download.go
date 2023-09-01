package cmd

import (
	"fmt"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/spf13/cobra"
)

var downloadCmd = &cobra.Command{
	Use:   "download [<path>] [<url>...]",
	Short: "Download scheme(s)",
	Long:  downloadHelp(),
	Run: func(cmd *cobra.Command, args []string) {
		var path string
		var urls []string
		defaultIrmaconf := irma.DefaultSchemesPath()
		if useSchemeAssetsPath, _ := cmd.Flags().GetBool("use-schemes-assets-path"); useSchemeAssetsPath {
			defaultIrmaconf = irma.EnsureDefaultSchemesAssetsPathExists()
		}

		if len(args) == 0 {
			path = defaultIrmaconf
		} else {
			if err := common.AssertPathExists(args[0]); err == nil {
				path = args[0]
				urls = args[1:]
			} else {
				path = defaultIrmaconf
				urls = args
			}
		}
		if path == defaultIrmaconf {
			if defaultIrmaconf == "" {
				die("Failed to determine default irma_configuration path", nil)
			}
			if err := common.EnsureDirectoryExists(defaultIrmaconf); err != nil {
				die("Failed to create irma_configuration directory", err)
			}
			fmt.Println("No irma_configuration path specified, using " + defaultIrmaconf)
		}
		if err := downloadSchemeManager(path, urls); err != nil {
			die("Downloading scheme failed", err)
		}
	},
}

func downloadSchemeManager(dest string, urls []string) error {
	exists, err := common.PathExists(dest)
	if err != nil {
		return errors.Errorf("Could not check path existence: %s", err.Error())
	}
	if !exists {
		return errors.New("Destination does not exist")
	}

	conf, err := irma.NewConfiguration(dest, irma.ConfigurationOptions{})
	if err != nil {
		return err
	}

	if len(urls) == 0 {
		if err := conf.DownloadDefaultSchemes(); err != nil {
			return errors.WrapPrefix(err, "failed to download default schemes", 0)
		}
	} else {
		for _, u := range urls {
			if err := conf.DangerousTOFUInstallScheme(u); err != nil {
				return err
			}
		}
	}

	return nil
}

func downloadHelp() string {
	defaultIrmaconf := irma.DefaultSchemesPath()
	str := "The download command downloads and saves scheme managers given their URLs, saving it in path (i.e., an irma_configuration folder).\n\n"
	if defaultIrmaconf != "" {
		str += "If path is not given, the default path " + defaultIrmaconf + " is used.\n"
	}
	str += "If no urls are given, the default IRMA schemes are downloaded."
	return str
}

func init() {
	flags := downloadCmd.Flags()
	flags.Bool("use-schemes-assets-path", false, "download the schemes to the schemes assets path instead of the schemes path")
	schemeCmd.AddCommand(downloadCmd)
}
