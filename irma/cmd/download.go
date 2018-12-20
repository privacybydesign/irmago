package cmd

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/spf13/cobra"
)

var downloadCmd = &cobra.Command{
	Use:   "download path url...",
	Short: "[Experimental] Download a scheme manager",
	Long:  `The download command downloads and saves a scheme manager given its URL, saving it in path (i.e., an irma_configuration folder).`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if err := downloadSchemeManager(args[0], args[1:]); err != nil {
			die("Downloading scheme failed", err)
		}
	},
}

func downloadSchemeManager(dest string, urls []string) error {
	exists, err := fs.PathExists(dest)
	if err != nil {
		return errors.Errorf("Could not check path existence: %s", err.Error())
	}
	if !exists {
		return errors.New("Destination does not exist")
	}

	var normalizedUrls []string
	for _, u := range urls {
		_, err := url.ParseRequestURI(u)
		if err != nil {
			return errors.Errorf("%s is not a valid URL: %s", u, err.Error())
		}
		// Calculate normalized scheme manager url
		if strings.HasSuffix(u, "description.xml") {
			u = strings.TrimRight(u, "description.xml")
		}
		if strings.HasSuffix(u, "/") {
			u = strings.TrimRight(u, "/")
		}
		normalizedUrls = append(normalizedUrls, u)
		urlparts := strings.Split(u, "/")
		managerName := urlparts[len(urlparts)-1]
		if err = fs.AssertPathNotExists(filepath.Join(dest, managerName)); err != nil {
			return errors.Errorf("Scheme manager %s already exists", managerName)
		}
	}

	conf, err := irma.NewConfiguration(dest, "")
	for _, u := range normalizedUrls {
		urlparts := strings.Split(u, "/")
		managerName := urlparts[len(urlparts)-1]
		manager := irma.NewSchemeManager(managerName)
		manager.URL = u
		if err := conf.InstallSchemeManager(manager, nil); err != nil {
			return err
		}
	}

	return nil
}

func init() {
	schemeCmd.AddCommand(downloadCmd)
}
