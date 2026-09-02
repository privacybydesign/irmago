package irmacli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/yivi/cli/internal/clihelpers"
	"github.com/spf13/cobra"
)

// translationsCmd reports translation coverage of a scheme or irma_configuration folder
var translationsCmd = &cobra.Command{
	Use:   "translations [<path>]",
	Short: "Report which user-facing texts of a scheme still need translating",
	Long: `The translations command parses the specified scheme or irma_configuration directory,
or the current directory if not specified, and lists every user-facing text (names, descriptions,
issue URLs, FAQ texts, wizard texts, ...) that has no translation in the requested languages.

By default the languages are those declared in the schemes' <Languages> elements. Pass --lang to
check against languages the scheme does not declare yet, which yields the to-do list for adding them:

    irma scheme translations --lang fr,de ./irma_configuration/pbdf

Without --lang and without declared languages, the project-wide supported languages (` + strings.Join(clientmodels.SupportedLanguages, ", ") + `) are used.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := os.Getwd()
		if err != nil {
			return err
		}
		if len(args) > 0 {
			path = args[0]
		}
		langsFlag, _ := cmd.Flags().GetString("lang")
		summary, _ := cmd.Flags().GetBool("summary")

		var langs []string
		for _, l := range strings.Split(langsFlag, ",") {
			if l = strings.TrimSpace(l); l != "" {
				langs = append(langs, l)
			}
		}

		conf, err := loadConfigurationForReport(path)
		if err != nil {
			clihelpers.Die("Could not parse schemes", err, Logger)
		}
		printTranslationReport(conf.TranslationCoverage(langs), summary)
		return nil
	},
}

// loadConfigurationForReport parses either an irma_configuration folder or a
// single scheme folder, the same two shapes `irma scheme verify` accepts.
func loadConfigurationForReport(path string) (*irma.Configuration, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if ok, err := common.IsIrmaconfDir(path); err != nil {
		return nil, err
	} else if ok {
		conf, err := irma.NewConfiguration(path, irma.ConfigurationOptions{ReadOnly: true})
		if err != nil {
			return nil, err
		}
		if err := conf.ParseFolder(); err != nil {
			return nil, err
		}
		if len(conf.SchemeManagers)+len(conf.RequestorSchemes) == 0 {
			return nil, errors.New("specified folder doesn't contain any schemes")
		}
		return conf, nil
	}
	if ok, err := common.IsScheme(path, true); err != nil {
		return nil, err
	} else if ok {
		conf, err := irma.NewConfiguration(filepath.Dir(filepath.Dir(path)), irma.ConfigurationOptions{ReadOnly: true})
		if err != nil {
			return nil, err
		}
		if _, err := conf.ParseSchemeFolder(path); err != nil {
			return nil, err
		}
		return conf, nil
	}
	return nil, errors.New("path must contain a scheme, or multiple schemes in subdirectories")
}

func printTranslationReport(report irma.TranslationReport, summaryOnly bool) {
	fmt.Printf("Translation coverage for languages: %s\n\n", strings.Join(report.Languages, ", "))
	for _, lang := range report.Languages {
		translated, total := report.Translated(lang)
		pct := 0
		if total > 0 {
			pct = translated * 100 / total
		}
		fmt.Printf("  %-6s %5d/%d (%d%%)\n", lang+":", translated, total, pct)
	}

	incomplete := report.Incomplete()
	if summaryOnly || len(incomplete) == 0 {
		if len(incomplete) == 0 {
			fmt.Println("\nAll texts are translated.")
		}
		return
	}
	fmt.Printf("\nMissing translations (%d):\n", len(incomplete))
	for _, e := range incomplete {
		fmt.Printf("  %s <%s>: %s\n", e.Object, e.Field, strings.Join(e.Missing, ", "))
	}
}

func init() {
	translationsCmd.Flags().String("lang", "", "Comma-separated languages to check, e.g. fr,de (default: languages declared by the schemes)")
	translationsCmd.Flags().Bool("summary", false, "Only print per-language totals, not the individual missing texts")
	schemeCmd.AddCommand(translationsCmd)
}
