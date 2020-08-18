package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sietseringers/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify [<path>]",
	Short: "Verify irma_configuration folder correctness and authenticity",
	Long:  `The verify command parses the specified irma_configuration directory, or the current directory if not specified, and checks the signatures of the contained scheme managers.`,
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
		if err = RunVerify(path, true); err == nil {
			fmt.Println()
			fmt.Println("Verification was successful.")
		} else {
			die("Verification failed", err)
		}
		return nil
	},
}

func RunVerify(path string, verbose bool) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	if filepath.Base(path) == "issuer_schemes" {
		path = filepath.Dir(path)
	} else {
		if _, err = common.UpgradeIrmaconf(path); err != nil {
			if err == common.ErrNonStandardIrmaconfPath {
				return errors.New("IRMA issuer schemes are now required to be contained in a folder called \"issuer_schemes\"")
			}
			return err
		}
	}

	ok, err := common.IsIrmaconfDir(path)
	if err != nil {
		return err
	}
	if ok {
		return VerifyIrmaConfiguration(path, verbose)
	}
	return VerifyScheme(path, verbose)
}

func log(verbose bool, msg string) {
	if verbose {
		fmt.Println(msg)
	}
}

func VerifyScheme(path string, verbose bool) error {
	for _, typ := range []irma.SchemeType{irma.SchemeTypeIssuer, irma.SchemeTypeRequestor} {
		ok, err := common.IsScheme(path, true, true, string(typ))
		if err != nil {
			return err
		}
		if ok {
			log(verbose, "Verifying scheme "+filepath.Base(path))
			return verifyScheme(path, typ)
		}
	}

	return errors.New("no scheme found at specified path")
}

func verifyScheme(path string, typ irma.SchemeType) error {
	conf, err := irma.NewConfiguration(filepath.Dir(filepath.Dir(path)), irma.ConfigurationOptions{ReadOnly: true})
	if err != nil {
		return err
	}

	switch typ {
	case irma.SchemeTypeIssuer:
		if err = conf.ParseSchemeManagerFolder(path); err != nil {
			return err
		}
		if err := conf.ValidateKeys(); err != nil {
			return err
		}
	case irma.SchemeTypeRequestor:
		if err = conf.ParseRequestorSchemeFolder(path); err != nil {
			return err
		}
	default:
		return errors.New("not a scheme or unsupported scheme type")
	}

	for _, warning := range conf.Warnings {
		fmt.Println("Warning: " + warning)
	}
	return nil
}

func VerifyIrmaConfiguration(path string, verbose bool) error {
	log(verbose, "Verifying as configuration directory")
	conf, err := irma.NewConfiguration(path, irma.ConfigurationOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	if err := conf.ParseFolder(); err != nil {
		return err
	}
	if err := conf.ValidateKeys(); err != nil {
		return err
	}
	if len(conf.SchemeManagers) == 0 {
		return errors.New("Specified folder doesn't contain any schemes")
	}

	for _, warning := range conf.Warnings {
		fmt.Println("Warning: " + warning)
	}

	return nil
}

func init() {
	schemeCmd.AddCommand(verifyCmd)
}
