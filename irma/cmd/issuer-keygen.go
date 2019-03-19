package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/spf13/cobra"
)

// issuerKeygenCmd represents the keygen command
var issuerKeygenCmd = &cobra.Command{
	Use:   "keygen [path]",
	Short: "Generate a new IRMA issuer private/public keypair",
	Long: `Generate a new IRMA issuer private/public keypair

The keygen command adds an IRMA issuer private/public keypair to the IRMA issuer specified by the
"path" parameter, within an IRMA scheme (if "path" is not provided the current directory is taken).
By default the keys are stored within the PrivateKeys and PublicKeys subfolder of "path" (which are
created if necessary), next to any existing private-public keypairs.

After adding keys, the scheme must be resigned (using "irma scheme sign") before it can be used in
IRMA applications.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()
		keylength, _ := flags.GetInt("keylength")
		counter, _ := flags.GetUint("counter")
		numAttributes, _ := flags.GetInt("numattributes")
		privkeyfile, _ := flags.GetString("privatekey")
		pubkeyfile, _ := flags.GetString("publickey")
		overwrite, _ := flags.GetBool("force-overwrite")
		expiryDateString, _ := flags.GetString("expirydate")
		validFor, _ := flags.GetString("valid-for")

		var expiryDate time.Time
		var err error
		if expiryDateString != "" {
			expiryDate, err = time.Parse(time.RFC3339, expiryDateString)
			if err != nil {
				return errors.WrapPrefix(err, "Failed to parse expirydate", 0)
			}
		} else {
			expiryDate = time.Now()
			m := regexp.MustCompile(`^(\d+)([yMdhm])$`).FindStringSubmatch(validFor)
			if m == nil {
				return errors.New("unable to parse valid-for period")
			}
			num, err := strconv.Atoi(m[1])
			if err != nil {
				return errors.New("unable to parse valid-for period")
			}
			switch m[2] {
			case "m":
				expiryDate = expiryDate.Add(time.Minute * time.Duration(num))
			case "h":
				expiryDate = expiryDate.Add(time.Hour * time.Duration(num))
			case "d":
				expiryDate = expiryDate.AddDate(0, 0, num)
			case "M":
				expiryDate = expiryDate.AddDate(0, num, 0)
			case "y":
				expiryDate = expiryDate.AddDate(num, 0, 0)
			}
		}

		var path string
		if len(args) != 0 {
			path = args[0]
		}
		if path == "" {
			path, err = os.Getwd()
			if err != nil {
				return err
			}
		}
		if err = fs.AssertPathExists(path); err != nil {
			return errors.WrapPrefix(err, "Nonexisting path specified", 0)
		}

		if counter == 0 {
			counter = uint(defaultCounter(path))
		}

		// Now generate the key pair
		fmt.Println("Generating keys (may take several minutes)")
		sysParams, ok := gabi.DefaultSystemParameters[keylength]
		if !ok {
			return errors.Errorf("Unsupported key length, should be one of %v", gabi.DefaultKeyLengths)
		}
		privk, pubk, err := gabi.GenerateKeyPair(sysParams, numAttributes, counter, expiryDate)
		if err != nil {
			return err
		}

		defaultFilename := strconv.Itoa(int(counter)) + ".xml"
		if privkeyfile == "" {
			keypath := filepath.Join(path, "PrivateKeys")
			if err = fs.EnsureDirectoryExists(keypath); err != nil {
				return errors.WrapPrefix(err, "Failed to create"+keypath, 0)
			}
			privkeyfile = filepath.Join(keypath, defaultFilename)
		}
		if pubkeyfile == "" {
			keypath := filepath.Join(path, "PublicKeys")
			if err = fs.EnsureDirectoryExists(keypath); err != nil {
				return errors.WrapPrefix(err, "Failed to create"+keypath, 0)
			}
			pubkeyfile = filepath.Join(keypath, defaultFilename)
		}

		if _, err = privk.WriteToFile(privkeyfile, overwrite); err != nil {
			return errors.New("private key file already exists, will not overwrite (force with -f flag)")
		}
		if _, err = pubk.WriteToFile(pubkeyfile, overwrite); err != nil {
			return errors.New("public key file already exists, will not overwrite (force with -f flag)")
		}
		return nil
	},
}

func defaultCounter(path string) (counter int) {
	matches, _ := filepath.Glob(filepath.Join(path, "PublicKeys", "*.xml"))
	for _, match := range matches {
		filename := filepath.Base(match)
		c, err := strconv.Atoi(filename[:len(filename)-4])
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		if c >= counter {
			counter = c + 1
		}
	}
	return
}

func init() {
	issuerCmd.AddCommand(issuerKeygenCmd)

	issuerKeygenCmd.Flags().StringP("privatekey", "s", "", `File to write private key to (default "PrivateKeys/$counter.xml")`)
	issuerKeygenCmd.Flags().StringP("publickey", "p", "", `File to write public key to (default "PublicKeys/$counter.xml")`)
	issuerKeygenCmd.Flags().StringP("expirydate", "e", "", "Expiry date for the key pair. Specify in RFC3339 (\"2006-01-02T15:04:05+07:00\") format. Alternatively, use the --valid-for option.")
	issuerKeygenCmd.Flags().StringP("valid-for", "v", "1y", "The duration key pair should be valid starting from now. Specify as a number followed by either y, M, d, h, or m (for years, months, days, hours, and minutes, respectively). For example, use \"2y\" for a expiry date 2 years from now. This flag is ignored when expirydate flag is used.")
	issuerKeygenCmd.Flags().IntP("keylength", "l", 2048, "Keylength")
	issuerKeygenCmd.Flags().UintP("counter", "c", 0, "Override key counter")
	issuerKeygenCmd.Flags().IntP("numattributes", "a", 12, "Number of attributes")
	issuerKeygenCmd.Flags().BoolP("force-overwrite", "f", false, "Force overwriting of key files if files already exist")
}
