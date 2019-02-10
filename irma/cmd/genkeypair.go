// Copyright © 2017 Maarten Everts
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Originally from from github.com/mhe/irmatool/cmd/genkeypair.go.

package cmd

import (
	"time"

	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/privacybydesign/gabi"
	"github.com/spf13/cobra"
)

// genkeypairCmd represents the genkeypair command
var genkeypairCmd = &cobra.Command{
	Use:        "genkeypair",
	Short:      "Generate an IRMA issuer keypair",
	Long:       `The genkeypair command generates an IRMA issuer keypair.`,
	Deprecated: `use "irma scheme issuer keygen" instead`,
	RunE: func(cmd *cobra.Command, args []string) error {
		keylength, err := cmd.Flags().GetInt("keylength")
		if err != nil {
			return err
		}

		counter, err := cmd.Flags().GetUint("counter")

		if err != nil {
			return err
		}

		numAttributes, err := cmd.Flags().GetInt("numattributes")
		if err != nil {
			return err
		}

		privkeyfile, err := cmd.Flags().GetString("private-key-file")
		if err != nil {
			return err
		}
		pubkeyfile, err := cmd.Flags().GetString("public-key-file")
		if err != nil {
			return err
		}

		overwrite, err := cmd.Flags().GetBool("force-overwrite")
		if err != nil {
			return err
		}

		expiryDateString, err := cmd.Flags().GetString("expirydate")
		if err != nil {
			return err
		}

		validFor, err := cmd.Flags().GetString("valid-for")
		if err != nil {
			return err
		}

		var expiryDate time.Time
		if expiryDateString != "" {
			expiryDate, err = time.Parse(time.RFC3339, expiryDateString)
			if err != nil {
				return err
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

		// Now generate the key pair
		sysParams, ok := gabi.DefaultSystemParameters[keylength]
		if !ok {
			return fmt.Errorf("Unsupported key length, should be one of %v", gabi.DefaultKeyLengths)
		}
		privk, pubk, err := gabi.GenerateKeyPair(sysParams, numAttributes, counter, expiryDate)
		if err != nil {
			return err
		}

		// TODO: consider support for writing keys to stdout?
		if _, err = privk.WriteToFile(privkeyfile, overwrite); err != nil {
			return errors.New("private key file already exists, will not overwrite. Check -f flag")
		}
		if _, err = pubk.WriteToFile(pubkeyfile, overwrite); err != nil {
			return errors.New("public key file already exists, will not overwrite. Check -f flag")
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(genkeypairCmd)

	genkeypairCmd.Flags().StringP("private-key-file", "k", "isk.xml", "File to write private key to")
	genkeypairCmd.Flags().StringP("public-key-file", "p", "ipk.xml", "File to write public key to")
	genkeypairCmd.Flags().StringP("expirydate", "e", "", "Expiry date for the key pair. Specify in RFC3339 (\"2006-01-02T15:04:05+07:00\") format. Alternatively, use the --valid-for option.")
	genkeypairCmd.Flags().StringP("valid-for", "v", "1y", "The duration key pair should be valid starting from now. Specify as a number followed by either y, M, d, h, or m (for years, months, days, hours, and minutes, respectively). For example, use \"2y\" for a expiry date 2 years from now. This flag is ignored when expirydate flag is used.")
	genkeypairCmd.Flags().IntP("keylength", "l", 1024, "Keylength")
	genkeypairCmd.Flags().UintP("counter", "c", 0, "Set the counter (for the number of generated key pairs).")
	genkeypairCmd.Flags().IntP("numattributes", "a", 6, "Number of attributes")
	genkeypairCmd.Flags().BoolP("force-overwrite", "f", false, "Force overwriting of key files if files already exist. If not set, irmatool will refuse to overwrite existing files.")

}
