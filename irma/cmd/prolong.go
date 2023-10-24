package cmd

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"os"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/spf13/cobra"
)

var prolongCmd = &cobra.Command{
	Use:   "prolong [<path>] [<timestamp>]",
	Short: "Prolong expiring public and private keys so they are at least valid until the specified timestamp",
	Long:  "The prolong command updates the latest public and private keys by setting <ExpiryDate> to the specified timestamp for keys which expire before that timestamp.\n\n",
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) < 2 {
			die("Invalid arguments given", nil)
		}

		path := args[0]
		exists, err := common.PathExists(path)
		if err != nil || !exists {
			die("Could not check path existence", err)
		}

		timestamp, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			die("Invalid timestamp", err)
		}

		keys, err := findHighestKeys(path)
		if err != nil {
			die("Could not find keys", err)
		}

		for _, key := range keys {
			updateExpiryDate(key, timestamp)
		}
	},
}

func findHighestKeys(path string) ([]string, error) {
	var items []string

	if err := filepath.Walk(path, func(path string, file os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !file.IsDir() {

			// Is this a key?
			if r, err := regexp.MatchString("[0-999].xml", file.Name()); err != nil || !r {
				return err
			}

			// Get the key number to be able to determine if there is a higher key number available
			keyNr, err := strconv.ParseInt(strings.Split(file.Name(), ".")[0], 10, 64)
			if err != nil {
				return err
			}

			nextKey := filepath.Dir(path) + "/" + strconv.FormatInt(keyNr+1, 10) + ".xml"
			exists, err := common.PathExists(nextKey)
			if err != nil || exists {
				// There is a higher key number available in the same folder so we skip this one
				return err
			}

			absPath, err := filepath.Abs(path)
			if err != nil {
				return err
			}

			items = append(items, absPath)

		}
		return nil
	}); err != nil {
		return nil, err
	}

	return items, nil
}

func updateExpiryDate(file string, timestamp int64) error {
	pubKey, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	regex, err := regexp.Compile("(<ExpiryDate>)(.*?)(</ExpiryDate>)")
	if err != nil {
		return err
	}

	matches := regex.FindSubmatch(pubKey)
	if len(matches) == 0 {
		return nil
	}

	currTimestamp, err := strconv.ParseInt(string(matches[2]), 10, 64)
	if err != nil {
		return err
	}

	if currTimestamp >= timestamp {
		// Does not expire before given timestamp
		return nil
	}

	replace := regex.ReplaceAllString(string(pubKey), "${1}"+strconv.FormatInt(timestamp, 10)+"${3}")

	err = os.WriteFile(file, []byte(replace), 0644)
	if err != nil {
		return err
	}

	fmt.Printf("Prolonged key: %s\n", file)

	return nil
}

func init() {
	schemeCmd.AddCommand(prolongCmd)
}
