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
	Long:  "The prolong command updates the latest public and private keys for non deprecated issuers by setting <ExpiryDate> to the specified timestamp for keys which expire before that timestamp.\n\n",
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

			// Is this key part of a deprecated issuer?
			deprecated, err := deprecated(key, timestamp)

			if err != nil {
				die("Could not check if key is deprecated", err)
			}

			if !deprecated {
				updateExpiryDate(key, timestamp)
			} else {
				fmt.Printf("Skipping deprecated key: %s\n", key)
			}
		}
	},
}

func findHighestKeys(path string) ([]string, error) {
	var keys []string

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

			keys = append(keys, absPath)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return keys, nil
}

// Is this key part of a deprecated issuer?
func deprecated(file string, timestamp int64) (bool, error) {

	descriptionFile := filepath.Dir(file) + "/../description.xml"

	foundTimestamp, err := findTimestamp(descriptionFile, "(<DeprecatedSince>)(.*?)(</DeprecatedSince>)")
	if err != nil {
		return false, err
	}

	if foundTimestamp == 0 || foundTimestamp >= timestamp {
		// Is not deprecated or does not become deprecated before given timestamp
		return false, nil
	}

	return true, nil
}

func updateExpiryDate(file string, timestamp int64) error {
	foundTimestamp, err := findTimestamp(file, "(<ExpiryDate>)(.*?)(</ExpiryDate>)")
	if err != nil {
		return err
	}

	if foundTimestamp >= timestamp {
		// Does not expire before given timestamp
		return nil
	}

	if err := replaceTimestamp(file,
		"<ExpiryDate>"+strconv.FormatInt(foundTimestamp, 10)+"</ExpiryDate>",
		"<ExpiryDate>"+strconv.FormatInt(timestamp, 10)+"</ExpiryDate>"); err != nil {
		return err
	}

	fmt.Printf("Prolonged key: %s\n", file)

	return nil
}

func replaceTimestamp(file string, find string, replace string) error {
	bytes, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	result := strings.ReplaceAll(string(bytes), find, replace)

	if err := os.WriteFile(file, []byte(result), 0644); err != nil {
		return err
	}

	return nil
}

func findTimestamp(file string, pattern string) (int64, error) {
	bytes, err := os.ReadFile(file)
	if err != nil {
		return 0, err
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return 0, err
	}

	matches := regex.FindSubmatch(bytes)
	if len(matches) == 0 {
		return 0, nil
	}

	timestamp, err := strconv.ParseInt(string(matches[2]), 10, 64)
	if err != nil {
		return 0, err
	}
	return timestamp, nil
}

func init() {
	schemeCmd.AddCommand(prolongCmd)
}
