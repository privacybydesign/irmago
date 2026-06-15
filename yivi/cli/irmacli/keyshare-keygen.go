package irmacli

import (
	"encoding/binary"
	"os"

	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/yivi/cli/internal/clihelpers"
	"github.com/spf13/cobra"
)

var keyshareKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate storage key for keyshare server",
	Run: func(command *cobra.Command, args []string) {
		filename, err := command.Flags().GetString("key-file")
		if err != nil {
			clihelpers.Die("", err, Logger)
		}

		counter, err := command.Flags().GetUint32("counter")
		if err != nil {
			clihelpers.Die("", err, Logger)
		}

		key, err := keysharecore.GenerateDecryptionKey()
		if err != nil {
			clihelpers.Die("", err, Logger)
		}

		keydata := make([]byte, 4+len(key[:]))
		binary.LittleEndian.PutUint32(keydata, counter)
		copy(keydata[4:], key[:])

		err = os.WriteFile(filename, keydata, 0600)
		if err != nil {
			clihelpers.Die("", err, Logger)
		}
	},
}

func init() {
	keyshareRootCmd.AddCommand(keyshareKeygenCmd)

	flags := keyshareKeygenCmd.Flags()
	flags.SortFlags = false

	flags.StringP("key-file", "k", "storagekey.aes", "File to write key to")
	flags.Uint32P("counter", "c", 0, "Counter of generated key")
}
