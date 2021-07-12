package cmd

import (
	"encoding/binary"
	"io/ioutil"

	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/spf13/cobra"
)

var keyshareKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate storage key for keyshare server",
	Run: func(command *cobra.Command, args []string) {
		filename, err := command.Flags().GetString("key-file")
		if err != nil {
			die("", err)
		}

		counter, err := command.Flags().GetUint32("counter")
		if err != nil {
			die("", err)
		}

		key, err := keysharecore.GenerateDecryptionKey()
		if err != nil {
			die("", err)
		}

		keydata := make([]byte, 4+len(key[:]))
		binary.LittleEndian.PutUint32(keydata, counter)
		copy(keydata[4:], key[:])

		err = ioutil.WriteFile(filename, keydata, 0600)
		if err != nil {
			die("", err)
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
